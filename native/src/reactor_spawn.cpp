#include "reactor_internal.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace msys::native {
namespace {

void validate_c_string(const std::string& value, const char* field) {
    if (value.find('\0') != std::string::npos) {
        throw std::invalid_argument(std::string(field) + " contains an embedded NUL");
    }
}

class SpawnAttributes final {
public:
    SpawnAttributes() {
        const int result = ::posix_spawnattr_init(&attributes_);
        if (result != 0) {
            throw_system_error("posix_spawnattr_init", result);
        }
    }
    ~SpawnAttributes() { (void)::posix_spawnattr_destroy(&attributes_); }
    SpawnAttributes(const SpawnAttributes&) = delete;
    SpawnAttributes& operator=(const SpawnAttributes&) = delete;
    [[nodiscard]] posix_spawnattr_t* get() noexcept { return &attributes_; }

private:
    posix_spawnattr_t attributes_{};
};

class SpawnFileActions final {
public:
    SpawnFileActions() {
        const int result = ::posix_spawn_file_actions_init(&actions_);
        if (result != 0) {
            throw_system_error("posix_spawn_file_actions_init", result);
        }
    }
    ~SpawnFileActions() { (void)::posix_spawn_file_actions_destroy(&actions_); }
    SpawnFileActions(const SpawnFileActions&) = delete;
    SpawnFileActions& operator=(const SpawnFileActions&) = delete;

    void close_fd(int fd) {
        const int result = ::posix_spawn_file_actions_addclose(&actions_, fd);
        if (result != 0) {
            throw_system_error("posix_spawn_file_actions_addclose", result);
        }
    }

    void inherit_fd(int fd) {
        // POSIX specifies that an identity dup2 file action clears FD_CLOEXEC.
        const int result = ::posix_spawn_file_actions_adddup2(&actions_, fd, fd);
        if (result != 0) {
            throw_system_error("posix_spawn_file_actions_adddup2", result);
        }
    }

    [[nodiscard]] posix_spawn_file_actions_t* get() noexcept { return &actions_; }

private:
    posix_spawn_file_actions_t actions_{};
};

class OpenFdDirectory final {
public:
    explicit OpenFdDirectory(int minimum_fd) {
        const int raw_fd = ::open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (raw_fd < 0) {
            throw_system_error("open(/proc/self/fd)");
        }
        const int directory_fd = ::fcntl(raw_fd, F_DUPFD_CLOEXEC, minimum_fd);
        const int saved_errno = errno;
        close_nointr(raw_fd);
        if (directory_fd < 0) {
            throw_system_error("fcntl(F_DUPFD_CLOEXEC)", saved_errno);
        }
        directory_ = ::fdopendir(directory_fd);
        if (directory_ == nullptr) {
            const int directory_errno = errno;
            close_nointr(directory_fd);
            throw_system_error("fdopendir(/proc/self/fd)", directory_errno);
        }
    }

    ~OpenFdDirectory() {
        if (directory_ != nullptr) {
            (void)::closedir(directory_);
        }
    }
    OpenFdDirectory(const OpenFdDirectory&) = delete;
    OpenFdDirectory& operator=(const OpenFdDirectory&) = delete;

    [[nodiscard]] std::vector<int> entries() {
        std::vector<int> descriptors;
        errno = 0;
        while (dirent* entry = ::readdir(directory_)) {
            const std::string_view name(entry->d_name);
            int descriptor = -1;
            const auto conversion =
                std::from_chars(name.data(), name.data() + name.size(), descriptor);
            if (conversion.ec == std::errc{} && conversion.ptr == name.data() + name.size() &&
                descriptor >= 0) {
                descriptors.push_back(descriptor);
            }
            errno = 0;
        }
        if (errno != 0) {
            throw_system_error("readdir(/proc/self/fd)");
        }
        std::sort(descriptors.begin(), descriptors.end());
        descriptors.erase(
            std::unique(descriptors.begin(), descriptors.end()), descriptors.end());
        return descriptors;
    }

private:
    DIR* directory_{nullptr};
};

std::vector<int> validate_inherited_fds(std::vector<int> descriptors) {
    for (const int descriptor : descriptors) {
        if (descriptor < 0) {
            throw std::invalid_argument("inherited_fds contains a negative descriptor");
        }
        if (descriptor == INT_MAX) {
            throw std::invalid_argument("inherited_fds contains an unusable descriptor");
        }
    }
    std::sort(descriptors.begin(), descriptors.end());
    descriptors.erase(std::unique(descriptors.begin(), descriptors.end()), descriptors.end());
    return descriptors;
}

int enumeration_minimum_fd(const std::vector<int>& inherited_fds) {
    int minimum = 3;
    for (const int descriptor : inherited_fds) {
        minimum = std::max(minimum, descriptor + 1);
    }
    return minimum;
}

std::string path_from_environment(
    const std::optional<std::vector<std::string>>& environment) {
    if (!environment.has_value()) {
        const char* inherited_path = ::getenv("PATH");
        if (inherited_path == nullptr) {
            throw std::invalid_argument("search_path requires PATH in the inherited environment");
        }
        return inherited_path;
    }

    const std::string* path = nullptr;
    for (const std::string& entry : *environment) {
        if (entry.starts_with("PATH=")) {
            if (path != nullptr) {
                throw std::invalid_argument("environment contains duplicate PATH entries");
            }
            path = &entry;
        }
    }
    if (path == nullptr) {
        throw std::invalid_argument("search_path requires PATH in the supplied environment");
    }
    return path->substr(5U);
}

std::string resolve_executable(
    const std::string& program,
    bool search_path,
    const std::optional<std::vector<std::string>>& environment) {
    const bool absolute = !program.empty() && program.front() == '/';
    if (!search_path) {
        if (!absolute) {
            throw std::invalid_argument("spawn_process requires an absolute argv[0]");
        }
        return program;
    }
    if (program.find('/') != std::string::npos) {
        if (!absolute) {
            throw std::invalid_argument("search_path rejects relative paths containing '/'");
        }
        return program;
    }

    const std::string path = path_from_environment(environment);
    bool saw_permission_denied = false;
    std::size_t begin = 0U;
    for (;;) {
        const std::size_t end = path.find(':', begin);
        const std::string directory = path.substr(begin, end - begin);
        if (directory.empty() || directory.front() != '/') {
            throw std::invalid_argument("search_path requires non-empty absolute PATH entries");
        }
        const std::string candidate =
            directory == "/" ? directory + program : directory + "/" + program;
        struct stat metadata {};
        if (::stat(candidate.c_str(), &metadata) == 0) {
            if (S_ISREG(metadata.st_mode) && ::access(candidate.c_str(), X_OK) == 0) {
                return candidate;
            }
            saw_permission_denied = true;
        } else if (errno == EACCES) {
            saw_permission_denied = true;
        }
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1U;
    }
    throw_system_error("resolve executable from PATH", saw_permission_denied ? EACCES : ENOENT);
}

}  // namespace

SpawnedChild Reactor::Impl::spawn_process(
    SpawnOptions options,
    Reactor::ChildCallback callback) {
    require_owner();
    if (options.argv.empty()) {
        throw std::invalid_argument("spawn_process requires a non-empty argv");
    }
    if (!callback) {
        throw std::invalid_argument("spawn_process requires a callback");
    }
    for (const auto& argument : options.argv) {
        validate_c_string(argument, "argv");
    }
    if (options.argv.front().empty()) {
        throw std::invalid_argument("spawn_process argv[0] must not be empty");
    }
    if (options.environment.has_value()) {
        for (const auto& entry : *options.environment) {
            validate_c_string(entry, "environment");
            const std::size_t separator = entry.find('=');
            if (separator == std::string::npos || separator == 0U) {
                throw std::invalid_argument("environment entries must use non-empty NAME=VALUE");
            }
        }
    }

    const std::string executable = resolve_executable(
        options.argv.front(), options.search_path, options.environment);
    const std::vector<int> inherited_fds =
        validate_inherited_fds(std::move(options.inherited_fds));

    std::vector<char*> argv;
    argv.reserve(options.argv.size() + 1U);
    for (auto& argument : options.argv) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    std::vector<char*> explicit_environment;
    char** environment = environ;
    if (options.environment.has_value()) {
        explicit_environment.reserve(options.environment->size() + 1U);
        for (auto& entry : *options.environment) {
            explicit_environment.push_back(entry.data());
        }
        explicit_environment.push_back(nullptr);
        environment = explicit_environment.data();
    }

    SpawnAttributes attributes;
    short flags = POSIX_SPAWN_SETSIGMASK;
    int result = ::posix_spawnattr_setsigmask(attributes.get(), &original_signal_mask_);
    if (result != 0) {
        throw_system_error("posix_spawnattr_setsigmask", result);
    }
    if (options.new_process_group) {
        flags = static_cast<short>(flags | POSIX_SPAWN_SETPGROUP);
        result = ::posix_spawnattr_setpgroup(attributes.get(), 0);
        if (result != 0) {
            throw_system_error("posix_spawnattr_setpgroup", result);
        }
    }
    result = ::posix_spawnattr_setflags(attributes.get(), flags);
    if (result != 0) {
        throw_system_error("posix_spawnattr_setflags", result);
    }

    OpenFdDirectory open_fds(enumeration_minimum_fd(inherited_fds));
    SpawnFileActions file_actions;
    for (const int descriptor : open_fds.entries()) {
        if (std::binary_search(inherited_fds.begin(), inherited_fds.end(), descriptor)) {
            file_actions.inherit_fd(descriptor);
        } else {
            file_actions.close_fd(descriptor);
        }
    }

    pid_t pid = -1;
    result = ::posix_spawn(
        &pid,
        executable.c_str(),
        file_actions.get(),
        attributes.get(),
        argv.data(),
        environment);
    if (result != 0) {
        throw_system_error("posix_spawn", result);
    }

    try {
        ChildHandle handle = watch_child(pid, std::move(callback));
        return SpawnedChild{pid, handle};
    } catch (...) {
        if (options.new_process_group) {
            (void)::kill(-pid, SIGKILL);
        }
        (void)::kill(pid, SIGKILL);
        siginfo_t information{};
        while (::waitid(P_PID, static_cast<id_t>(pid), &information, WEXITED) < 0 &&
               errno == EINTR) {
        }
        throw;
    }
}

}  // namespace msys::native
