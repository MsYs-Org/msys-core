#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

namespace {

volatile sig_atomic_t stopping = 0;

void handle_signal(int) {
    stopping = 1;
}

void write_all(int descriptor, const std::string& value) {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const ssize_t count = ::write(
            descriptor, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("write failed");
        }
        offset += static_cast<std::size_t>(count);
    }
}

void append(const std::string& path, const std::string& value) {
    const int descriptor = ::open(
        path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("open log failed");
    }
    try {
        write_all(descriptor, value + "\n");
    } catch (...) {
        (void)::close(descriptor);
        throw;
    }
    if (::close(descriptor) != 0) {
        throw std::runtime_error("close log failed");
    }
}

int environment_fd(const char* name) {
    const char* const raw = std::getenv(name);
    if (raw == nullptr || *raw == '\0') {
        throw std::runtime_error("required descriptor environment is missing");
    }
    char* end = nullptr;
    errno = 0;
    const long parsed = std::strtol(raw, &end, 10);
    if (errno != 0 || end == raw || *end != '\0' || parsed < 0 || parsed > 65535) {
        throw std::runtime_error("descriptor environment is invalid");
    }
    return static_cast<int>(parsed);
}

int ready_fd() {
    return environment_fd("MSYS_READY_FD");
}

std::string generation() {
    const char* const value = std::getenv("MSYS_GENERATION");
    return value == nullptr ? "?" : std::string{value};
}

void install_signals() {
    struct sigaction action {};
    action.sa_handler = handle_signal;
    (void)::sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (::sigaction(SIGTERM, &action, nullptr) != 0
        || ::sigaction(SIGINT, &action, nullptr) != 0) {
        throw std::runtime_error("sigaction failed");
    }
}

int ready_loop(const std::string& log, const std::string& name) {
    install_signals();
    append(log, "start:" + name + ":" + generation());
    const int descriptor = ready_fd();
    write_all(descriptor, "READY\n");
    (void)::close(descriptor);
    append(log, "ready:" + name + ":" + generation());
    while (stopping == 0) {
        (void)::pause();
    }
    append(log, "term:" + name + ":" + generation());
    return 0;
}

int invalid_ready_loop(const std::string& log, const std::string& name) {
    install_signals();
    append(log, "start:" + name + ":" + generation());
    const int descriptor = ready_fd();
    write_all(descriptor, "READY\nEXTRA");
    (void)::close(descriptor);
    while (stopping == 0) {
        (void)::pause();
    }
    append(log, "term:" + name + ":" + generation());
    return 0;
}

int ready_loop_with_descendant(
    const std::string& log,
    const std::string& pid_file,
    const std::string& name) {
    int synchronized[2]{-1, -1};
    if (::pipe(synchronized) != 0) {
        throw std::runtime_error("descendant sync pipe failed");
    }
    const pid_t descendant = ::fork();
    if (descendant < 0) {
        (void)::close(synchronized[0]);
        (void)::close(synchronized[1]);
        throw std::runtime_error("descendant fork failed");
    }
    if (descendant == 0) {
        (void)::close(synchronized[0]);
        struct sigaction ignore {};
        ignore.sa_handler = SIG_IGN;
        (void)::sigemptyset(&ignore.sa_mask);
        if (::sigaction(SIGTERM, &ignore, nullptr) != 0
            || ::sigaction(SIGINT, &ignore, nullptr) != 0) {
            ::_exit(66);
        }
        try {
            write_all(synchronized[1], "R");
        } catch (...) {
            ::_exit(67);
        }
        (void)::close(synchronized[1]);
        for (;;) {
            (void)::pause();
        }
    }

    (void)::close(synchronized[1]);
    char ready = '\0';
    ssize_t count = -1;
    do {
        count = ::read(synchronized[0], &ready, 1U);
    } while (count < 0 && errno == EINTR);
    (void)::close(synchronized[0]);
    if (count != 1 || ready != 'R') {
        (void)::kill(descendant, SIGKILL);
        throw std::runtime_error("descendant did not become ready");
    }
    append(pid_file, std::to_string(descendant));
    return ready_loop(log, name);
}

void send_record(int descriptor, const std::string& packet) {
    const ssize_t count = ::send(
        descriptor, packet.data(), packet.size(), MSG_NOSIGNAL);
    if (count != static_cast<ssize_t>(packet.size())) {
        throw std::runtime_error("mIPC fixture send failed");
    }
}

std::uint64_t request_id(std::string_view packet) {
    constexpr std::string_view marker = "\"id\":";
    const std::size_t marker_offset = packet.find(marker);
    if (marker_offset == std::string_view::npos) {
        throw std::runtime_error("mIPC fixture call id missing");
    }
    const std::size_t begin = marker_offset + marker.size();
    std::size_t end = begin;
    while (end < packet.size() && packet[end] >= '0' && packet[end] <= '9') {
        ++end;
    }
    if (end == begin) {
        throw std::runtime_error("mIPC fixture call id invalid");
    }
    return static_cast<std::uint64_t>(std::stoull(std::string{packet.substr(begin, end - begin)}));
}

int mipc_role_loop(const std::string& log, const std::string& name) {
    install_signals();
    const int descriptor = environment_fd("MSYS_CONTROL_FD");
    const char* const component = std::getenv("MSYS_COMPONENT_ID");
    const char* const generation_value = std::getenv("MSYS_GENERATION");
    if (component == nullptr || generation_value == nullptr) {
        throw std::runtime_error("mIPC fixture identity missing");
    }
    append(log, "start:" + name + ":" + generation());
    send_record(
        descriptor,
        "{\"type\":\"hello\",\"component\":\"" + std::string{component}
            + "\",\"generation\":" + generation_value + "}");
    std::vector<char> buffer(256U * 1024U + 1U, '\0');
    ssize_t count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
    if (count <= 0 || std::string_view{buffer.data(), static_cast<std::size_t>(count)}
            .find("\"type\":\"welcome\"") == std::string_view::npos) {
        throw std::runtime_error("mIPC fixture welcome missing");
    }
    send_record(descriptor, "{\"type\":\"subscribe\",\"topic\":\"msys.demo.*\"}");
    send_record(descriptor, "{\"type\":\"ready\"}");
    append(log, "ready:" + name + ":" + generation());
    while (stopping == 0) {
        count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        const std::string_view packet{buffer.data(), static_cast<std::size_t>(count)};
        if (packet.find("\"type\":\"call\"") == std::string_view::npos) {
            continue;
        }
        const std::uint64_t id = request_id(packet);
        if (packet.find("\"method\":\"ping\"") != std::string_view::npos) {
            send_record(
                descriptor,
                "{\"type\":\"return\",\"id\":" + std::to_string(id)
                    + ",\"payload\":{\"pong\":true}}");
        } else {
            send_record(
                descriptor,
                "{\"type\":\"error\",\"id\":" + std::to_string(id)
                    + ",\"code\":\"NO_METHOD\",\"message\":\"fixture\"}");
        }
    }
    append(log, "term:" + name + ":" + generation());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string{argv[1]} == "--ready-loop") {
            return ready_loop(argv[2], argv[3]);
        }
        if (argc == 4 && std::string{argv[1]} == "--invalid-ready-loop") {
            return invalid_ready_loop(argv[2], argv[3]);
        }
        if (argc == 5 && std::string{argv[1]} == "--ready-loop-with-descendant") {
            return ready_loop_with_descendant(argv[2], argv[3], argv[4]);
        }
        if (argc == 5 && std::string{argv[1]} == "--fail-once") {
            const int marker = ::open(
                argv[2], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (marker >= 0) {
                (void)::close(marker);
                append(argv[3], "start:" + std::string{argv[4]} + ":" + generation());
                append(argv[3], "fail:" + std::string{argv[4]} + ":" + generation());
                return 17;
            }
            if (errno != EEXIST) {
                throw std::runtime_error("fail-once marker failed");
            }
            return ready_loop(argv[3], argv[4]);
        }
        if (argc == 4 && std::string{argv[1]} == "--mipc-role-loop") {
            return mipc_role_loop(argv[2], argv[3]);
        }
        return 64;
    } catch (...) {
        return 65;
    }
}
