#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string encode(std::string_view value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2U);
    for (char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        result.push_back(digits[static_cast<std::size_t>(byte >> 4U)]);
        result.push_back(digits[static_cast<std::size_t>(byte & 0x0fU)]);
    }
    return result;
}

std::string component_record(
    const std::string& id,
    const std::string& kind,
    const std::string& restart,
    const std::vector<std::string>& argv,
    const std::vector<std::string>& after) {
    std::ostringstream output;
    output << "component\t" << id << '\t' << kind
           << "\t1\t" << restart
           << "\tfd\t2000\t10\t100\t4\t"
           << argv.size() << '\t' << after.size() << "\t0\n";
    for (const auto& argument : argv) {
        output << "arg\t" << encode(argument) << '\n';
    }
    for (const auto& dependency : after) {
        output << "after\t" << dependency << '\n';
    }
    output << "end\n";
    return output.str();
}

std::string v2_component_record(
    const std::string& id,
    const std::string& name,
    const std::vector<std::string>& argv,
    const std::string& lifecycle,
    bool critical,
    bool launchable,
    bool provides_role) {
    std::ostringstream output;
    const std::size_t provide_count = provides_role ? 1U : 0U;
    output << "component\t" << id << "\tother\t"
           << (critical ? "1" : "0")
           << "\ton-failure\tmipc-ready\t3000\t10\t100\t3\t"
           << argv.size() << "\t0\t0\t" << lifecycle
           << "\t0\t" << provide_count << "\t1\t"
           << (launchable ? "1" : "0") << '\n';
    for (const auto& argument : argv) {
        output << "arg\t" << encode(argument) << '\n';
    }
    if (provides_role) {
        output << "provide\trole\t" << encode("echo-provider") << "\t1\t100\n";
    }
    output << "permission\t" << encode("mipc.event:subscribe:msys.demo.*") << '\n';
    output << "package\t" << encode("org.msys.test") << '\t'
           << encode("Native Test") << '\t' << encode("1") << '\t'
           << encode(launchable ? "application" : "system") << '\n';
    output << "metadata\t" << encode(name) << '\t'
           << encode("native-lite routed fixture") << "\t\n";
    output << "window\t" << encode("x11") << '\t' << encode("inherit") << '\t'
           << encode(launchable ? "window" : "background") << '\t'
           << encode(name) << '\t' << encode(id) << '\t' << encode(id) << "\t\n";
    output << "end\n";
    return output.str();
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
            throw std::runtime_error("fixture write failed");
        }
        offset += static_cast<std::size_t>(count);
    }
}

void write_file(const std::string& path, const std::string& value) {
    const int descriptor = ::open(
        path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("fixture open failed");
    }
    try {
        write_all(descriptor, value);
    } catch (...) {
        (void)::close(descriptor);
        throw;
    }
    expect(::close(descriptor) == 0, "fixture close failed");
}

std::string read_file(const std::string& path) {
    std::ifstream input{path};
    return std::string{
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{},
    };
}

bool wait_for_text(
    const std::string& path,
    const std::string& needle,
    std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (read_file(path).find(needle) != std::string::npos) {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

bool pid_is_active(pid_t pid) {
    std::ifstream status{"/proc/" + std::to_string(pid) + "/status"};
    std::string line;
    while (std::getline(status, line)) {
        if (!line.starts_with("State:")) {
            continue;
        }
        return line.find("\tZ") == std::string::npos
            && line.find("\tX") == std::string::npos;
    }
    return status.is_open();
}

bool wait_for_pid_inactive(pid_t pid, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!pid_is_active(pid)) {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

pid_t spawn_supervisor(
    const std::string& supervisor,
    const std::string& plan,
    const std::string& log) {
    const pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork supervisor failed");
    }
    if (pid == 0) {
        const int descriptor = ::open(
            log.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (descriptor < 0) {
            ::_exit(126);
        }
        if (::dup2(descriptor, STDOUT_FILENO) < 0
            || ::dup2(descriptor, STDERR_FILENO) < 0) {
            ::_exit(126);
        }
        (void)::close(descriptor);
        ::execl(
            supervisor.c_str(),
            supervisor.c_str(),
            "--plan",
            plan.c_str(),
            "--report-rss",
            static_cast<char*>(nullptr));
        ::_exit(127);
    }
    return pid;
}

pid_t spawn_supervisor_with_runtime(
    const std::string& supervisor,
    const std::string& plan,
    const std::string& runtime,
    const std::string& log) {
    const pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork routed supervisor failed");
    }
    if (pid == 0) {
        const int descriptor = ::open(
            log.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (descriptor < 0 || ::dup2(descriptor, STDOUT_FILENO) < 0
            || ::dup2(descriptor, STDERR_FILENO) < 0) {
            ::_exit(126);
        }
        (void)::close(descriptor);
        ::execl(
            supervisor.c_str(),
            supervisor.c_str(),
            "--plan",
            plan.c_str(),
            "--runtime-dir",
            runtime.c_str(),
            static_cast<char*>(nullptr));
        ::_exit(127);
    }
    return pid;
}

bool wait_for_socket(const std::string& path, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        struct stat metadata {};
        if (::lstat(path.c_str(), &metadata) == 0 && S_ISSOCK(metadata.st_mode)) {
            return true;
        }
        std::this_thread::sleep_for(10ms);
    }
    return false;
}

int connect_public(const std::string& path) {
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        throw std::runtime_error("public fixture socket failed");
    }
    const timeval timeout{5, 0};
    if (::setsockopt(
            descriptor, SOL_SOCKET, SO_RCVTIMEO,
            &timeout, static_cast<socklen_t>(sizeof(timeout))) != 0) {
        (void)::close(descriptor);
        throw std::runtime_error("public fixture timeout failed");
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        (void)::close(descriptor);
        throw std::runtime_error("public fixture path too long");
    }
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    const auto length = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    if (::connect(descriptor, reinterpret_cast<const sockaddr*>(&address), length) != 0) {
        (void)::close(descriptor);
        throw std::runtime_error("public fixture connect failed");
    }
    return descriptor;
}

void send_line(int descriptor, const std::string& packet) {
    write_all(descriptor, packet + "\n");
}

std::string receive_line(int descriptor) {
    std::string result;
    for (;;) {
        char byte = '\0';
        ssize_t count = -1;
        do {
            count = ::read(descriptor, &byte, 1U);
        } while (count < 0 && errno == EINTR);
        if (count != 1) {
            throw std::runtime_error("public fixture read failed");
        }
        if (byte == '\n') {
            return result;
        }
        result.push_back(byte);
        if (result.size() > 256U * 1024U) {
            throw std::runtime_error("public fixture line too large");
        }
    }
}

std::string public_call(
    const std::string& socket_path,
    std::uint64_t id,
    std::string_view target,
    std::string_view method,
    std::string_view payload) {
    const int descriptor = connect_public(socket_path);
    try {
        const std::string welcome = receive_line(descriptor);
        expect(welcome.find("\"type\":\"welcome\"") != std::string::npos,
               "public fixture welcome missing");
        send_line(
            descriptor,
            "{\"type\":\"call\",\"id\":" + std::to_string(id)
                + ",\"target\":\"" + std::string{target}
                + "\",\"method\":\"" + std::string{method}
                + "\",\"payload\":" + std::string{payload}
                + ",\"idempotent\":true}");
        const std::string response = receive_line(descriptor);
        expect(::close(descriptor) == 0, "public fixture close failed");
        return response;
    } catch (...) {
        (void)::close(descriptor);
        throw;
    }
}

int terminate_and_wait(pid_t pid) {
    if (::kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        throw std::runtime_error("SIGTERM supervisor failed");
    }
    const auto deadline = std::chrono::steady_clock::now() + 8s;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = ::waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            return status;
        }
        if (result < 0 && errno != EINTR) {
            throw std::runtime_error("waitpid supervisor failed");
        }
        std::this_thread::sleep_for(10ms);
    }
    (void)::kill(pid, SIGKILL);
    (void)::waitpid(pid, &status, 0);
    throw std::runtime_error("supervisor shutdown timed out");
}

int wait_for_exit(pid_t pid, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const pid_t result = ::waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            return status;
        }
        if (result < 0 && errno != EINTR) {
            throw std::runtime_error("waitpid supervisor failed");
        }
        std::this_thread::sleep_for(10ms);
    }
    try {
        // Preserve component cleanup even when the terminal-exit assertion is
        // about to fail.
        (void)terminate_and_wait(pid);
    } catch (...) {
    }
    throw std::runtime_error("supervisor did not exit after terminal failure");
}

class ProcessGuard final {
public:
    explicit ProcessGuard(pid_t pid) : pid_(pid) {}
    ~ProcessGuard() {
        if (pid_ <= 0) {
            return;
        }
        try {
            // Give the supervisor a chance to stop its component process
            // groups before the timeout path escalates it.
            (void)terminate_and_wait(pid_);
        } catch (...) {
        }
    }

    ProcessGuard(const ProcessGuard&) = delete;
    ProcessGuard& operator=(const ProcessGuard&) = delete;

    [[nodiscard]] pid_t pid() const noexcept { return pid_; }
    void release() noexcept { pid_ = -1; }

private:
    pid_t pid_{-1};
};

std::size_t process_rss_kib(pid_t pid) {
    std::ifstream status{"/proc/" + std::to_string(pid) + "/status"};
    std::string line;
    while (std::getline(status, line)) {
        if (!line.starts_with("VmRSS:")) {
            continue;
        }
        std::istringstream values{line.substr(6U)};
        std::size_t rss = 0U;
        std::string unit;
        if (values >> rss >> unit && unit == "kB") {
            return rss;
        }
    }
    return 0U;
}

void expect_order(
    const std::string& value,
    const std::vector<std::string>& needles,
    const char* message) {
    std::size_t offset = 0U;
    for (const auto& needle : needles) {
        const std::size_t found = value.find(needle, offset);
        if (found == std::string::npos) {
            throw std::runtime_error(message);
        }
        offset = found + needle.size();
    }
}

struct TemporaryDirectory final {
    std::string path;
    TemporaryDirectory() {
        char pattern[] = "/tmp/msys-native-lite-integration-XXXXXX";
        char* const result = ::mkdtemp(pattern);
        if (result == nullptr) {
            throw std::runtime_error("mkdtemp failed");
        }
        path = result;
    }
    ~TemporaryDirectory() {
        std::error_code error;
        (void)std::filesystem::remove_all(path, error);
    }
};

void test_ordered_start_stop_and_rss(
    const std::string& supervisor,
    const std::string& child) {
    TemporaryDirectory temporary;
    const std::string plan = temporary.path + "/runtime.plan";
    const std::string child_log = temporary.path + "/children.log";
    const std::string supervisor_log = temporary.path + "/supervisor.log";
    std::string document = "MSYS_NATIVE_LITE_PLAN\t1\nstop_grace_ms\t500\n";
    document += component_record(
        "display", "display", "on-failure",
        {child, "--ready-loop", child_log, "display"}, {});
    document += component_record(
        "window", "window", "on-failure",
        {child, "--ready-loop", child_log, "window"}, {"display"});
    document += component_record(
        "shell", "shell", "on-failure",
        {child, "--ready-loop", child_log, "shell"}, {"window"});
    write_file(plan, document);

    ProcessGuard process{spawn_supervisor(supervisor, plan, supervisor_log)};
    expect(wait_for_text(child_log, "ready:shell:1", 5s), "shell did not become ready");
    const std::size_t rss = process_rss_kib(process.pid());
    expect(rss > 0U && rss < 65536U, "native-lite RSS is missing or unexpectedly large");
    std::cout << "native-lite-rss-kib=" << rss << '\n';
    const int status = terminate_and_wait(process.pid());
    process.release();
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "ordered supervisor exit failed");

    const std::string events = read_file(child_log);
    expect_order(
        events,
        {"start:display:1", "start:window:1", "start:shell:1"},
        "startup dependency order failed");
    expect_order(
        events,
        {"term:shell:1", "term:window:1", "term:display:1"},
        "reverse shutdown order failed");
}

void test_restart_backoff(const std::string& supervisor, const std::string& child) {
    TemporaryDirectory temporary;
    const std::string plan = temporary.path + "/runtime.plan";
    const std::string marker = temporary.path + "/failed.once";
    const std::string child_log = temporary.path + "/children.log";
    const std::string supervisor_log = temporary.path + "/supervisor.log";
    std::string document = "MSYS_NATIVE_LITE_PLAN\t1\nstop_grace_ms\t500\n";
    document += component_record(
        "worker", "other", "on-failure",
        {child, "--fail-once", marker, child_log, "worker"}, {});
    write_file(plan, document);

    ProcessGuard process{spawn_supervisor(supervisor, plan, supervisor_log)};
    expect(wait_for_text(child_log, "ready:worker:2", 5s), "failed child was not restarted");
    const int status = terminate_and_wait(process.pid());
    process.release();
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "restart supervisor exit failed");
    const std::string events = read_file(child_log);
    expect_order(
        events,
        {"start:worker:1", "fail:worker:1", "start:worker:2", "ready:worker:2"},
        "restart generation/backoff flow failed");
}

void test_terminal_spawn_failure(const std::string& supervisor) {
    TemporaryDirectory temporary;
    const std::string plan = temporary.path + "/runtime.plan";
    const std::string supervisor_log = temporary.path + "/supervisor.log";
    std::string document = "MSYS_NATIVE_LITE_PLAN\t1\nstop_grace_ms\t500\n";
    document += component_record(
        "missing", "other", "never",
        {"/definitely/not/an/msys/executable"}, {});
    write_file(plan, document);

    ProcessGuard process{spawn_supervisor(supervisor, plan, supervisor_log)};
    const int status = wait_for_exit(process.pid(), 5s);
    process.release();
    expect(
        WIFEXITED(status) && WEXITSTATUS(status) == 70,
        "terminal critical spawn failure did not return 70");
}

void test_invalid_readiness_record(
    const std::string& supervisor,
    const std::string& child) {
    TemporaryDirectory temporary;
    const std::string plan = temporary.path + "/runtime.plan";
    const std::string child_log = temporary.path + "/children.log";
    const std::string supervisor_log = temporary.path + "/supervisor.log";
    std::string document = "MSYS_NATIVE_LITE_PLAN\t1\nstop_grace_ms\t500\n";
    document += component_record(
        "bad-ready", "other", "never",
        {child, "--invalid-ready-loop", child_log, "bad-ready"}, {});
    write_file(plan, document);

    ProcessGuard process{spawn_supervisor(supervisor, plan, supervisor_log)};
    const int status = wait_for_exit(process.pid(), 5s);
    process.release();
    expect(
        WIFEXITED(status) && WEXITSTATUS(status) == 70,
        "invalid readiness record did not terminate the critical component");
    expect(
        read_file(child_log).find("term:bad-ready:1") != std::string::npos,
        "invalid readiness child did not receive SIGTERM");
}

void test_remaining_process_group_is_killed(
    const std::string& supervisor,
    const std::string& child) {
    TemporaryDirectory temporary;
    const std::string plan = temporary.path + "/runtime.plan";
    const std::string child_log = temporary.path + "/children.log";
    const std::string descendant_file = temporary.path + "/descendant.pid";
    const std::string supervisor_log = temporary.path + "/supervisor.log";
    std::string document = "MSYS_NATIVE_LITE_PLAN\t1\nstop_grace_ms\t500\n";
    document += component_record(
        "tree", "other", "on-failure",
        {child, "--ready-loop-with-descendant", child_log, descendant_file, "tree"},
        {});
    write_file(plan, document);

    ProcessGuard process{spawn_supervisor(supervisor, plan, supervisor_log)};
    expect(wait_for_text(child_log, "ready:tree:1", 5s), "tree child did not become ready");
    const int descendant_value = std::stoi(read_file(descendant_file));
    expect(descendant_value > 0, "invalid descendant pid");
    const pid_t descendant = static_cast<pid_t>(descendant_value);
    const int status = terminate_and_wait(process.pid());
    process.release();
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "tree supervisor exit failed");
    const bool descendant_gone = wait_for_pid_inactive(descendant, 2s);
    if (!descendant_gone) {
        (void)::kill(descendant, SIGKILL);
    }
    expect(descendant_gone, "component descendant escaped process-group cleanup");
}

void test_mipc_catalog_router_runtime(
    const std::string& supervisor,
    const std::string& child) {
    TemporaryDirectory temporary;
    const std::string plan_path = temporary.path + "/runtime-v2.plan";
    const std::string runtime = temporary.path + "/runtime";
    const std::string socket_path = runtime + "/control.sock";
    const std::string child_log = temporary.path + "/routed-children.log";
    const std::string supervisor_log = temporary.path + "/routed-supervisor.log";
    const std::string provider_id = "org.msys.test:provider";
    const std::string app_id = "org.msys.test:app";
    std::string document =
        "MSYS_NATIVE_LITE_PLAN\t2\n"
        "stop_grace_ms\t500\n"
        "profile\t74657374\t3a3234\t1\t0\t1\n"
        "role\t6563686f2d70726f7669646572\t1\n"
        "provider\t" + provider_id + "\n"
        "startup\t" + provider_id + "\n";
    document += v2_component_record(
        provider_id,
        "Echo Provider",
        {child, "--mipc-role-loop", child_log, "provider"},
        "background",
        true,
        false,
        true);
    document += v2_component_record(
        app_id,
        "Fixture App",
        {child, "--mipc-role-loop", child_log, "app"},
        "manual",
        false,
        true,
        false);
    write_file(plan_path, document);

    ProcessGuard process{
        spawn_supervisor_with_runtime(supervisor, plan_path, runtime, supervisor_log)};
    expect(wait_for_socket(socket_path, 5s), "native routed control socket did not appear");
    expect(wait_for_text(child_log, "ready:provider:1", 5s),
           "native routed provider did not become ready");

    const std::string roles = public_call(
        socket_path, 1U, "msys.core", "list_roles", "{}");
    expect(roles.find("echo-provider") != std::string::npos
               && roles.find(provider_id) != std::string::npos,
           "native public list_roles omitted provider");
    expect(roles.find("\"preferred\":\"" + provider_id + "\"")
               != std::string::npos
               && roles.find("\"active\":\"" + provider_id + "\"")
                   != std::string::npos,
           "native public list_roles did not report the ready profile provider");
    expect(roles.find("\"candidates\":[{\"component\":\"" + provider_id)
               != std::string::npos
               && roles.find("\"explicit\":true") != std::string::npos,
           "native public list_roles did not retain compiled candidate metadata");
    const std::string apps = public_call(
        socket_path, 2U, "msys.core", "list_apps", "{}");
    expect(apps.find(app_id) != std::string::npos
               && apps.find("Fixture App") != std::string::npos,
           "native public list_apps omitted app");
    const std::string ping = public_call(
        socket_path, 3U, "role:echo-provider", "ping", "{\"value\":1}");
    expect(ping.find("\"pong\":true") != std::string::npos,
           "native role call did not round-trip through provider");

    const std::string started = public_call(
        socket_path,
        4U,
        "msys.core",
        "start",
        "{\"component\":\"org.msys.test:app\"}");
    expect(started.find(app_id) != std::string::npos,
           "native app start response omitted component");
    expect(wait_for_text(child_log, "ready:app:1", 5s),
           "native manual app did not become ready");
    const std::string foreground = public_call(
        socket_path, 5U, "msys.core", "foreground_stack", "{}");
    expect(foreground.find(app_id) != std::string::npos,
           "native foreground stack omitted ready app");

    const int status = terminate_and_wait(process.pid());
    process.release();
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "native routed supervisor exit failed");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc != 3) {
            throw std::runtime_error("usage: native-lite-integration SUPERVISOR CHILD");
        }
        const std::string supervisor{argv[1]};
        const std::string child{argv[2]};
        expect(!supervisor.empty() && supervisor.front() == '/', "supervisor path must be absolute");
        expect(!child.empty() && child.front() == '/', "child path must be absolute");
        test_ordered_start_stop_and_rss(supervisor, child);
        test_restart_backoff(supervisor, child);
        test_terminal_spawn_failure(supervisor);
        test_invalid_readiness_record(supervisor, child);
        test_remaining_process_group_is_killed(supervisor, child);
        test_mipc_catalog_router_runtime(supervisor, child);
        std::cout << "native-lite integration tests: ok\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "native-lite integration tests: " << error.what() << '\n';
        return 1;
    }
}
