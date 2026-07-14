#include "msys/mipc_broker.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using msys::native::ChildExit;
using msys::native::Reactor;
using msys::native::SpawnOptions;
using msys::native::mipc::AccessRequest;
using msys::native::mipc::Broker;
using msys::native::mipc::BrokerHooks;
using msys::native::mipc::BrokerOptions;
using msys::native::mipc::ComponentStatus;
using msys::native::mipc::OperationReply;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct TemporaryDirectory final {
    std::string path;
    TemporaryDirectory() {
        char pattern[] = "/tmp/msys-native-mipc-XXXXXX";
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

std::string executable_path() {
    std::vector<char> buffer(4096U, '\0');
    const ssize_t count = ::readlink(
        "/proc/self/exe", buffer.data(), buffer.size() - 1U);
    if (count <= 0) {
        throw std::runtime_error("readlink /proc/self/exe failed");
    }
    return std::string{buffer.data(), static_cast<std::size_t>(count)};
}

void rethrow_callback_failure(Reactor& reactor) {
    auto failures = reactor.take_callback_failures();
    if (!failures.empty()) {
        std::rethrow_exception(failures.front().exception);
    }
}

void run_until(
    Reactor& reactor,
    const std::function<bool()>& complete,
    std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!complete() && std::chrono::steady_clock::now() < deadline) {
        (void)reactor.run_once(20ms);
        rethrow_callback_failure(reactor);
    }
    expect(complete(), "integration event loop timed out");
}

void send_packet(int descriptor, std::string_view packet) {
    const ssize_t count = ::send(
        descriptor, packet.data(), packet.size(), MSG_NOSIGNAL);
    if (count != static_cast<ssize_t>(packet.size())) {
        throw std::runtime_error("test send packet failed");
    }
}

void send_line(int descriptor, std::string_view packet) {
    std::string framed{packet};
    framed.push_back('\n');
    std::size_t offset = 0U;
    while (offset < framed.size()) {
        const ssize_t count = ::send(
            descriptor,
            framed.data() + offset,
            framed.size() - offset,
            MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("test send line failed");
        }
        offset += static_cast<std::size_t>(count);
    }
}

std::string receive_line_with_pump(Reactor& reactor, int descriptor) {
    std::string result;
    bool complete = false;
    run_until(reactor, [&] {
        // run_until deliberately evaluates its completion predicate once more
        // after leaving the loop. Keep this stateful line reader idempotent.
        if (complete) {
            return true;
        }
        for (;;) {
            char byte = '\0';
            const ssize_t count = ::recv(descriptor, &byte, 1U, MSG_DONTWAIT);
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return false;
            }
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                throw std::runtime_error("test receive line failed");
            }
            if (byte == '\n') {
                complete = true;
                return true;
            }
            result.push_back(byte);
            expect(result.size() <= msys::native::mipc::max_packet_bytes,
                   "test public response is too large");
        }
    });
    expect(complete, "test public response lacks newline");
    return result;
}

int connect_public(const std::string& path) {
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        throw std::runtime_error("public client socket failed");
    }
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) {
        (void)::close(descriptor);
        throw std::runtime_error("public socket path too long");
    }
    std::memcpy(address.sun_path, path.c_str(), path.size() + 1U);
    const auto size = static_cast<socklen_t>(
        offsetof(sockaddr_un, sun_path) + path.size() + 1U);
    if (::connect(descriptor, reinterpret_cast<const sockaddr*>(&address), size) != 0) {
        const int saved_errno = errno;
        (void)::close(descriptor);
        throw std::runtime_error("public connect failed errno=" + std::to_string(saved_errno));
    }
    return descriptor;
}

std::size_t current_rss_kib() {
    std::ifstream status{"/proc/self/status"};
    std::string line;
    while (std::getline(status, line)) {
        if (!line.starts_with("VmRSS:")) {
            continue;
        }
        const std::size_t begin = line.find_first_of("0123456789");
        if (begin == std::string::npos) {
            return 0U;
        }
        return static_cast<std::size_t>(std::stoull(line.substr(begin)));
    }
    return 0U;
}

ComponentStatus component_status(
    std::string id,
    std::string lifecycle,
    std::string restart,
    std::string state) {
    ComponentStatus result{};
    result.id = std::move(id);
    result.lifecycle = std::move(lifecycle);
    result.restart = std::move(restart);
    result.state = std::move(state);
    return result;
}

struct FakeBackend final {
    std::vector<ComponentStatus> components{
        component_status("org.msys.demo:app", "manual", "never", "stopped"),
        component_status("org.msys.shell:main", "background", "on-failure", "ready"),
    };
    bool allow{true};
    bool ready{false};
    bool disconnected{false};
    std::vector<std::string> authorization_sources;

    BrokerHooks hooks() {
        BrokerHooks result{};
        result.list_components = [this] { return components; };
        result.start_component = [this](std::string_view component) {
            return transition(component, "ready");
        };
        result.stop_component = [this](std::string_view component) {
            return transition(component, "stopped");
        };
        result.component_ready = [this](std::string_view component, std::uint64_t generation) {
            ready = component == "org.msys.demo:app" && generation == 7U;
        };
        result.component_disconnected =
            [this](std::string_view component, std::uint64_t generation) {
                disconnected = component == "org.msys.demo:app" && generation == 7U;
            };
        result.authorize = [this](const AccessRequest& request) {
            authorization_sources.push_back(request.peer.source);
            return allow && request.target == "msys.core";
        };
        return result;
    }

    OperationReply transition(std::string_view component, std::string state) {
        for (auto& candidate : components) {
            if (candidate.id == component) {
                candidate.state = state;
                return OperationReply{true, candidate.id, std::move(state), "", ""};
            }
        }
        return OperationReply{false, std::string{component}, "", "NO_COMPONENT", "unknown component"};
    }
};

void test_runtime_ownership_and_public_calls() {
    TemporaryDirectory temporary;
    const std::string runtime = temporary.path + "/runtime";
    expect(::mkdir(runtime.c_str(), 0700) == 0, "runtime fixture mkdir failed");
    const std::string stale = runtime + "/control.sock";
    const int stale_fd = ::open(stale.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    expect(stale_fd >= 0 && ::close(stale_fd) == 0, "stale control fixture failed");

    Reactor reactor;
    FakeBackend backend;
    {
        Broker broker{reactor, BrokerOptions{runtime}, backend.hooks()};
        struct stat metadata {};
        expect(::lstat(broker.control_path().c_str(), &metadata) == 0, "control socket missing");
        expect(S_ISSOCK(metadata.st_mode), "control path is not a socket");
        expect(
            (metadata.st_mode & static_cast<mode_t>(0777)) == static_cast<mode_t>(0600),
            "control socket mode is not 0600");

        bool second_rejected = false;
        try {
            Reactor second_reactor;
            Broker second{second_reactor, BrokerOptions{runtime}, backend.hooks()};
            (void)second;
        } catch (const std::runtime_error&) {
            second_rejected = true;
        }
        expect(second_rejected, "second runtime owner was accepted");

        const int client = connect_public(broker.control_path());
        const std::string welcome = receive_line_with_pump(reactor, client);
        expect(welcome == "{\"type\":\"welcome\",\"component\":\"public\",\"generation\":0}",
               "public welcome mismatch");

        send_line(client, "{\"type\":\"hello\"}");
        expect(receive_line_with_pump(reactor, client) == welcome,
               "explicit public hello mismatch");

        send_line(client,
            "{\"type\":\"call\",\"id\":1,\"target\":\"msys.core\","
            "\"method\":\"list_components\",\"payload\":{},\"idempotent\":true}");
        const std::string listed = receive_line_with_pump(reactor, client);
        expect(listed.find("\"id\":1") != std::string::npos, "list response id missing");
        expect(listed.find("org.msys.demo:app") != std::string::npos, "list response component missing");

        send_line(client,
            "{\"type\":\"call\",\"id\":2,\"target\":\"msys.core\","
            "\"method\":\"start\",\"payload\":{\"component\":\"org.msys.demo:app\"}}");
        const std::string started = receive_line_with_pump(reactor, client);
        expect(started.find("\"state\":\"ready\"") != std::string::npos,
               "start response state mismatch");

        backend.allow = false;
        send_line(client,
            "{\"type\":\"call\",\"id\":3,\"target\":\"msys.core\","
            "\"method\":\"stop\",\"payload\":{\"component\":\"org.msys.demo:app\"}}");
        const std::string denied = receive_line_with_pump(reactor, client);
        expect(denied.find("ACCESS_DENIED") != std::string::npos, "ACL denial missing");
        expect(broker.stats().access_denied == 1U, "ACL denial counter mismatch");
        expect(!backend.authorization_sources.empty()
                   && backend.authorization_sources.front() == "public",
               "public ACL source mismatch");
        (void)::close(client);
    }
    expect(::access(stale.c_str(), F_OK) != 0 && errno == ENOENT,
           "control socket was not removed by owner");
}

int component_child() {
    const char* raw_fd = ::getenv("MSYS_CONTROL_FD");
    const char* component = ::getenv("MSYS_COMPONENT_ID");
    const char* generation = ::getenv("MSYS_GENERATION");
    if (raw_fd == nullptr || component == nullptr || generation == nullptr) {
        return 60;
    }
    const int descriptor = std::stoi(raw_fd);
    send_packet(
        descriptor,
        "{\"type\":\"hello\",\"component\":" + std::string{"\""} + component
            + "\",\"generation\":" + generation + "}");
    std::vector<char> buffer(msys::native::mipc::max_packet_bytes + 1U, '\0');
    ssize_t count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
    if (count <= 0 || std::string_view{buffer.data(), static_cast<std::size_t>(count)}
            .find("\"type\":\"welcome\"") == std::string_view::npos) {
        return 61;
    }
    send_packet(descriptor, "{\"type\":\"ready\"}");
    send_packet(descriptor,
        "{\"type\":\"call\",\"id\":9,\"target\":\"msys.core\","
        "\"method\":\"list_components\",\"payload\":{}}");
    count = ::recv(descriptor, buffer.data(), buffer.size(), 0);
    if (count <= 0 || std::string_view{buffer.data(), static_cast<std::size_t>(count)}
            .find("\"id\":9") == std::string_view::npos) {
        return 62;
    }
    return 0;
}

void test_inherited_component_session() {
    TemporaryDirectory temporary;
    Reactor reactor;
    FakeBackend backend;
    Broker broker{
        reactor,
        BrokerOptions{temporary.path + "/runtime"},
        backend.hooks(),
    };
    const int child_fd = broker.create_component_session("org.msys.demo:app", 7U);
    SpawnOptions options{};
    options.argv = {executable_path(), "--component-child"};
    options.environment = std::vector<std::string>{
        "MSYS_CONTROL_FD=" + std::to_string(child_fd),
        "MSYS_COMPONENT_ID=org.msys.demo:app",
        "MSYS_GENERATION=7",
    };
    options.inherited_fds = {0, 1, 2, child_fd};
    std::optional<ChildExit> child_result;
    const auto child = reactor.spawn_process(
        std::move(options),
        [&child_result](const ChildExit& result) { child_result = result; });
    (void)child;
    expect(::close(child_fd) == 0, "parent child-session fd close failed");
    run_until(reactor, [&] { return backend.ready && child_result.has_value(); });
    expect(child_result->status == 0, "component child handshake failed");
    expect(
        std::find(
            backend.authorization_sources.begin(),
            backend.authorization_sources.end(),
            "org.msys.demo:app") != backend.authorization_sources.end(),
        "component ACL source mismatch");
    run_until(reactor, [&] { return broker.stats().active_component_sessions == 0U; });
    expect(backend.disconnected, "component disconnect hook was not called");
}

void test_protocol_close_and_backpressure() {
    TemporaryDirectory temporary;
    Reactor reactor;
    FakeBackend backend;
    for (std::size_t index = 0U; index < 16U; ++index) {
        backend.components.push_back(component_status(
            "org.msys.component.with-a-deliberately-long-name:" + std::to_string(index),
            "background",
            "on-failure",
            "ready"));
    }
    BrokerOptions options{temporary.path + "/runtime"};
    options.max_queued_bytes_per_session = 128U;
    Broker broker{reactor, std::move(options), backend.hooks()};
    const int client = connect_public(broker.control_path());
    (void)receive_line_with_pump(reactor, client);
    send_line(client,
        "{\"type\":\"call\",\"id\":4,\"target\":\"msys.core\","
        "\"method\":\"list_components\",\"payload\":{}}");
    run_until(reactor, [&] { return broker.stats().backpressure_drops == 1U; });
    expect(broker.stats().active_public_sessions == 0U, "backpressured session stayed open");
    (void)::close(client);

    BrokerOptions second_options{temporary.path + "/runtime-two"};
    Broker second{reactor, std::move(second_options), backend.hooks()};
    const int malformed = connect_public(second.control_path());
    (void)receive_line_with_pump(reactor, malformed);
    send_line(malformed,
        "{\"type\":\"call\",\"id\":0,\"target\":\"msys.core\",\"method\":\"x\"}");
    run_until(reactor, [&] { return second.stats().protocol_errors == 1U; });
    expect(second.stats().active_public_sessions == 0U, "protocol-invalid session stayed open");
    (void)::close(malformed);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--component-child") {
        try {
            return component_child();
        } catch (...) {
            return 63;
        }
    }
    try {
        test_runtime_ownership_and_public_calls();
        test_inherited_component_session();
        test_protocol_close_and_backpressure();
        const std::size_t rss = current_rss_kib();
        expect(rss > 0U && rss < 65536U, "mIPC broker RSS is unexpectedly large");
        std::cout << "mipc-broker-rss-kib=" << rss << '\n';
        std::cout << "mIPC broker integration tests: ok\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "mIPC broker integration tests: " << error.what() << '\n';
        return 1;
    }
}
