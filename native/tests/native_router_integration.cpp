#include "msys/mipc_broker.hpp"
#include "msys/native_catalog.hpp"
#include "msys/native_router.hpp"
#include "msys/reactor.hpp"

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using msys::native::Reactor;
using msys::native::lite::CatalogProvider;
using msys::native::lite::ComponentPlan;
using msys::native::lite::Lifecycle;
using msys::native::lite::NativeCatalog;
using msys::native::lite::NativeRouter;
using msys::native::lite::ProvideKind;
using msys::native::lite::ProvidePlan;
using msys::native::lite::RouterCallbacks;
using msys::native::lite::RuntimePlan;
using msys::native::mipc::Broker;
using msys::native::mipc::BrokerHooks;
using msys::native::mipc::BrokerOptions;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct TemporaryDirectory final {
    std::string path;
    TemporaryDirectory() {
        char pattern[] = "/tmp/msys-native-router-XXXXXX";
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

void rethrow_callback_failure(Reactor& reactor) {
    auto failures = reactor.take_callback_failures();
    if (!failures.empty()) {
        std::rethrow_exception(failures.front().exception);
    }
}

void pump_until(
    Reactor& reactor,
    const std::function<bool()>& complete,
    const char* message,
    std::chrono::milliseconds timeout = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!complete() && std::chrono::steady_clock::now() < deadline) {
        (void)reactor.run_once(20ms);
        rethrow_callback_failure(reactor);
    }
    expect(complete(), message);
}

void send_record(int descriptor, std::string_view packet) {
    const ssize_t count = ::send(
        descriptor, packet.data(), packet.size(), MSG_NOSIGNAL);
    if (count != static_cast<ssize_t>(packet.size())) {
        throw std::runtime_error("send record failed");
    }
}

std::optional<std::string> receive_record(int descriptor) {
    std::vector<char> buffer(msys::native::mipc::max_packet_bytes + 1U, '\0');
    const ssize_t count = ::recv(
        descriptor, buffer.data(), buffer.size(), MSG_DONTWAIT);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return std::nullopt;
    }
    if (count <= 0) {
        throw std::runtime_error("receive record failed");
    }
    return std::string{buffer.data(), static_cast<std::size_t>(count)};
}

std::string receive_with_pump(Reactor& reactor, int descriptor, const char* message) {
    std::optional<std::string> packet;
    pump_until(reactor, [&] {
        if (packet.has_value()) {
            return true;
        }
        packet = receive_record(descriptor);
        return packet.has_value();
    }, message);
    return std::move(*packet);
}

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::uint64_t packet_id(std::string_view packet) {
    constexpr std::string_view marker = "\"id\":";
    const std::size_t begin = packet.find(marker);
    if (begin == std::string_view::npos) {
        throw std::runtime_error("forwarded call id missing");
    }
    std::size_t end = begin + marker.size();
    while (end < packet.size() && packet[end] >= '0' && packet[end] <= '9') {
        ++end;
    }
    return static_cast<std::uint64_t>(std::stoull(
        std::string{packet.substr(begin + marker.size(), end - begin - marker.size())}));
}

ComponentPlan component(
    std::string id,
    std::vector<std::string> permissions,
    bool launchable = false) {
    ComponentPlan result{};
    result.id = std::move(id);
    result.lifecycle = launchable ? Lifecycle::manual : Lifecycle::on_demand;
    result.idle_timeout_ms = launchable ? 0U : 500U;
    result.permissions = std::move(permissions);
    result.launchable = launchable;
    result.package_id = "org.msys.test";
    result.package_version = "1";
    result.package_kind = launchable ? "application" : "system";
    result.name = launchable ? "Caller App" : "Test Provider";
    result.summary = "router integration fixture";
    result.window.mode = launchable ? "window" : "background";
    return result;
}

RuntimePlan plan_fixture() {
    RuntimePlan plan{};
    plan.profile_id = "test";
    ComponentPlan caller = component(
        "org.msys.test:caller",
        {
            "mipc.call:msys.core",
            "mipc.call:role:test-role",
            "mipc.call:org.msys.test.v1",
            "mipc.event:subscribe:msys.demo.*",
        },
        true);
    ComponentPlan provider = component(
        "org.msys.test:provider",
        {"mipc.event:publish:msys.demo.changed"});
    provider.provides.push_back(
        ProvidePlan{ProvideKind::role, "test-role", true, 50U});
    provider.provides.push_back(
        ProvidePlan{ProvideKind::interface, "org.msys.test.v1", false, 50U});
    plan.components.push_back(std::move(caller));
    plan.components.push_back(std::move(provider));
    plan.role_preferences.push_back(
        msys::native::lite::RolePreference{
            "test-role", {"org.msys.test:provider"}});
    return plan;
}

void test_router_end_to_end() {
    TemporaryDirectory temporary;
    RuntimePlan plan = plan_fixture();
    NativeCatalog catalog{plan};
    expect(catalog.roles().size() == 1U, "catalog role count mismatch");
    const CatalogProvider preferred = catalog.roles().front().candidates.front();
    expect(preferred.component_index == 1U && preferred.profile_preferred,
           "profile role preference was not selected");
    expect(catalog.launchable_apps() == std::vector<std::size_t>{0U},
           "launchable catalog mismatch");

    Reactor reactor;
    NativeRouter* router_pointer = nullptr;
    std::vector<bool> ready(plan.components.size(), false);
    std::vector<std::uint64_t> generations(plan.components.size(), 0U);
    std::vector<int> busy(plan.components.size(), 0);
    bool provider_activation_requested = false;

    BrokerHooks hooks{};
    hooks.authorize = [&router_pointer](const msys::native::mipc::AccessRequest& request) {
        return router_pointer != nullptr && router_pointer->authorize_call(request);
    };
    hooks.routed_message = [&router_pointer](const msys::native::mipc::RoutedMessage& routed) {
        expect(router_pointer != nullptr, "router callback ran before construction");
        router_pointer->on_message(routed);
    };
    hooks.session_closed = [&router_pointer](
                               std::uint64_t session,
                               const msys::native::mipc::PeerIdentity& peer) {
        if (router_pointer != nullptr) {
            router_pointer->session_closed(session, peer);
        }
    };
    hooks.component_ready = [&](std::string_view id, std::uint64_t generation) {
        const auto index = catalog.component_index(id);
        expect(index.has_value(), "ready component is not in catalog");
        ready[*index] = true;
        generations[*index] = generation;
        expect(router_pointer != nullptr, "ready callback lacks router");
        router_pointer->component_ready(*index, generation);
    };

    Broker broker{reactor, BrokerOptions{temporary.path + "/runtime"}, std::move(hooks)};
    RouterCallbacks callbacks{};
    callbacks.activate_component = [&](std::size_t index) {
        provider_activation_requested = index == 1U;
        return index < ready.size();
    };
    callbacks.component_state = [&](std::size_t index) {
        return ready[index] ? std::string{"ready"} : std::string{"stopped"};
    };
    callbacks.component_generation = [&](std::size_t index) { return generations[index]; };
    callbacks.component_ready = [&](std::size_t index) { return ready[index]; };
    callbacks.operator_peer = [](const msys::native::mipc::PeerIdentity&) { return false; };
    callbacks.provider_busy_delta = [&](std::size_t index, int delta) { busy[index] += delta; };
    callbacks.foreground_components = [] { return std::vector<std::size_t>{0U}; };
    NativeRouter router{reactor, plan, catalog, broker, std::move(callbacks)};
    router_pointer = &router;

    const int caller = broker.create_component_session("org.msys.test:caller", 1U);
    send_record(caller,
        "{\"type\":\"hello\",\"component\":\"org.msys.test:caller\",\"generation\":1}");
    expect(receive_with_pump(reactor, caller, "caller welcome timed out").find("welcome")
               != std::string::npos,
           "caller welcome missing");
    // The production native shell subscribes before sending ready.
    send_record(caller, "{\"type\":\"subscribe\",\"topic\":\"msys.demo.*\"}");
    send_record(caller, "{\"type\":\"ready\"}");
    pump_until(reactor, [&] { return ready[0U]; }, "caller did not become ready");

    send_record(caller,
        "{\"type\":\"call\",\"id\":10,\"target\":\"role:test-role\","
        "\"method\":\"echo\",\"payload\":{\"value\":7},\"deadline_ms\":"
        + std::to_string(now_ms() + 5000U) + ",\"idempotent\":true}");
    pump_until(
        reactor,
        [&] { return provider_activation_requested; },
        "on-demand provider activation was not requested");

    const int provider = broker.create_component_session("org.msys.test:provider", 1U);
    send_record(provider,
        "{\"type\":\"hello\",\"component\":\"org.msys.test:provider\",\"generation\":1}");
    (void)receive_with_pump(reactor, provider, "provider welcome timed out");
    send_record(provider, "{\"type\":\"ready\"}");
    const std::string forwarded = receive_with_pump(
        reactor, provider, "routed provider call timed out");
    expect(forwarded.find("\"method\":\"echo\"") != std::string::npos,
           "forwarded method mismatch");
    expect(forwarded.find("\"source\":\"org.msys.test:caller\"") != std::string::npos,
           "forwarded source mismatch");
    expect(busy[1U] == 1, "provider busy count was not raised");
    const std::uint64_t forwarded_id = packet_id(forwarded);
    send_record(provider,
        "{\"type\":\"return\",\"id\":" + std::to_string(forwarded_id)
        + ",\"payload\":{\"echo\":7}}");
    const std::string returned = receive_with_pump(
        reactor, caller, "routed caller reply timed out");
    expect(returned.find("\"id\":10") != std::string::npos
               && returned.find("\"echo\":7") != std::string::npos,
           "caller reply id/payload was not restored");
    expect(busy[1U] == 0, "provider busy count was not released");

    send_record(caller,
        "{\"type\":\"call\",\"id\":15,\"target\":\"interface:org.msys.test.v1\","
        "\"method\":\"status\",\"payload\":{},\"deadline_ms\":"
        + std::to_string(now_ms() + 5000U) + ",\"idempotent\":true}");
    const std::string interface_call = receive_with_pump(
        reactor, provider, "interface provider call timed out");
    expect(interface_call.find("\"method\":\"status\"") != std::string::npos,
           "interface call was not routed");
    send_record(provider,
        "{\"type\":\"return\",\"id\":" + std::to_string(packet_id(interface_call))
        + ",\"payload\":{\"status\":\"ok\"}}");
    expect(receive_with_pump(reactor, caller, "interface caller reply timed out")
               .find("\"id\":15") != std::string::npos,
           "interface reply id was not restored");

    send_record(provider,
        "{\"type\":\"event\",\"topic\":\"msys.demo.changed\","
        "\"payload\":{\"revision\":2}}");
    const std::string event = receive_with_pump(
        reactor, caller, "subscribed event fanout timed out");
    expect(event.find("\"source\":\"org.msys.test:provider\"") != std::string::npos
               && event.find("\"revision\":2") != std::string::npos,
           "event source/payload mismatch");

    send_record(caller,
        "{\"type\":\"call\",\"id\":11,\"target\":\"msys.core\","
        "\"method\":\"list_apps\",\"payload\":{},\"idempotent\":true}");
    const std::string apps = receive_with_pump(reactor, caller, "list_apps timed out");
    expect(apps.find("org.msys.test:caller") != std::string::npos,
           "list_apps omitted launchable component");
    send_record(caller,
        "{\"type\":\"call\",\"id\":12,\"target\":\"msys.core\","
        "\"method\":\"list_roles\",\"payload\":{},\"idempotent\":true}");
    const std::string roles = receive_with_pump(reactor, caller, "list_roles timed out");
    expect(roles.find("test-role") != std::string::npos
               && roles.find("org.msys.test:provider") != std::string::npos,
           "list_roles omitted native role/provider");
    expect(roles.find("\"preferred\":\"org.msys.test:provider\"")
               != std::string::npos
               && roles.find("\"active\":\"org.msys.test:provider\"")
                   != std::string::npos,
           "list_roles did not expose the compiled preference and ready provider");
    expect(roles.find("\"exclusive\":true") != std::string::npos
               && roles.find("\"explicit\":true") != std::string::npos
               && roles.find("\"declared\":true") != std::string::npos,
           "list_roles candidate metadata drifted from the offline plan");

    send_record(caller,
        "{\"type\":\"call\",\"id\":13,\"target\":\"role:test-role\","
        "\"method\":\"echo\",\"payload\":{},\"deadline_ms\":0}");
    expect(receive_with_pump(reactor, caller, "expired call reply timed out")
               .find("CALL_TIMEOUT") != std::string::npos,
           "expired deadline was not rejected");

    send_record(provider,
        "{\"type\":\"call\",\"id\":14,\"target\":\"role:test-role\","
        "\"method\":\"echo\",\"payload\":{}}");
    expect(receive_with_pump(reactor, provider, "ACL denial timed out")
               .find("ACCESS_DENIED") != std::string::npos,
           "fail-closed component ACL did not deny call");

    (void)::close(provider);
    (void)::close(caller);
}

}  // namespace

int main() {
    try {
        test_router_end_to_end();
        return 0;
    } catch (const std::exception& error) {
        (void)::write(STDERR_FILENO, error.what(), std::char_traits<char>::length(error.what()));
        (void)::write(STDERR_FILENO, "\n", 1U);
        return 1;
    }
}
