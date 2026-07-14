#include "msys/native_router.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace msys::native::lite {
namespace {

constexpr std::size_t max_pending_calls = 256U;
constexpr std::size_t max_subscriptions_per_session = 128U;
constexpr std::uint64_t max_call_timeout_ms = 300000U;

std::uint64_t monotonic_ms() noexcept {
    const auto value = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return value <= 0 ? 0U : static_cast<std::uint64_t>(value);
}

std::string json_quote(std::string_view value) {
    constexpr char hexadecimal[] = "0123456789abcdef";
    std::string output;
    output.reserve(value.size() + 2U);
    output.push_back('"');
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        switch (character) {
        case '"':
            output += "\\\"";
            break;
        case '\\':
            output += "\\\\";
            break;
        case '\b':
            output += "\\b";
            break;
        case '\f':
            output += "\\f";
            break;
        case '\n':
            output += "\\n";
            break;
        case '\r':
            output += "\\r";
            break;
        case '\t':
            output += "\\t";
            break;
        default:
            if (byte < 0x20U) {
                output += "\\u00";
                output.push_back(hexadecimal[static_cast<std::size_t>(byte >> 4U)]);
                output.push_back(hexadecimal[static_cast<std::size_t>(byte & 0x0fU)]);
            } else {
                output.push_back(character);
            }
        }
    }
    output.push_back('"');
    return output;
}

std::string error_packet(
    std::uint64_t id,
    std::string_view code,
    std::string_view message) {
    return "{\"type\":\"error\",\"id\":" + std::to_string(id)
        + ",\"code\":" + json_quote(code)
        + ",\"message\":" + json_quote(message) + "}";
}

std::string return_packet(std::uint64_t id, std::string_view payload) {
    return "{\"type\":\"return\",\"id\":" + std::to_string(id)
        + ",\"payload\":" + std::string{payload} + "}";
}

bool subscription_matches(std::string_view pattern, std::string_view topic) noexcept {
    if (pattern == "*") {
        return true;
    }
    if (pattern.size() >= 2U && pattern.ends_with(".*")) {
        return topic.starts_with(pattern.substr(0U, pattern.size() - 1U));
    }
    return pattern == topic;
}

}  // namespace

class NativeRouter::Impl final {
public:
    Impl(
        Reactor& reactor,
        const RuntimePlan& plan,
        const NativeCatalog& catalog,
        msys::native::mipc::Broker& broker,
        RouterCallbacks callbacks)
        : reactor_(reactor),
          plan_(plan),
          catalog_(catalog),
          broker_(broker),
          callbacks_(std::move(callbacks)) {}

    ~Impl() {
        for (auto& pending : pending_) {
            if (pending.timer) {
                (void)reactor_.remove(pending.timer);
            }
        }
    }

    bool authorize_call(const msys::native::mipc::AccessRequest& request) const {
        const auto source = source_component(request.peer);
        if (source.has_value()) {
            return catalog_.allows_call(*source, request.target, request.method);
        }
        return callbacks_.operator_peer && callbacks_.operator_peer(request.peer);
    }

    void on_message(const msys::native::mipc::RoutedMessage& routed) {
        switch (routed.message.type) {
        case msys::native::mipc::MessageType::call:
            route_call(routed);
            return;
        case msys::native::mipc::MessageType::subscribe:
            subscribe(routed);
            return;
        case msys::native::mipc::MessageType::event:
            publish(routed);
            return;
        case msys::native::mipc::MessageType::returned:
        case msys::native::mipc::MessageType::error:
            provider_reply(routed);
            return;
        case msys::native::mipc::MessageType::hello:
        case msys::native::mipc::MessageType::ready:
            return;
        }
    }

    void component_ready(std::size_t component, std::uint64_t generation) {
        for (std::size_t index = 0U; index < pending_.size();) {
            if (pending_[index].provider == component && !pending_[index].delivered) {
                if (!deliver(index, generation)) {
                    continue;
                }
            }
            ++index;
        }
    }

    void component_unavailable(std::size_t component, std::uint64_t generation) {
        for (std::size_t index = 0U; index < pending_.size();) {
            const auto& pending = pending_[index];
            if (pending.provider == component
                && (!pending.delivered || pending.provider_generation == generation)) {
                fail_pending(index, "PROVIDER_UNAVAILABLE", plan_.components[component].id);
                continue;
            }
            ++index;
        }
    }

    void session_closed(
        std::uint64_t session_id,
        const msys::native::mipc::PeerIdentity& peer) {
        subscriptions_.erase(session_id);
        subscriber_components_.erase(session_id);
        for (std::size_t index = 0U; index < pending_.size();) {
            if (pending_[index].caller_session == session_id) {
                erase_pending(index);
                continue;
            }
            ++index;
        }
        const auto component = source_component(peer);
        if (peer.kind == msys::native::mipc::SessionKind::component
            && component.has_value()) {
            component_unavailable(*component, peer.generation);
        }
    }

private:
    struct PendingCall final {
        std::uint64_t forwarded_id{0U};
        std::uint64_t caller_session{0U};
        std::uint64_t caller_request_id{0U};
        std::size_t provider{0U};
        std::uint64_t provider_generation{0U};
        std::uint64_t deadline_ms{0U};
        std::string source;
        msys::native::mipc::DecodedMessage call;
        Handle timer{};
        bool delivered{false};
    };

    std::optional<std::size_t> source_component(
        const msys::native::mipc::PeerIdentity& peer) const {
        if (peer.kind == msys::native::mipc::SessionKind::component) {
            return catalog_.component_index(peer.source);
        }
        if (callbacks_.component_for_pid) {
            return callbacks_.component_for_pid(peer.pid);
        }
        return std::nullopt;
    }

    std::string source_name(const msys::native::mipc::PeerIdentity& peer) const {
        const auto component = source_component(peer);
        return component.has_value() ? plan_.components[*component].id : "public";
    }

    void reply_error(
        std::uint64_t session,
        std::uint64_t id,
        std::string_view code,
        std::string_view message) {
        (void)broker_.send_to_session(session, error_packet(id, code, message));
    }

    void route_call(const msys::native::mipc::RoutedMessage& routed) {
        const auto request_id = routed.message.request_id;
        if (!request_id.has_value()) {
            return;
        }
        if (routed.message.target == "msys.core") {
            core_call(routed);
            return;
        }
        std::optional<std::size_t> provider;
        if (routed.message.target.starts_with("role:")) {
            const auto* role = catalog_.role(
                std::string_view{routed.message.target}.substr(5U));
            if (role != nullptr) {
                for (const auto& candidate : role->candidates) {
                    if (component_state(candidate.component_index) != "failed") {
                        provider = candidate.component_index;
                        break;
                    }
                }
            }
        } else if (routed.message.target.starts_with("interface:")) {
            const auto* candidates = catalog_.interface_providers(
                std::string_view{routed.message.target}.substr(10U));
            if (candidates != nullptr) {
                for (const auto& candidate : *candidates) {
                    if (component_state(candidate.component_index) != "failed") {
                        provider = candidate.component_index;
                        break;
                    }
                }
            }
        } else if (routed.message.target.starts_with("component:")) {
            provider = catalog_.component_index(
                std::string_view{routed.message.target}.substr(10U));
        } else {
            reply_error(routed.session_id, *request_id, "BAD_TARGET", routed.message.target);
            return;
        }
        if (!provider.has_value()) {
            reply_error(routed.session_id, *request_id, "NO_PROVIDER", routed.message.target);
            return;
        }
        queue_provider_call(routed, *provider);
    }

    void queue_provider_call(
        const msys::native::mipc::RoutedMessage& routed,
        std::size_t provider) {
        const std::uint64_t now = monotonic_ms();
        const std::uint64_t deadline = routed.message.deadline_ms.value_or(now + 5000U);
        if (deadline <= now) {
            reply_error(
                routed.session_id, *routed.message.request_id,
                "CALL_TIMEOUT", "call deadline already expired");
            return;
        }
        if (deadline - now > max_call_timeout_ms) {
            reply_error(
                routed.session_id, *routed.message.request_id,
                "BAD_DEADLINE", "call deadline exceeds the native router bound");
            return;
        }
        if (pending_.size() >= max_pending_calls
            || next_forwarded_id_ == std::numeric_limits<std::uint64_t>::max()) {
            reply_error(
                routed.session_id, *routed.message.request_id,
                "ROUTER_BUSY", "native router pending-call limit reached");
            return;
        }
        PendingCall pending{};
        pending.forwarded_id = next_forwarded_id_++;
        pending.caller_session = routed.session_id;
        pending.caller_request_id = *routed.message.request_id;
        pending.provider = provider;
        pending.deadline_ms = deadline;
        pending.source = source_name(routed.peer);
        pending.call = routed.message;
        const std::uint64_t forwarded_id = pending.forwarded_id;
        pending.timer = reactor_.add_timer(
            std::chrono::milliseconds{static_cast<std::chrono::milliseconds::rep>(deadline - now)},
            std::chrono::nanoseconds{0},
            [this, forwarded_id](std::uint64_t) { timeout(forwarded_id); });
        const Handle timer_handle = pending.timer;
        try {
            pending_.push_back(std::move(pending));
        } catch (...) {
            if (timer_handle) {
                (void)reactor_.remove(timer_handle);
            }
            throw;
        }
        const std::size_t pending_index = pending_.size() - 1U;
        try {
            if (callbacks_.component_ready && callbacks_.component_ready(provider)) {
                const std::uint64_t generation = callbacks_.component_generation
                    ? callbacks_.component_generation(provider) : 0U;
                (void)deliver(pending_index, generation);
                return;
            }
            if (!callbacks_.activate_component || !callbacks_.activate_component(provider)) {
                fail_pending(pending_index, "COMPONENT_UNAVAILABLE", plan_.components[provider].id);
            }
        } catch (...) {
            const auto still_pending = std::find_if(
                pending_.begin(), pending_.end(),
                [forwarded_id](const PendingCall& candidate) {
                    return candidate.forwarded_id == forwarded_id;
                });
            if (still_pending != pending_.end()) {
                erase_pending(static_cast<std::size_t>(
                    std::distance(pending_.begin(), still_pending)));
            }
            throw;
        }
    }

    bool deliver(std::size_t index, std::uint64_t generation) {
        if (index >= pending_.size()) {
            return false;
        }
        PendingCall& pending = pending_[index];
        if (pending.deadline_ms <= monotonic_ms()) {
            fail_pending(index, "CALL_TIMEOUT", "call deadline expired before provider delivery");
            return false;
        }
        const auto& component = plan_.components[pending.provider];
        std::string packet = "{\"type\":\"call\",\"id\":"
            + std::to_string(pending.forwarded_id)
            + ",\"target\":" + json_quote(component.id)
            + ",\"method\":" + json_quote(pending.call.method)
            + ",\"payload\":" + pending.call.payload_json
            + ",\"source\":" + json_quote(pending.source)
            + ",\"deadline_ms\":" + std::to_string(pending.deadline_ms)
            + ",\"idempotent\":"
            + (pending.call.idempotent.value_or(false) ? "true}" : "false}");
        if (!broker_.send_to_component(component.id, generation, std::move(packet))) {
            fail_pending(index, "NO_PROVIDER_SOCKET", component.id);
            return false;
        }
        pending.delivered = true;
        pending.provider_generation = generation;
        if (callbacks_.provider_busy_delta) {
            callbacks_.provider_busy_delta(pending.provider, 1);
        }
        if (callbacks_.component_activity) {
            callbacks_.component_activity(pending.provider);
        }
        return true;
    }

    void provider_reply(const msys::native::mipc::RoutedMessage& routed) {
        const auto response_id = routed.message.request_id;
        if (!response_id.has_value()) {
            return;
        }
        const auto iterator = std::find_if(
            pending_.begin(), pending_.end(),
            [response_id](const PendingCall& pending) {
                return pending.forwarded_id == *response_id;
            });
        if (iterator == pending_.end()) {
            return;
        }
        const std::size_t index = static_cast<std::size_t>(
            std::distance(pending_.begin(), iterator));
        const auto source = source_component(routed.peer);
        if (!source.has_value() || *source != iterator->provider
            || routed.peer.generation != iterator->provider_generation) {
            return;
        }
        const std::uint64_t caller_session = iterator->caller_session;
        const std::uint64_t caller_request_id = iterator->caller_request_id;
        std::string packet;
        if (routed.message.type == msys::native::mipc::MessageType::returned) {
            packet = return_packet(caller_request_id, routed.message.payload_json);
        } else {
            packet = error_packet(
                caller_request_id,
                routed.message.code,
                routed.message.message);
        }
        erase_pending(index);
        (void)broker_.send_to_session(caller_session, std::move(packet));
    }

    void timeout(std::uint64_t forwarded_id) {
        const auto iterator = std::find_if(
            pending_.begin(), pending_.end(),
            [forwarded_id](const PendingCall& pending) {
                return pending.forwarded_id == forwarded_id;
            });
        if (iterator == pending_.end()) {
            return;
        }
        const std::size_t index = static_cast<std::size_t>(
            std::distance(pending_.begin(), iterator));
        fail_pending(index, "CALL_TIMEOUT", plan_.components[iterator->provider].id);
    }

    void fail_pending(
        std::size_t index,
        std::string_view code,
        std::string_view message) {
        if (index >= pending_.size()) {
            return;
        }
        const std::uint64_t caller_session = pending_[index].caller_session;
        const std::uint64_t caller_request_id = pending_[index].caller_request_id;
        const std::string error_code{code};
        const std::string error_message{message};
        erase_pending(index);
        reply_error(caller_session, caller_request_id, error_code, error_message);
    }

    void erase_pending(std::size_t index) {
        if (index >= pending_.size()) {
            return;
        }
        PendingCall& pending = pending_[index];
        if (pending.timer) {
            (void)reactor_.remove(pending.timer);
        }
        if (pending.delivered && callbacks_.provider_busy_delta) {
            callbacks_.provider_busy_delta(pending.provider, -1);
        }
        pending_.erase(pending_.begin() + static_cast<std::ptrdiff_t>(index));
    }

    void subscribe(const msys::native::mipc::RoutedMessage& routed) {
        const auto source = source_component(routed.peer);
        if (!source.has_value()
            || !catalog_.allows_subscribe(*source, routed.message.topic)) {
            return;
        }
        auto& topics = subscriptions_[routed.session_id];
        if (topics.size() >= max_subscriptions_per_session
            && topics.find(routed.message.topic) == topics.end()) {
            return;
        }
        topics.insert(routed.message.topic);
        subscriber_components_[routed.session_id] = *source;
        if (callbacks_.component_activity) {
            callbacks_.component_activity(*source);
        }
    }

    void publish(const msys::native::mipc::RoutedMessage& routed) {
        const auto source = source_component(routed.peer);
        if (!source.has_value()
            || !catalog_.allows_publish(*source, routed.message.topic)) {
            return;
        }
        broadcast(
            routed.message.topic,
            routed.message.payload_json,
            plan_.components[*source].id);
        if (callbacks_.component_activity) {
            callbacks_.component_activity(*source);
        }
    }

    void broadcast(
        std::string_view topic,
        std::string_view payload,
        std::string_view source) {
        const std::string packet = "{\"type\":\"event\",\"topic\":"
            + json_quote(topic) + ",\"source\":" + json_quote(source)
            + ",\"payload\":" + std::string{payload} + "}";
        std::vector<std::uint64_t> deliveries;
        for (const auto& entry : subscriptions_) {
            const bool matches = std::any_of(
                entry.second.begin(), entry.second.end(),
                [topic](const std::string& pattern) {
                    return subscription_matches(pattern, topic);
                });
            if (matches) {
                deliveries.push_back(entry.first);
            }
        }
        for (const std::uint64_t session : deliveries) {
            const auto component = subscriber_components_.find(session);
            std::size_t component_index = 0U;
            bool has_component = false;
            if (component != subscriber_components_.end()) {
                component_index = component->second;
                has_component = true;
            }
            if (broker_.send_to_session(session, packet)
                && has_component && callbacks_.component_activity) {
                callbacks_.component_activity(component_index);
            }
        }
    }

    void core_call(const msys::native::mipc::RoutedMessage& routed) {
        const std::uint64_t request_id = *routed.message.request_id;
        const std::string& method = routed.message.method;
        if (method == "list_roles") {
            std::string payload = "{\"roles\":[";
            const auto& roles = catalog_.roles();
            for (std::size_t role_index = 0U; role_index < roles.size(); ++role_index) {
                if (role_index != 0U) {
                    payload.push_back(',');
                }
                const auto& role = roles[role_index];
                std::optional<std::size_t> active;
                for (const auto& candidate : role.candidates) {
                    if (callbacks_.component_ready
                        && callbacks_.component_ready(candidate.component_index)) {
                        active = candidate.component_index;
                        break;
                    }
                }
                const bool exclusive = std::any_of(
                    role.candidates.begin(), role.candidates.end(),
                    [](const CatalogProvider& candidate) {
                        return candidate.exclusive;
                    });
                payload += "{\"role\":" + json_quote(role.name)
                    + ",\"exclusive\":" + (exclusive ? "true" : "false")
                    + ",\"active\":";
                payload += active.has_value()
                    ? json_quote(plan_.components[*active].id) : "null";
                payload += ",\"active_providers\":[";
                if (active.has_value()) {
                    payload += json_quote(plan_.components[*active].id);
                }
                payload += "],\"preferred\":";
                if (role.candidates.empty()) {
                    payload += "null";
                } else {
                    payload += json_quote(plan_.components[role.candidates.front().component_index].id);
                }
                payload += ",\"candidates\":[";
                for (std::size_t candidate_index = 0U;
                     candidate_index < role.candidates.size();
                     ++candidate_index) {
                    if (candidate_index != 0U) {
                        payload.push_back(',');
                    }
                    const auto& candidate = role.candidates[candidate_index];
                    payload += "{\"component\":"
                        + json_quote(plan_.components[candidate.component_index].id)
                        + ",\"priority\":" + std::to_string(candidate.priority)
                        + ",\"exclusive\":" + (candidate.exclusive ? "true" : "false")
                        + ",\"explicit\":"
                        + (candidate.profile_preferred ? "true" : "false")
                        + ",\"declared\":true"
                        + ",\"state\":" + json_quote(component_state(candidate.component_index))
                        + "}";
                }
                payload += "]}";
            }
            payload += "]}";
            (void)broker_.send_to_session(routed.session_id, return_packet(request_id, payload));
            return;
        }
        if (method == "list_apps") {
            std::string payload = "{\"apps\":[";
            const auto apps = catalog_.launchable_apps();
            for (std::size_t app_index = 0U; app_index < apps.size(); ++app_index) {
                if (app_index != 0U) {
                    payload.push_back(',');
                }
                const auto& component = plan_.components[apps[app_index]];
                payload += "{\"id\":" + json_quote(component.id)
                    + ",\"package\":" + json_quote(component.package_id)
                    + ",\"package_version\":" + json_quote(component.package_version)
                    + ",\"package_kind\":" + json_quote(component.package_kind)
                    + ",\"name\":" + json_quote(component.name)
                    + ",\"summary\":" + json_quote(component.summary)
                    + ",\"package_summary\":" + json_quote(component.summary)
                    + ",\"state\":" + json_quote(component_state(apps[app_index]))
                    + ",\"launchable\":true";
                if (!component.icon.empty()) {
                    payload += ",\"icons\":[{\"path\":" + json_quote(component.icon) + "}]";
                }
                payload += "}";
            }
            payload += "]}";
            (void)broker_.send_to_session(routed.session_id, return_packet(request_id, payload));
            return;
        }
        if (method == "foreground_stack") {
            std::string payload = "{\"windows\":[";
            const auto foreground = callbacks_.foreground_components
                ? callbacks_.foreground_components() : std::vector<std::size_t>{};
            for (std::size_t entry = 0U; entry < foreground.size(); ++entry) {
                if (entry != 0U) {
                    payload.push_back(',');
                }
                const auto index = foreground[entry];
                const auto& component = plan_.components[index];
                payload += "{\"component\":" + json_quote(component.id)
                    + ",\"title\":" + json_quote(component.name)
                    + ",\"identity\":" + json_quote(
                        component.window.wm_class.empty()
                            ? component.window.app_id : component.window.wm_class)
                    + ",\"state\":" + json_quote(component_state(index)) + "}";
            }
            payload += "]}";
            (void)broker_.send_to_session(routed.session_id, return_packet(request_id, payload));
            return;
        }
        if (method == "activate_role" || method == "home") {
            const std::string role = method == "home"
                ? "launcher"
                : routed.message.payload_role.value_or("");
            const auto provider = catalog_.preferred_role_provider(role);
            if (!provider.has_value()) {
                reply_error(routed.session_id, request_id, "NO_PROVIDER", role);
                return;
            }
            if (!callbacks_.activate_component || !callbacks_.activate_component(*provider)) {
                reply_error(
                    routed.session_id, request_id,
                    "ROLE_UNAVAILABLE", plan_.components[*provider].id);
                return;
            }
            const std::string payload = "{\"role\":" + json_quote(role)
                + ",\"provider\":" + json_quote(plan_.components[*provider].id)
                + ",\"state\":" + json_quote(component_state(*provider)) + "}";
            (void)broker_.send_to_session(routed.session_id, return_packet(request_id, payload));
            return;
        }
        if (method == "broadcast") {
            if (!routed.message.payload_topic.has_value()) {
                reply_error(routed.session_id, request_id, "BAD_PAYLOAD", "payload.topic is required");
                return;
            }
            broadcast(
                *routed.message.payload_topic,
                routed.message.nested_payload_json.value_or("{}"),
                source_name(routed.peer));
            (void)broker_.send_to_session(
                routed.session_id,
                return_packet(request_id, "{\"ok\":true}"));
            return;
        }
        if (method == "reload_registry" || method == "display_migration"
            || method == "select_role" || method == "reset_role") {
            reply_error(
                routed.session_id, request_id,
                "NATIVE_STATIC_CATALOG", "operation requires the production dynamic Core");
            return;
        }
        reply_error(routed.session_id, request_id, "NO_METHOD", method);
    }

    std::string component_state(std::size_t component) const {
        return callbacks_.component_state
            ? callbacks_.component_state(component) : "declared";
    }

    Reactor& reactor_;
    const RuntimePlan& plan_;
    const NativeCatalog& catalog_;
    msys::native::mipc::Broker& broker_;
    RouterCallbacks callbacks_;
    std::vector<PendingCall> pending_;
    std::unordered_map<std::uint64_t, std::unordered_set<std::string>> subscriptions_;
    std::unordered_map<std::uint64_t, std::size_t> subscriber_components_;
    std::uint64_t next_forwarded_id_{1U};
};

NativeRouter::NativeRouter(
    Reactor& reactor,
    const RuntimePlan& plan,
    const NativeCatalog& catalog,
    msys::native::mipc::Broker& broker,
    RouterCallbacks callbacks)
    : impl_(std::make_unique<Impl>(
          reactor, plan, catalog, broker, std::move(callbacks))) {}

NativeRouter::~NativeRouter() = default;

bool NativeRouter::authorize_call(
    const msys::native::mipc::AccessRequest& request) const {
    return impl_->authorize_call(request);
}

void NativeRouter::on_message(const msys::native::mipc::RoutedMessage& routed) {
    impl_->on_message(routed);
}

void NativeRouter::component_ready(std::size_t component, std::uint64_t generation) {
    impl_->component_ready(component, generation);
}

void NativeRouter::component_unavailable(
    std::size_t component,
    std::uint64_t generation) {
    impl_->component_unavailable(component, generation);
}

void NativeRouter::session_closed(
    std::uint64_t session_id,
    const msys::native::mipc::PeerIdentity& peer) {
    impl_->session_closed(session_id, peer);
}

}  // namespace msys::native::lite
