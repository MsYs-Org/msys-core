#pragma once

#include "msys/reactor.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/types.h>

namespace msys::native::mipc {

inline constexpr std::size_t max_packet_bytes = 256U * 1024U;
inline constexpr std::size_t max_json_depth = 32U;
inline constexpr std::size_t max_json_container_entries = 4096U;

class ProtocolError final : public std::runtime_error {
public:
    explicit ProtocolError(const std::string& detail);
};

enum class MessageType {
    hello,
    ready,
    call,
    subscribe,
    event,
    returned,
    error,
};

// The bounded subset of the current JSON mIPC v0 envelope consumed by this
// phase. Payload values other than payload.component are syntax-checked and
// skipped without constructing a general-purpose JSON DOM.
struct DecodedMessage {
    MessageType type{MessageType::hello};
    std::optional<std::uint64_t> request_id;
    std::optional<std::uint64_t> generation;
    std::optional<std::uint64_t> deadline_ms;
    std::optional<bool> idempotent;
    std::string component;
    std::string target;
    std::string method;
    std::string topic;
    std::string code;
    std::string message;
    std::string payload_json{"{}"};
    std::optional<std::string> payload_component;
    std::optional<std::string> payload_role;
    std::optional<std::string> payload_topic;
    std::optional<std::string> payload_provider;
    std::optional<std::string> payload_action;
    std::optional<std::string> nested_payload_json;
};

[[nodiscard]] DecodedMessage decode_message(std::string_view packet);

enum class SessionKind {
    public_control,
    component,
};

struct PeerIdentity {
    SessionKind kind{SessionKind::public_control};
    pid_t pid{-1};
    uid_t uid{0};
    gid_t gid{0};
    std::string source;
    std::uint64_t generation{0U};
};

struct RoutedMessage {
    std::uint64_t session_id{0U};
    PeerIdentity peer;
    DecodedMessage message;
};

struct AccessRequest {
    const PeerIdentity& peer;
    std::uint64_t request_id{0U};
    std::string_view target;
    std::string_view method;
};

struct ComponentStatus {
    struct Provided final {
        std::string kind;
        std::string name;
        bool exclusive{false};
        std::uint32_t priority{0U};
    };

    std::string id;
    std::string lifecycle;
    std::string restart;
    std::string state;
    std::string package;
    std::string package_version;
    std::string package_kind;
    std::string name;
    std::string summary;
    std::string window_system;
    std::string window_display;
    std::string window_mode;
    std::string window_title;
    std::string window_identity;
    bool launchable{false};
    bool foreground{false};
    std::vector<Provided> provides;
};

struct OperationReply {
    bool ok{false};
    std::string component;
    std::string state;
    std::string code;
    std::string message;
};

struct BrokerHooks {
    std::function<std::vector<ComponentStatus>()> list_components;
    std::function<OperationReply(std::string_view)> start_component;
    std::function<OperationReply(std::string_view)> stop_component;

    // Called only after an exact component hello/welcome/ready handshake.
    std::function<void(std::string_view, std::uint64_t)> component_ready;

    // Called for an unexpected private-channel close. Deliberate
    // close_component_session() calls do not report a disconnect.
    std::function<void(std::string_view, std::uint64_t)> component_disconnected;

    // Receives post-handshake calls not implemented by the phase-3 lifecycle
    // subset plus subscribe/event/return/error records. The callback may reply
    // immediately or retain session_id for an asynchronous routed reply.
    std::function<void(const RoutedMessage&)> routed_message;

    // Called after any non-destructor session close so routers can discard
    // pending calls and subscriptions without retaining a dead transport id.
    std::function<void(std::uint64_t, const PeerIdentity&)> session_closed;

    // Mandatory policy boundary for calls. An empty hook denies every call.
    // The inherited private FD, not SO_PEERCRED, establishes component source
    // identity because a socketpair is normally created before the child.
    std::function<bool(const AccessRequest&)> authorize;
};

struct BrokerOptions {
    BrokerOptions() = default;
    explicit BrokerOptions(std::string path) : runtime_dir(std::move(path)) {}

    std::string runtime_dir;
    std::size_t max_sessions{128U};
    std::size_t max_queued_bytes_per_session{512U * 1024U};
    std::size_t max_queued_packets_per_session{128U};
    std::size_t max_packets_per_dispatch{32U};
};

struct BrokerStats {
    std::size_t active_public_sessions{0U};
    std::size_t active_component_sessions{0U};
    std::uint64_t accepted_public_sessions{0U};
    std::uint64_t received_packets{0U};
    std::uint64_t sent_packets{0U};
    std::uint64_t protocol_errors{0U};
    std::uint64_t access_denied{0U};
    std::uint64_t backpressure_drops{0U};
    std::uint64_t ready_notifications{0U};
};

class Broker final {
public:
    Broker(Reactor& reactor, BrokerOptions options, BrokerHooks hooks);
    ~Broker();

    Broker(const Broker&) = delete;
    Broker& operator=(const Broker&) = delete;
    Broker(Broker&&) = delete;
    Broker& operator=(Broker&&) = delete;

    // Creates an AF_UNIX SOCK_SEQPACKET socketpair and registers the broker
    // endpoint. The returned CLOEXEC fd is owned by the caller; pass it through
    // SpawnOptions::inherited_fds (which clears CLOEXEC) and expose its decimal
    // value as MSYS_CONTROL_FD. The caller must close its copy after spawning.
    [[nodiscard]] int create_component_session(
        const std::string& component,
        std::uint64_t generation);

    void close_component_session(
        std::string_view component,
        std::uint64_t generation) noexcept;

    [[nodiscard]] bool send_to_session(
        std::uint64_t session_id,
        std::string packet);
    [[nodiscard]] bool send_to_component(
        std::string_view component,
        std::uint64_t generation,
        std::string packet);

    [[nodiscard]] const std::string& control_path() const noexcept;
    [[nodiscard]] BrokerStats stats() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace msys::native::mipc
