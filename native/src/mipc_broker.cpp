#include "msys/mipc_broker.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace msys::native::mipc {
namespace {

[[noreturn]] void fail_errno(const std::string& operation, int error_number = errno) {
    throw std::runtime_error(
        "mIPC broker: " + operation + ": " + std::string{std::strerror(error_number)});
}

[[noreturn]] void fail(const std::string& detail) {
    throw std::runtime_error("mIPC broker: " + detail);
}

void close_fd(int& descriptor) noexcept {
    if (descriptor >= 0) {
        (void)::close(descriptor);
        descriptor = -1;
    }
}

void write_all(int descriptor, std::string_view value) {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const ssize_t count = ::write(
            descriptor, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            fail_errno("write runtime lock");
        }
        offset += static_cast<std::size_t>(count);
    }
}

void validate_runtime_path(std::string_view path) {
    if (path.empty() || path.front() != '/' || path == "/"
        || path.find('\0') != std::string_view::npos) {
        fail("runtime_dir must be a non-root absolute path");
    }
    if (path.back() == '/') {
        fail("runtime_dir must not have a trailing slash");
    }
    std::size_t offset = 1U;
    while (offset < path.size()) {
        const std::size_t separator = path.find('/', offset);
        const std::size_t end = separator == std::string_view::npos ? path.size() : separator;
        const std::string_view segment = path.substr(offset, end - offset);
        if (segment.empty() || segment == "." || segment == "..") {
            fail("runtime_dir contains an unsafe path segment");
        }
        if (separator == std::string_view::npos) {
            break;
        }
        offset = separator + 1U;
    }
}

class RuntimeClaim final {
public:
    explicit RuntimeClaim(const std::string& runtime_dir) : runtime_dir_(runtime_dir) {
        validate_runtime_path(runtime_dir_);
        if (::mkdir(runtime_dir_.c_str(), 0700) != 0 && errno != EEXIST) {
            fail_errno("mkdir runtime_dir");
        }
        dir_fd_ = ::open(
            runtime_dir_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (dir_fd_ < 0) {
            fail_errno("open runtime_dir");
        }
        try {
            validate_directory();
            acquire_lock();
        } catch (...) {
            close_fd(lock_fd_);
            close_fd(dir_fd_);
            throw;
        }
    }

    ~RuntimeClaim() {
        if (lock_fd_ >= 0) {
            (void)::flock(lock_fd_, LOCK_UN);
        }
        close_fd(lock_fd_);
        close_fd(dir_fd_);
    }

    RuntimeClaim(const RuntimeClaim&) = delete;
    RuntimeClaim& operator=(const RuntimeClaim&) = delete;

    [[nodiscard]] int directory_fd() const noexcept { return dir_fd_; }
    [[nodiscard]] const std::string& runtime_dir() const noexcept { return runtime_dir_; }

private:
    void validate_directory() {
        struct stat metadata {};
        if (::fstat(dir_fd_, &metadata) != 0) {
            fail_errno("fstat runtime_dir");
        }
        if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
            fail("runtime_dir must be a directory owned by the effective uid");
        }
        constexpr mode_t unsafe = static_cast<mode_t>(S_IRWXG | S_IRWXO);
        if ((metadata.st_mode & unsafe) != 0
            || (metadata.st_mode & static_cast<mode_t>(S_IRWXU))
                != static_cast<mode_t>(S_IRWXU)) {
            fail("runtime_dir permissions must be 0700");
        }
    }

    void acquire_lock() {
        lock_fd_ = ::openat(
            dir_fd_, ".msysd.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (lock_fd_ < 0) {
            fail_errno("open runtime lock");
        }
        struct stat metadata {};
        if (::fstat(lock_fd_, &metadata) != 0) {
            fail_errno("fstat runtime lock");
        }
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != ::geteuid()) {
            fail("runtime lock must be a regular file owned by the effective uid");
        }
        if (::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                fail("runtime_dir is already owned");
            }
            fail_errno("flock runtime lock");
        }
        if (::fchmod(lock_fd_, 0600) != 0 || ::ftruncate(lock_fd_, 0) != 0
            || ::lseek(lock_fd_, 0, SEEK_SET) < 0) {
            fail_errno("prepare runtime lock");
        }
        const std::string owner = std::to_string(::getpid()) + "\n";
        write_all(lock_fd_, owner);
        if (::fsync(lock_fd_) != 0) {
            fail_errno("fsync runtime lock");
        }
    }

    std::string runtime_dir_;
    int dir_fd_{-1};
    int lock_fd_{-1};
};

std::string json_quote(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
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
                output.push_back(hex[static_cast<std::size_t>(byte >> 4U)]);
                output.push_back(hex[static_cast<std::size_t>(byte & 0x0fU)]);
            } else {
                output.push_back(character);
            }
        }
    }
    output.push_back('"');
    return output;
}

std::string error_response(
    std::uint64_t request_id,
    std::string_view code,
    std::string_view message) {
    return "{\"type\":\"error\",\"id\":" + std::to_string(request_id)
        + ",\"code\":" + json_quote(code)
        + ",\"message\":" + json_quote(message) + "}";
}

std::string public_welcome() {
    return "{\"type\":\"welcome\",\"component\":\"public\",\"generation\":0}";
}

std::string component_welcome(
    std::string_view component,
    std::uint64_t generation,
    std::string_view runtime_dir) {
    return "{\"type\":\"welcome\",\"component\":" + json_quote(component)
        + ",\"generation\":" + std::to_string(generation)
        + ",\"runtime_dir\":" + json_quote(runtime_dir) + "}";
}

enum class HandshakeState {
    public_ready,
    awaiting_hello,
    welcomed,
    component_ready,
};

enum class SendResult {
    sent,
    would_block,
    failed,
};

}  // namespace

class Broker::Impl final {
public:
    Impl(Reactor& reactor, BrokerOptions options, BrokerHooks hooks)
        : reactor_(reactor),
          options_(std::move(options)),
          hooks_(std::move(hooks)),
          runtime_(options_.runtime_dir),
          control_path_(runtime_.runtime_dir() + "/control.sock"),
          receive_buffer_(max_packet_bytes + 1U, '\0') {
        validate_options();
        create_listener();
    }

    ~Impl() {
        destroying_ = true;
        while (!sessions_.empty()) {
            close_session(sessions_.back()->id, false);
        }
        if (listen_watch_) {
            (void)reactor_.remove(listen_watch_);
            listen_watch_ = Handle{};
        }
        close_fd(listen_fd_);
        if (socket_created_) {
            (void)::unlinkat(runtime_.directory_fd(), "control.sock", 0);
        }
    }

    int create_component_session(const std::string& component, std::uint64_t generation) {
        if (component.empty() || component.size() > 128U || generation == 0U) {
            throw std::invalid_argument(
                "create_component_session requires a component and positive generation");
        }
        std::array<int, 2U> sockets{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets.data()) != 0) {
            fail_errno("socketpair component session");
        }
        try {
            set_nonblocking(sockets[0U]);
            PeerIdentity peer = peer_identity(sockets[0U], SessionKind::component);
            peer.source = component;
            peer.generation = generation;
            (void)add_session(
                sockets[0U], std::move(peer), HandshakeState::awaiting_hello,
                component, generation);
            sockets[0U] = -1;
            const int child = sockets[1U];
            sockets[1U] = -1;
            return child;
        } catch (...) {
            close_fd(sockets[0U]);
            close_fd(sockets[1U]);
            throw;
        }
    }

    void close_component_session(
        std::string_view component,
        std::uint64_t generation) noexcept {
        for (;;) {
            const auto iterator = std::find_if(
                sessions_.begin(), sessions_.end(),
                [component, generation](const auto& session) {
                    return session->peer.kind == SessionKind::component
                        && session->expected_component == component
                        && session->expected_generation == generation;
                });
            if (iterator == sessions_.end()) {
                return;
            }
            close_session((*iterator)->id, false);
        }
    }

    bool send_to_session(std::uint64_t session_id, std::string packet) {
        if (find_session(session_id) == nullptr) {
            return false;
        }
        queue_packet(session_id, std::move(packet));
        return find_session(session_id) != nullptr;
    }

    bool send_to_component(
        std::string_view component,
        std::uint64_t generation,
        std::string packet) {
        const auto iterator = std::find_if(
            sessions_.begin(), sessions_.end(),
            [component, generation](const auto& session) {
                return session->peer.kind == SessionKind::component
                    && session->expected_component == component
                    && session->expected_generation == generation
                    && session->handshake == HandshakeState::component_ready;
            });
        if (iterator == sessions_.end()) {
            return false;
        }
        return send_to_session((*iterator)->id, std::move(packet));
    }

    [[nodiscard]] const std::string& control_path() const noexcept {
        return control_path_;
    }

    [[nodiscard]] BrokerStats stats() const noexcept {
        BrokerStats result = counters_;
        for (const auto& session : sessions_) {
            if (session->peer.kind == SessionKind::public_control) {
                ++result.active_public_sessions;
            } else {
                ++result.active_component_sessions;
            }
        }
        return result;
    }

private:
    struct Session final {
        std::uint64_t id{0U};
        int fd{-1};
        PeerIdentity peer{};
        HandshakeState handshake{HandshakeState::awaiting_hello};
        std::string expected_component;
        std::uint64_t expected_generation{0U};
        Handle watch{};
        std::uint32_t watched_events{0U};
        std::deque<std::string> outgoing;
        std::size_t outgoing_offset{0U};
        std::size_t queued_bytes{0U};
        std::string incoming;
    };

    void validate_options() {
        if (options_.max_sessions == 0U || options_.max_sessions > 4096U) {
            throw std::invalid_argument("mIPC max_sessions is outside 1..4096");
        }
        if (options_.max_queued_bytes_per_session < 64U
            || options_.max_queued_bytes_per_session > 16U * 1024U * 1024U
            || options_.max_queued_packets_per_session == 0U
            || options_.max_queued_packets_per_session > 4096U
            || options_.max_packets_per_dispatch == 0U
            || options_.max_packets_per_dispatch > 1024U) {
            throw std::invalid_argument("mIPC queue/dispatch bounds are invalid");
        }
    }

    void create_listener() {
        if (control_path_.size() >= sizeof(sockaddr_un{}.sun_path)) {
            fail("runtime control socket path is too long");
        }
        if (::unlinkat(runtime_.directory_fd(), "control.sock", 0) != 0
            && errno != ENOENT) {
            fail_errno("remove stale control.sock");
        }

        // Keep the public ABI identical to the Python Core and existing SDK:
        // AF_UNIX/SOCK_STREAM with one JSON object per LF-terminated line.
        // Private inherited component channels remain SOCK_SEQPACKET records.
        listen_fd_ = ::socket(
            AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listen_fd_ < 0) {
            fail_errno("socket public control");
        }
        try {
            sockaddr_un address{};
            address.sun_family = AF_UNIX;
            std::memcpy(
                address.sun_path, control_path_.c_str(), control_path_.size() + 1U);
            const auto address_size = static_cast<socklen_t>(
                offsetof(sockaddr_un, sun_path) + control_path_.size() + 1U);
            const mode_t previous_mask = ::umask(0077);
            const int bind_result = ::bind(
                listen_fd_, reinterpret_cast<const sockaddr*>(&address), address_size);
            const int bind_errno = errno;
            (void)::umask(previous_mask);
            if (bind_result != 0) {
                fail_errno("bind public control", bind_errno);
            }
            socket_created_ = true;
            if (::chmod(control_path_.c_str(), 0600) != 0) {
                fail_errno("chmod public control");
            }
            if (::listen(listen_fd_, 32) != 0) {
                fail_errno("listen public control");
            }
            listen_watch_ = reactor_.watch_fd(
                listen_fd_,
                static_cast<std::uint32_t>(EPOLLIN | EPOLLERR | EPOLLHUP),
                [this](std::uint32_t events) { on_listener(events); });
        } catch (...) {
            close_fd(listen_fd_);
            if (socket_created_) {
                (void)::unlinkat(runtime_.directory_fd(), "control.sock", 0);
                socket_created_ = false;
            }
            throw;
        }
    }

    static void set_nonblocking(int descriptor) {
        const int current = ::fcntl(descriptor, F_GETFL, 0);
        if (current < 0 || ::fcntl(descriptor, F_SETFL, current | O_NONBLOCK) != 0) {
            fail_errno("set component broker fd nonblocking");
        }
    }

    static PeerIdentity peer_identity(int descriptor, SessionKind kind) {
        struct ucred credentials {};
        socklen_t size = static_cast<socklen_t>(sizeof(credentials));
        if (::getsockopt(
                descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0
            || size != static_cast<socklen_t>(sizeof(credentials))) {
            fail_errno("SO_PEERCRED");
        }
        PeerIdentity result{};
        result.kind = kind;
        result.pid = credentials.pid;
        result.uid = credentials.uid;
        result.gid = credentials.gid;
        result.source = kind == SessionKind::public_control ? "public" : "";
        return result;
    }

    std::uint64_t add_session(
        int descriptor,
        PeerIdentity peer,
        HandshakeState handshake,
        std::string expected_component,
        std::uint64_t expected_generation) {
        if (sessions_.size() >= options_.max_sessions) {
            fail("session limit reached");
        }
        if (next_session_id_ == std::numeric_limits<std::uint64_t>::max()) {
            fail("session id space exhausted");
        }
        auto session = std::make_unique<Session>();
        session->id = next_session_id_++;
        session->fd = descriptor;
        session->peer = std::move(peer);
        session->handshake = handshake;
        session->expected_component = std::move(expected_component);
        session->expected_generation = expected_generation;
        const std::uint64_t id = session->id;
        sessions_.push_back(std::move(session));
        try {
            install_session_watch(id);
        } catch (...) {
            const auto iterator = find_session_iterator(id);
            if (iterator != sessions_.end()) {
                sessions_.erase(iterator);
            }
            throw;
        }
        return id;
    }

    void on_listener(std::uint32_t events) {
        if ((events & static_cast<std::uint32_t>(EPOLLERR | EPOLLHUP)) != 0U) {
            fail("public control listener failed");
        }
        std::size_t accepted = 0U;
        while (accepted < options_.max_packets_per_dispatch) {
            const int descriptor = ::accept4(
                listen_fd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (descriptor < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                fail_errno("accept public control");
            }
            ++accepted;
            if (sessions_.size() >= options_.max_sessions) {
                (void)::close(descriptor);
                continue;
            }
            std::uint64_t id = 0U;
            try {
                PeerIdentity peer = peer_identity(descriptor, SessionKind::public_control);
                id = add_session(
                    descriptor, std::move(peer), HandshakeState::public_ready, "", 0U);
                ++counters_.accepted_public_sessions;
                queue_packet(id, public_welcome());
            } catch (const std::exception& error) {
                if (id == 0U) {
                    (void)::close(descriptor);
                } else {
                    close_session(id, false);
                }
                std::cerr << "mIPC broker: rejected public client: "
                          << error.what() << '\n';
            }
        }
    }

    void install_session_watch(std::uint64_t id) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        std::uint32_t events = static_cast<std::uint32_t>(
            EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP);
        if (!session->outgoing.empty()) {
            events |= static_cast<std::uint32_t>(EPOLLOUT);
        }
        if (session->watch && session->watched_events == events) {
            return;
        }
        if (session->watch) {
            (void)reactor_.remove(session->watch);
            session->watch = Handle{};
        }
        session->watched_events = events;
        const int descriptor = session->fd;
        session->watch = reactor_.watch_fd(
            descriptor, events,
            [this, id](std::uint32_t ready_events) {
                on_session(id, ready_events);
            });
    }

    void on_session(std::uint64_t id, std::uint32_t events) {
        if ((events & static_cast<std::uint32_t>(EPOLLIN)) != 0U) {
            drain_session(id);
        }
        if (find_session(id) == nullptr) {
            return;
        }
        if ((events & static_cast<std::uint32_t>(EPOLLOUT)) != 0U) {
            flush_session(id);
        }
        if (find_session(id) == nullptr) {
            return;
        }
        if ((events & static_cast<std::uint32_t>(EPOLLRDHUP | EPOLLERR | EPOLLHUP)) != 0U) {
            close_session(id, true);
        }
    }

    void drain_session(std::uint64_t id) {
        std::size_t packet_index = 0U;
        while (packet_index < options_.max_packets_per_dispatch) {
            Session* session = find_session(id);
            if (session == nullptr) {
                return;
            }
            std::array<char, CMSG_SPACE(sizeof(int) * 16U)> control{};
            iovec vector{};
            vector.iov_base = receive_buffer_.data();
            vector.iov_len = receive_buffer_.size();
            msghdr message{};
            message.msg_iov = &vector;
            message.msg_iovlen = 1U;
            message.msg_control = control.data();
            message.msg_controllen = control.size();
            const ssize_t count = ::recvmsg(
                session->fd, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
            if (count < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return;
                }
                close_session(id, true);
                return;
            }
            if (count == 0) {
                close_session(id, true);
                return;
            }
            ++packet_index;
            bool unexpected_ancillary = false;
            for (cmsghdr* header = CMSG_FIRSTHDR(&message);
                 header != nullptr;
                 header = CMSG_NXTHDR(&message, header)) {
                unexpected_ancillary = true;
                if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS
                    || header->cmsg_len < CMSG_LEN(0U)) {
                    continue;
                }
                const std::size_t payload_bytes = header->cmsg_len - CMSG_LEN(0U);
                const std::size_t descriptor_count = payload_bytes / sizeof(int);
                const unsigned char* data = CMSG_DATA(header);
                for (std::size_t offset = 0U; offset < descriptor_count; ++offset) {
                    int received = -1;
                    std::memcpy(
                        &received, data + offset * sizeof(int), sizeof(received));
                    if (received >= 0) {
                        (void)::close(received);
                    }
                }
            }
            const bool is_public = session->peer.kind == SessionKind::public_control;
            const bool invalid_size = (!is_public
                    && count > static_cast<ssize_t>(max_packet_bytes))
                || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0;
            if (invalid_size || unexpected_ancillary) {
                ++counters_.protocol_errors;
                close_session(id, true);
                return;
            }
            try {
                const auto size = static_cast<std::size_t>(count);
                const std::string_view received{receive_buffer_.data(), size};
                if (is_public) {
                    handle_public_bytes(id, received);
                } else {
                    ++counters_.received_packets;
                    handle_packet(id, decode_message(received));
                }
            } catch (const ProtocolError&) {
                ++counters_.protocol_errors;
                close_session(id, true);
                return;
            }
        }
    }

    void handle_public_bytes(std::uint64_t id, std::string_view received) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        session->incoming.append(received);
        std::size_t consumed = 0U;
        std::size_t packet_count = 0U;
        for (;;) {
            const std::size_t newline = session->incoming.find('\n', consumed);
            if (newline == std::string::npos) {
                break;
            }
            if (packet_count >= options_.max_packets_per_dispatch) {
                throw ProtocolError("too many public records in one dispatch");
            }
            const std::size_t length = newline - consumed;
            if (length > max_packet_bytes) {
                throw ProtocolError("public record exceeds 262144 bytes");
            }
            const std::string_view packet{
                session->incoming.data() + consumed,
                length,
            };
            ++counters_.received_packets;
            handle_packet(id, decode_message(packet));
            ++packet_count;
            consumed = newline + 1U;
            session = find_session(id);
            if (session == nullptr) {
                return;
            }
        }
        if (consumed != 0U) {
            session->incoming.erase(0U, consumed);
        }
        if (session->incoming.size() > max_packet_bytes) {
            throw ProtocolError("public record exceeds 262144 bytes");
        }
    }

    void handle_packet(std::uint64_t id, const DecodedMessage& message) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        if (session->peer.kind == SessionKind::public_control) {
            if (message.type == MessageType::hello
                && message.component.empty() && !message.generation.has_value()) {
                queue_packet(id, public_welcome());
                return;
            }
            if (message.type != MessageType::call) {
                ++counters_.protocol_errors;
                close_session(id, false);
                return;
            }
            handle_call(id, message);
            return;
        }

        if (session->handshake == HandshakeState::awaiting_hello) {
            if (message.type != MessageType::hello
                || message.component != session->expected_component
                || message.generation != session->expected_generation) {
                ++counters_.protocol_errors;
                close_session(id, true);
                return;
            }
            session->handshake = HandshakeState::welcomed;
            queue_packet(id, component_welcome(
                session->expected_component,
                session->expected_generation,
                runtime_.runtime_dir()));
            return;
        }
        if (session->handshake == HandshakeState::welcomed) {
            if (message.type == MessageType::subscribe) {
                route_message(id, message);
                return;
            }
            if (message.type != MessageType::ready) {
                ++counters_.protocol_errors;
                close_session(id, true);
                return;
            }
            session->handshake = HandshakeState::component_ready;
            const std::string component = session->expected_component;
            const std::uint64_t generation = session->expected_generation;
            ++counters_.ready_notifications;
            if (hooks_.component_ready) {
                hooks_.component_ready(component, generation);
            }
            return;
        }
        if (message.type == MessageType::call) {
            handle_call(id, message);
            return;
        }
        if (message.type == MessageType::subscribe
            || message.type == MessageType::event
            || message.type == MessageType::returned
            || message.type == MessageType::error) {
            route_message(id, message);
            return;
        }
        ++counters_.protocol_errors;
        close_session(id, true);
    }

    void route_message(std::uint64_t id, const DecodedMessage& message) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        if (!hooks_.routed_message) {
            ++counters_.access_denied;
            if (message.request_id.has_value()) {
                queue_packet(id, error_response(
                    *message.request_id, "NOT_IMPLEMENTED", "native router is unavailable"));
            }
            return;
        }
        const RoutedMessage routed{id, session->peer, message};
        hooks_.routed_message(routed);
    }

    void handle_call(std::uint64_t id, const DecodedMessage& message) {
        Session* session = find_session(id);
        if (session == nullptr || !message.request_id.has_value()) {
            return;
        }
        const std::uint64_t request_id = *message.request_id;
        // Copy the identity so an embedding policy hook may re-enter the
        // broker without invalidating AccessRequest::peer.
        const PeerIdentity peer = session->peer;
        const AccessRequest request{
            peer,
            request_id,
            message.target,
            message.method,
        };
        bool authorized = false;
        try {
            authorized = hooks_.authorize && hooks_.authorize(request);
        } catch (...) {
            authorized = false;
        }
        if (!authorized) {
            ++counters_.access_denied;
            queue_packet(id, error_response(
                request_id, "ACCESS_DENIED", "mIPC call is not authorized"));
            return;
        }
        try {
            if (message.target == "msys.core" && message.method == "list_components") {
                std::vector<ComponentStatus> components;
                if (hooks_.list_components) {
                    components = hooks_.list_components();
                }
                std::sort(
                    components.begin(), components.end(),
                    [](const ComponentStatus& left, const ComponentStatus& right) {
                        return left.id < right.id;
                    });
                std::string response = "{\"type\":\"return\",\"id\":"
                    + std::to_string(request_id) + ",\"payload\":{\"components\":[";
                for (std::size_t index = 0U; index < components.size(); ++index) {
                    if (index != 0U) {
                        response.push_back(',');
                    }
                    const auto& component = components[index];
                    response += "{\"id\":" + json_quote(component.id)
                        + ",\"lifecycle\":" + json_quote(component.lifecycle)
                        + ",\"restart\":" + json_quote(component.restart)
                        + ",\"state\":" + json_quote(component.state)
                        + ",\"package\":" + json_quote(component.package)
                        + ",\"package_version\":" + json_quote(component.package_version)
                        + ",\"package_kind\":" + json_quote(component.package_kind)
                        + ",\"name\":" + json_quote(
                            component.name.empty() ? component.id : component.name)
                        + ",\"summary\":" + json_quote(component.summary)
                        + ",\"launchable\":" + (component.launchable ? "true" : "false")
                        + ",\"foreground\":" + (component.foreground ? "true" : "false")
                        + ",\"provides\":[";
                    for (std::size_t provide_index = 0U;
                         provide_index < component.provides.size();
                         ++provide_index) {
                        if (provide_index != 0U) {
                            response.push_back(',');
                        }
                        const auto& provided = component.provides[provide_index];
                        response += "{\"kind\":" + json_quote(provided.kind)
                            + ",\"name\":" + json_quote(provided.name)
                            + ",\"exclusive\":" + (provided.exclusive ? "true" : "false")
                            + ",\"priority\":" + std::to_string(provided.priority) + "}";
                    }
                    response += "],\"windowing\":{\"system\":"
                        + json_quote(component.window_system)
                        + ",\"display\":" + json_quote(component.window_display)
                        + ",\"mode\":" + json_quote(component.window_mode)
                        + ",\"title\":" + json_quote(component.window_title)
                        + ",\"identity\":{\"app_id\":"
                        + json_quote(component.window_identity)
                        + ",\"x11_wm_class\":" + json_quote(component.window_identity)
                        + "}}}";
                }
                response += "]}}";
                queue_packet(id, std::move(response));
                return;
            }
            if (message.target == "msys.core"
                && (message.method == "start" || message.method == "stop")) {
                if (!message.payload_component.has_value()) {
                    queue_packet(id, error_response(
                        request_id, "BAD_PAYLOAD", "payload.component is required"));
                    return;
                }
                OperationReply reply{};
                if (message.method == "start" && hooks_.start_component) {
                    reply = hooks_.start_component(*message.payload_component);
                } else if (message.method == "stop" && hooks_.stop_component) {
                    reply = hooks_.stop_component(*message.payload_component);
                } else {
                    reply.code = "NOT_IMPLEMENTED";
                    reply.message = "lifecycle hook is unavailable";
                }
                if (!reply.ok) {
                    queue_packet(id, error_response(
                        request_id,
                        reply.code.empty() ? "CALL_FAILED" : reply.code,
                        reply.message.empty() ? "lifecycle operation failed" : reply.message));
                    return;
                }
                const std::string_view component = reply.component.empty()
                    ? std::string_view{*message.payload_component}
                    : std::string_view{reply.component};
                queue_packet(
                    id,
                    "{\"type\":\"return\",\"id\":" + std::to_string(request_id)
                        + ",\"payload\":{\"component\":" + json_quote(component)
                        + ",\"state\":" + json_quote(reply.state) + "}}" );
                return;
            }
            route_message(id, message);
        } catch (const std::exception& error) {
            queue_packet(id, error_response(request_id, "CALL_FAILED", error.what()));
        }
    }

    void queue_packet(std::uint64_t id, std::string packet) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        if (packet.empty() || packet.size() > max_packet_bytes) {
            ++counters_.backpressure_drops;
            close_session(id, session->peer.kind == SessionKind::component);
            return;
        }
        if (session->peer.kind == SessionKind::public_control) {
            packet.push_back('\n');
        }
        if (packet.size() > options_.max_queued_bytes_per_session
            || session->outgoing.size() >= options_.max_queued_packets_per_session
            || session->queued_bytes
                > options_.max_queued_bytes_per_session - packet.size()) {
            ++counters_.backpressure_drops;
            close_session(id, session->peer.kind == SessionKind::component);
            return;
        }
        std::size_t offset = 0U;
        if (session->outgoing.empty()) {
            const SendResult sent = send_one(*session, packet, offset);
            if (sent == SendResult::sent) {
                return;
            }
            if (sent == SendResult::failed) {
                close_session(id, session->peer.kind == SessionKind::component);
                return;
            }
        }
        session = find_session(id);
        if (session == nullptr) {
            return;
        }
        session->outgoing.push_back(std::move(packet));
        if (session->outgoing.size() == 1U) {
            session->outgoing_offset = offset;
        }
        session->queued_bytes += session->outgoing.back().size();
        install_session_watch(id);
    }

    SendResult send_one(
        Session& session,
        const std::string& packet,
        std::size_t& offset) {
        for (;;) {
            const ssize_t count = ::send(
                session.fd,
                packet.data() + offset,
                packet.size() - offset,
                MSG_DONTWAIT | MSG_NOSIGNAL);
            if (count > 0) {
                if (session.peer.kind == SessionKind::component
                    && count != static_cast<ssize_t>(packet.size())) {
                    return SendResult::failed;
                }
                offset += static_cast<std::size_t>(count);
                if (offset == packet.size()) {
                    offset = 0U;
                    ++counters_.sent_packets;
                    return SendResult::sent;
                }
                return SendResult::would_block;
            }
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return SendResult::would_block;
            }
            return SendResult::failed;
        }
    }

    void flush_session(std::uint64_t id) {
        Session* session = find_session(id);
        if (session == nullptr) {
            return;
        }
        std::size_t sent_packets = 0U;
        while (!session->outgoing.empty()
               && sent_packets < options_.max_packets_per_dispatch) {
            const SendResult result = send_one(
                *session,
                session->outgoing.front(),
                session->outgoing_offset);
            if (result == SendResult::would_block) {
                return;
            }
            if (result == SendResult::failed) {
                close_session(id, session->peer.kind == SessionKind::component);
                return;
            }
            session->queued_bytes -= session->outgoing.front().size();
            session->outgoing.pop_front();
            session->outgoing_offset = 0U;
            ++sent_packets;
        }
        install_session_watch(id);
    }

    void close_session(std::uint64_t id, bool notify_component) {
        const auto iterator = find_session_iterator(id);
        if (iterator == sessions_.end()) {
            return;
        }
        Session& session = **iterator;
        const bool notify = notify_component && !destroying_
            && session.peer.kind == SessionKind::component;
        const std::string component = session.expected_component;
        const std::uint64_t generation = session.expected_generation;
        const PeerIdentity peer = session.peer;
        if (session.watch) {
            (void)reactor_.remove(session.watch);
            session.watch = Handle{};
        }
        close_fd(session.fd);
        sessions_.erase(iterator);
        if (!destroying_ && hooks_.session_closed) {
            hooks_.session_closed(id, peer);
        }
        if (notify && hooks_.component_disconnected) {
            hooks_.component_disconnected(component, generation);
        }
    }

    Session* find_session(std::uint64_t id) noexcept {
        const auto iterator = find_session_iterator(id);
        return iterator == sessions_.end() ? nullptr : iterator->get();
    }

    std::vector<std::unique_ptr<Session>>::iterator find_session_iterator(
        std::uint64_t id) noexcept {
        return std::find_if(
            sessions_.begin(), sessions_.end(),
            [id](const auto& session) { return session->id == id; });
    }

    Reactor& reactor_;
    BrokerOptions options_;
    BrokerHooks hooks_;
    RuntimeClaim runtime_;
    std::string control_path_;
    int listen_fd_{-1};
    Handle listen_watch_{};
    bool socket_created_{false};
    bool destroying_{false};
    std::uint64_t next_session_id_{1U};
    std::vector<std::unique_ptr<Session>> sessions_;
    std::vector<char> receive_buffer_;
    BrokerStats counters_{};
};

Broker::Broker(Reactor& reactor, BrokerOptions options, BrokerHooks hooks)
    : impl_(std::make_unique<Impl>(reactor, std::move(options), std::move(hooks))) {}

Broker::~Broker() = default;

int Broker::create_component_session(
    const std::string& component,
    std::uint64_t generation) {
    return impl_->create_component_session(component, generation);
}

void Broker::close_component_session(
    std::string_view component,
    std::uint64_t generation) noexcept {
    impl_->close_component_session(component, generation);
}

bool Broker::send_to_session(std::uint64_t session_id, std::string packet) {
    return impl_->send_to_session(session_id, std::move(packet));
}

bool Broker::send_to_component(
    std::string_view component,
    std::uint64_t generation,
    std::string packet) {
    return impl_->send_to_component(component, generation, std::move(packet));
}

const std::string& Broker::control_path() const noexcept {
    return impl_->control_path();
}

BrokerStats Broker::stats() const noexcept {
    return impl_->stats();
}

}  // namespace msys::native::mipc
