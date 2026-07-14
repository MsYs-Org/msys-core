#pragma once

#include "msys/reactor.hpp"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <vector>

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

namespace msys::native {

[[noreturn]] inline void throw_system_error(
    const char* operation,
    int error_number = errno) {
    throw std::system_error(error_number, std::generic_category(), operation);
}

inline void close_nointr(int fd) noexcept {
    if (fd >= 0) {
        (void)::close(fd);
    }
}

class Reactor::Impl final {
public:
    explicit Impl(ReactorOptions options);
    ~Impl();

    Handle watch_fd(int fd, std::uint32_t events, Reactor::FdCallback callback);
    Handle add_timer(
        std::chrono::nanoseconds initial,
        std::chrono::nanoseconds interval,
        Reactor::TimerCallback callback);
    Handle watch_signal(int signal_number, Reactor::SignalCallback callback);
    bool remove(Handle handle);

    ChildHandle watch_child(pid_t pid, Reactor::ChildCallback callback);
    bool unwatch_child(ChildHandle child);
    SpawnedChild spawn_process(SpawnOptions options, Reactor::ChildCallback callback);

    std::size_t run_once(std::chrono::milliseconds timeout);
    void run();
    void request_stop() noexcept;
    [[nodiscard]] bool stop_requested() const noexcept;
    std::vector<CallbackFailure> take_callback_failures();

private:
    struct Source {
        std::uint64_t id{0U};
        int fd{-1};
        bool owned{false};
        bool public_removable{false};
        bool isolate_callback_exception{false};
        CallbackKind callback_kind{CallbackKind::fd};
        std::function<std::size_t(std::uint32_t)> callback;
    };

    struct SignalWatch {
        std::uint64_t id{0U};
        int signal_number{0};
        Reactor::SignalCallback callback;
    };

    struct ChildWatch {
        std::uint64_t id{0U};
        pid_t pid{-1};
        int pidfd{-1};
        std::uint64_t source_id{0U};
        ChildBackend backend{ChildBackend::sigchld};
        Reactor::ChildCallback callback;
    };

    struct PendingChild {
        std::uint64_t id{0U};
        Reactor::ChildCallback callback;
        ChildExit result;
    };

    void require_owner() const;
    std::uint64_t next_id();
    std::uint64_t add_source(
        int fd,
        std::uint32_t events,
        bool owned,
        bool public_removable,
        bool isolate_callback_exception,
        CallbackKind callback_kind,
        std::function<std::size_t(std::uint32_t)> callback);
    void remove_source(std::uint64_t id) noexcept;
    Source* find_source(std::uint64_t id) noexcept;
    ChildWatch* find_child(std::uint64_t id) noexcept;

    std::size_t drain_wake();
    std::size_t drain_signals();
    void reap_sigchld_children();
    bool try_reap_child(std::uint64_t id);
    void complete_lost_child(std::uint64_t id);
    void complete_child(std::uint64_t id, const ChildExit& result);
    std::size_t dispatch_pending_children();
    void record_callback_failure(
        CallbackKind kind,
        std::uint64_t id,
        std::exception_ptr exception);
    void close_all_fds() noexcept;
    void restore_signal_mask() noexcept;

    ReactorOptions options_{};
    std::thread::id owner_thread_{};
    int epoll_fd_{-1};
    int wake_fd_{-1};
    int signal_fd_{-1};
    std::uint64_t next_id_{1U};
    sigset_t original_signal_mask_{};
    sigset_t signal_mask_{};
    bool signal_mask_changed_{false};
    bool pidfd_waitid_unavailable_{false};
    std::atomic<bool> stop_requested_{false};
    std::vector<Source> sources_;
    std::vector<SignalWatch> signal_watches_;
    std::vector<ChildWatch> children_;
    std::deque<PendingChild> pending_children_;
    std::vector<CallbackFailure> callback_failures_;
};

}  // namespace msys::native
