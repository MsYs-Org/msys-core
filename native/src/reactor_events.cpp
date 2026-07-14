#include "reactor_internal.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace msys::native {
namespace {

itimerspec make_timer_spec(
    std::chrono::nanoseconds initial,
    std::chrono::nanoseconds interval) {
    const auto to_timespec = [](std::chrono::nanoseconds value) {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(value);
        const auto remainder = value - seconds;
        timespec result{};
        result.tv_sec = static_cast<time_t>(seconds.count());
        result.tv_nsec = static_cast<long>(remainder.count());
        return result;
    };
    itimerspec spec{};
    spec.it_value = to_timespec(initial);
    spec.it_interval = to_timespec(interval);
    return spec;
}

}  // namespace

Handle Reactor::Impl::watch_fd(
    int fd,
    std::uint32_t events,
    Reactor::FdCallback callback) {
    require_owner();
    if (fd < 0) {
        throw std::invalid_argument("watch_fd requires a non-negative fd");
    }
    if (events == 0U) {
        throw std::invalid_argument("watch_fd requires at least one epoll event");
    }
    if (!callback) {
        throw std::invalid_argument("watch_fd requires a callback");
    }
    if (std::any_of(sources_.begin(), sources_.end(), [fd](const Source& source) {
            return source.fd == fd;
        })) {
        throw std::invalid_argument("fd is already watched");
    }
    return Handle{add_source(
        fd, events, false, true, true, CallbackKind::fd,
        [callback = std::move(callback)](std::uint32_t ready_events) {
            callback(ready_events);
            return std::size_t{1U};
        })};
}

Handle Reactor::Impl::add_timer(
    std::chrono::nanoseconds initial,
    std::chrono::nanoseconds interval,
    Reactor::TimerCallback callback) {
    require_owner();
    if (initial <= std::chrono::nanoseconds::zero()) {
        throw std::invalid_argument("timer initial duration must be positive");
    }
    if (interval < std::chrono::nanoseconds::zero()) {
        throw std::invalid_argument("timer interval must not be negative");
    }
    if (!callback) {
        throw std::invalid_argument("add_timer requires a callback");
    }

    const int fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0) {
        throw_system_error("timerfd_create");
    }
    const itimerspec spec = make_timer_spec(initial, interval);
    if (::timerfd_settime(fd, 0, &spec, nullptr) < 0) {
        const int saved_errno = errno;
        close_nointr(fd);
        throw_system_error("timerfd_settime", saved_errno);
    }

    try {
        return Handle{add_source(
            fd, EPOLLIN, true, true, true, CallbackKind::timer,
            [fd, callback = std::move(callback)](std::uint32_t) {
                std::uint64_t expirations = 0U;
                const ssize_t count = ::read(fd, &expirations, sizeof(expirations));
                if (count < 0) {
                    if (errno == EAGAIN) {
                        return std::size_t{0U};
                    }
                    throw_system_error("read(timerfd)");
                }
                if (count != static_cast<ssize_t>(sizeof(expirations))) {
                    throw std::runtime_error("short read from timerfd");
                }
                callback(expirations);
                return std::size_t{1U};
            })};
    } catch (...) {
        close_nointr(fd);
        throw;
    }
}

Handle Reactor::Impl::watch_signal(
    int signal_number,
    Reactor::SignalCallback callback) {
    require_owner();
    if (signal_number <= 0 || signal_number >= NSIG || signal_number == SIGKILL ||
        signal_number == SIGSTOP) {
        throw std::invalid_argument("signal cannot be watched through signalfd");
    }
    if (!callback) {
        throw std::invalid_argument("watch_signal requires a callback");
    }

    if (::sigismember(&signal_mask_, signal_number) == 0) {
        sigset_t one_signal{};
        ::sigemptyset(&one_signal);
        ::sigaddset(&one_signal, signal_number);
        const int result = ::pthread_sigmask(SIG_BLOCK, &one_signal, nullptr);
        if (result != 0) {
            throw_system_error("pthread_sigmask(watched signal)", result);
        }
        ::sigaddset(&signal_mask_, signal_number);
        if (::signalfd(signal_fd_, &signal_mask_, SFD_NONBLOCK | SFD_CLOEXEC) < 0) {
            const int saved_errno = errno;
            ::sigdelset(&signal_mask_, signal_number);
            if (::sigismember(&original_signal_mask_, signal_number) == 0) {
                (void)::pthread_sigmask(SIG_UNBLOCK, &one_signal, nullptr);
            }
            throw_system_error("signalfd(update)", saved_errno);
        }
    }

    const std::uint64_t id = next_id();
    signal_watches_.push_back(SignalWatch{id, signal_number, std::move(callback)});
    return Handle{id};
}

bool Reactor::Impl::remove(Handle handle) {
    require_owner();
    if (!handle) {
        return false;
    }
    const auto signal_iterator = std::find_if(
        signal_watches_.begin(), signal_watches_.end(),
        [handle](const SignalWatch& watch) { return watch.id == handle.value(); });
    if (signal_iterator != signal_watches_.end()) {
        signal_watches_.erase(signal_iterator);
        return true;
    }
    Source* source = find_source(handle.value());
    if (source == nullptr || !source->public_removable) {
        return false;
    }
    remove_source(handle.value());
    return true;
}

std::size_t Reactor::Impl::drain_wake() {
    std::uint64_t value = 0U;
    for (;;) {
        const ssize_t count = ::read(wake_fd_, &value, sizeof(value));
        if (count == static_cast<ssize_t>(sizeof(value))) {
            continue;
        }
        if (count < 0 && errno == EAGAIN) {
            break;
        }
        if (count < 0) {
            throw_system_error("read(eventfd)");
        }
        throw std::runtime_error("short read from eventfd");
    }
    return 0U;
}

std::size_t Reactor::Impl::drain_signals() {
    std::size_t callback_count = 0U;
    std::array<signalfd_siginfo, 16U> records{};
    for (;;) {
        const ssize_t count = ::read(signal_fd_, records.data(), sizeof(records));
        if (count < 0) {
            if (errno == EAGAIN) {
                break;
            }
            throw_system_error("read(signalfd)");
        }
        if (count == 0 ||
            (count % static_cast<ssize_t>(sizeof(signalfd_siginfo))) != 0) {
            throw std::runtime_error("invalid read from signalfd");
        }
        const std::size_t record_count =
            static_cast<std::size_t>(count) / sizeof(signalfd_siginfo);
        for (std::size_t index = 0; index < record_count; ++index) {
            const signalfd_siginfo& record = records[index];
            const int signal_number = static_cast<int>(record.ssi_signo);
            if (signal_number == SIGCHLD) {
                reap_sigchld_children();
            }

            std::vector<SignalWatch> callbacks;
            for (const SignalWatch& watch : signal_watches_) {
                if (watch.signal_number == signal_number) {
                    callbacks.push_back(watch);
                }
            }
            const SignalEvent event{
                signal_number,
                static_cast<int>(record.ssi_code),
                static_cast<pid_t>(record.ssi_pid),
                static_cast<uid_t>(record.ssi_uid),
                static_cast<int>(record.ssi_status),
                record.ssi_overrun,
            };
            for (const SignalWatch& watch : callbacks) {
                try {
                    watch.callback(event);
                } catch (...) {
                    record_callback_failure(
                        CallbackKind::signal, watch.id, std::current_exception());
                }
                ++callback_count;
            }
        }
    }
    return callback_count;
}

std::size_t Reactor::Impl::run_once(std::chrono::milliseconds timeout) {
    require_owner();
    if (timeout < std::chrono::milliseconds{-1}) {
        throw std::invalid_argument("run_once timeout must be -1ms or greater");
    }
    std::size_t callback_count = dispatch_pending_children();
    if (callback_count != 0U || stop_requested_.load(std::memory_order_acquire)) {
        return callback_count;
    }

    const bool infinite = timeout == std::chrono::milliseconds{-1};
    const auto deadline = std::chrono::steady_clock::now() +
                          (infinite ? std::chrono::milliseconds::zero() : timeout);
    std::array<epoll_event, 32U> events{};
    int event_count = 0;
    for (;;) {
        int timeout_ms = -1;
        if (!infinite) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                timeout_ms = 0;
            } else {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now + std::chrono::milliseconds{1});
                timeout_ms = remaining.count() > INT_MAX
                                 ? INT_MAX
                                 : static_cast<int>(remaining.count());
            }
        }
        event_count = ::epoll_wait(
            epoll_fd_, events.data(), static_cast<int>(events.size()), timeout_ms);
        if (event_count >= 0) {
            break;
        }
        if (errno != EINTR) {
            throw_system_error("epoll_wait");
        }
    }

    for (int index = 0; index < event_count; ++index) {
        const epoll_event& event = events[static_cast<std::size_t>(index)];
        Source* source = find_source(event.data.u64);
        if (source == nullptr) {
            continue;
        }
        const auto callback = source->callback;
        const bool isolate = source->isolate_callback_exception;
        const CallbackKind callback_kind = source->callback_kind;
        const std::uint64_t source_id = source->id;
        try {
            callback_count += callback(event.events);
        } catch (...) {
            if (!isolate) {
                throw;
            }
            record_callback_failure(callback_kind, source_id, std::current_exception());
            ++callback_count;
        }
    }
    callback_count += dispatch_pending_children();
    return callback_count;
}

void Reactor::Impl::run() {
    require_owner();
    while (!stop_requested_.load(std::memory_order_acquire)) {
        (void)run_once(std::chrono::milliseconds{-1});
    }
}

void Reactor::Impl::request_stop() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    const std::uint64_t one = 1U;
    for (;;) {
        const ssize_t count = ::write(wake_fd_, &one, sizeof(one));
        if (count == static_cast<ssize_t>(sizeof(one)) ||
            (count < 0 && (errno == EAGAIN || errno == EBADF))) {
            return;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        // request_stop is noexcept and the atomic flag is authoritative even
        // if an unexpected eventfd write error occurs.
        return;
    }
}

bool Reactor::Impl::stop_requested() const noexcept {
    return stop_requested_.load(std::memory_order_acquire);
}

void Reactor::Impl::record_callback_failure(
    CallbackKind kind,
    std::uint64_t id,
    std::exception_ptr exception) {
    callback_failures_.push_back(CallbackFailure{kind, Handle{id}, std::move(exception)});
}

std::vector<CallbackFailure> Reactor::Impl::take_callback_failures() {
    require_owner();
    std::vector<CallbackFailure> failures = std::move(callback_failures_);
    callback_failures_.clear();
    return failures;
}

}  // namespace msys::native
