#include "reactor_internal.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <thread>
#include <utility>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <unistd.h>

namespace msys::native {

Reactor::Impl::Impl(ReactorOptions options)
    : options_(options), owner_thread_(std::this_thread::get_id()) {
    int result = ::pthread_sigmask(SIG_SETMASK, nullptr, &original_signal_mask_);
    if (result != 0) {
        throw_system_error("pthread_sigmask(get)", result);
    }

    struct sigaction child_action {};
    if (::sigaction(SIGCHLD, nullptr, &child_action) < 0) {
        throw_system_error("sigaction(SIGCHLD)");
    }
    if (child_action.sa_handler == SIG_IGN ||
        (child_action.sa_flags & SA_NOCLDWAIT) != 0) {
        throw std::logic_error(
            "SIGCHLD must not be ignored and SA_NOCLDWAIT must be disabled");
    }

    ::sigemptyset(&signal_mask_);
    ::sigaddset(&signal_mask_, SIGCHLD);
    result = ::pthread_sigmask(SIG_BLOCK, &signal_mask_, nullptr);
    if (result != 0) {
        throw_system_error("pthread_sigmask(SIGCHLD)", result);
    }
    signal_mask_changed_ = true;

    try {
        epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
        if (epoll_fd_ < 0) {
            throw_system_error("epoll_create1");
        }
        wake_fd_ = ::eventfd(0U, EFD_NONBLOCK | EFD_CLOEXEC);
        if (wake_fd_ < 0) {
            throw_system_error("eventfd");
        }
        signal_fd_ = ::signalfd(-1, &signal_mask_, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signal_fd_ < 0) {
            throw_system_error("signalfd");
        }
        (void)add_source(
            wake_fd_, EPOLLIN, false, false, false, CallbackKind::fd,
            [this](std::uint32_t) { return drain_wake(); });
        (void)add_source(
            signal_fd_, EPOLLIN, false, false, false, CallbackKind::signal,
            [this](std::uint32_t) { return drain_signals(); });
    } catch (...) {
        close_all_fds();
        restore_signal_mask();
        throw;
    }
}

Reactor::Impl::~Impl() {
    if (std::this_thread::get_id() != owner_thread_) {
        std::terminate();
    }
    close_all_fds();
    restore_signal_mask();
}

void Reactor::Impl::require_owner() const {
    if (std::this_thread::get_id() != owner_thread_) {
        throw std::logic_error("reactor operation called from a non-owner thread");
    }
}

std::uint64_t Reactor::Impl::next_id() {
    if (next_id_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("reactor handle space exhausted");
    }
    return next_id_++;
}

std::uint64_t Reactor::Impl::add_source(
    int fd,
    std::uint32_t events,
    bool owned,
    bool public_removable,
    bool isolate_callback_exception,
    CallbackKind callback_kind,
    std::function<std::size_t(std::uint32_t)> callback) {
    const std::uint64_t id = next_id();
    epoll_event event{};
    event.events = events;
    event.data.u64 = id;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) < 0) {
        throw_system_error("epoll_ctl(ADD)");
    }
    try {
        sources_.push_back(Source{
            id,
            fd,
            owned,
            public_removable,
            isolate_callback_exception,
            callback_kind,
            std::move(callback),
        });
    } catch (...) {
        (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
        throw;
    }
    return id;
}

void Reactor::Impl::remove_source(std::uint64_t id) noexcept {
    const auto iterator = std::find_if(
        sources_.begin(), sources_.end(),
        [id](const Source& source) { return source.id == id; });
    if (iterator == sources_.end()) {
        return;
    }
    (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, iterator->fd, nullptr);
    if (iterator->owned) {
        close_nointr(iterator->fd);
    }
    sources_.erase(iterator);
}

Reactor::Impl::Source* Reactor::Impl::find_source(std::uint64_t id) noexcept {
    const auto iterator = std::find_if(
        sources_.begin(), sources_.end(),
        [id](const Source& source) { return source.id == id; });
    return iterator == sources_.end() ? nullptr : &*iterator;
}

Reactor::Impl::ChildWatch* Reactor::Impl::find_child(std::uint64_t id) noexcept {
    const auto iterator = std::find_if(
        children_.begin(), children_.end(),
        [id](const ChildWatch& child) { return child.id == id; });
    return iterator == children_.end() ? nullptr : &*iterator;
}

void Reactor::Impl::close_all_fds() noexcept {
    for (const Source& source : sources_) {
        if (source.owned) {
            close_nointr(source.fd);
        }
    }
    sources_.clear();
    close_nointr(signal_fd_);
    close_nointr(wake_fd_);
    close_nointr(epoll_fd_);
    signal_fd_ = -1;
    wake_fd_ = -1;
    epoll_fd_ = -1;
}

void Reactor::Impl::restore_signal_mask() noexcept {
    if (signal_mask_changed_) {
        (void)::pthread_sigmask(SIG_SETMASK, &original_signal_mask_, nullptr);
        signal_mask_changed_ = false;
    }
}

Reactor::Reactor(ReactorOptions options) : impl_(std::make_unique<Impl>(options)) {}
Reactor::~Reactor() = default;

Handle Reactor::watch_fd(int fd, std::uint32_t events, FdCallback callback) {
    return impl_->watch_fd(fd, events, std::move(callback));
}

Handle Reactor::add_timer(
    std::chrono::nanoseconds initial,
    std::chrono::nanoseconds interval,
    TimerCallback callback) {
    return impl_->add_timer(initial, interval, std::move(callback));
}

Handle Reactor::watch_signal(int signal_number, SignalCallback callback) {
    return impl_->watch_signal(signal_number, std::move(callback));
}

bool Reactor::remove(Handle handle) { return impl_->remove(handle); }

ChildHandle Reactor::watch_child(pid_t pid, ChildCallback callback) {
    return impl_->watch_child(pid, std::move(callback));
}

bool Reactor::unwatch_child(ChildHandle child) { return impl_->unwatch_child(child); }

SpawnedChild Reactor::spawn_process(SpawnOptions options, ChildCallback callback) {
    return impl_->spawn_process(std::move(options), std::move(callback));
}

std::size_t Reactor::run_once(std::chrono::milliseconds timeout) {
    return impl_->run_once(timeout);
}

void Reactor::run() { impl_->run(); }
std::vector<CallbackFailure> Reactor::take_callback_failures() {
    return impl_->take_callback_failures();
}
void Reactor::request_stop() noexcept { impl_->request_stop(); }
bool Reactor::stop_requested() const noexcept { return impl_->stop_requested(); }

}  // namespace msys::native
