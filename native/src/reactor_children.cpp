#include "reactor_internal.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

namespace msys::native {
namespace {

int open_pidfd(pid_t pid) noexcept {
#if defined(SYS_pidfd_open)
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0U));
#elif defined(__NR_pidfd_open)
    return static_cast<int>(::syscall(__NR_pidfd_open, pid, 0U));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

constexpr idtype_t kPidfdIdType = static_cast<idtype_t>(3);

bool is_pidfd_unavailable_error(int error_number) noexcept {
    return error_number == ENOSYS || error_number == EINVAL || error_number == EPERM ||
           error_number == EACCES;
}

}  // namespace

ChildHandle Reactor::Impl::watch_child(pid_t pid, Reactor::ChildCallback callback) {
    require_owner();
    if (pid <= 0) {
        throw std::invalid_argument("watch_child requires a positive pid");
    }
    if (!callback) {
        throw std::invalid_argument("watch_child requires a callback");
    }
    if (std::any_of(children_.begin(), children_.end(), [pid](const ChildWatch& child) {
            return child.pid == pid;
        })) {
        throw std::invalid_argument("child pid is already watched");
    }

    int pidfd = -1;
    ChildBackend backend = ChildBackend::sigchld;
    if (options_.pidfd_policy == PidfdPolicy::automatic) {
        pidfd = open_pidfd(pid);
        if (pidfd >= 0) {
            backend = ChildBackend::pidfd;
        } else if (errno != ESRCH && !is_pidfd_unavailable_error(errno)) {
            throw_system_error("pidfd_open");
        }
    }

    const std::uint64_t id = next_id();
    try {
        children_.push_back(ChildWatch{id, pid, pidfd, 0U, backend, std::move(callback)});
    } catch (...) {
        close_nointr(pidfd);
        throw;
    }
    try {
        if (pidfd >= 0) {
            const std::uint64_t source_id = add_source(
                pidfd, EPOLLIN, true, false, false, CallbackKind::child,
                [this, id](std::uint32_t) {
                    (void)try_reap_child(id);
                    return std::size_t{0U};
                });
            ChildWatch* child = find_child(id);
            if (child == nullptr) {
                throw std::logic_error("new child watch disappeared");
            }
            child->source_id = source_id;
        }
        (void)try_reap_child(id);
    } catch (...) {
        ChildWatch* child = find_child(id);
        if (child != nullptr) {
            const std::uint64_t source_id = child->source_id;
            const int child_pidfd = child->pidfd;
            children_.erase(std::remove_if(
                children_.begin(), children_.end(),
                [id](const ChildWatch& item) { return item.id == id; }), children_.end());
            if (source_id != 0U) {
                remove_source(source_id);
            } else {
                close_nointr(child_pidfd);
            }
        }
        throw;
    }
    return ChildHandle{Handle{id}, pid, backend};
}

bool Reactor::Impl::unwatch_child(ChildHandle child) {
    require_owner();
    ChildWatch* watched = find_child(child.handle.value());
    if (watched == nullptr || watched->pid != child.pid) {
        return false;
    }
    const std::uint64_t id = watched->id;
    const std::uint64_t source_id = watched->source_id;
    const int pidfd = watched->pidfd;
    children_.erase(std::remove_if(
        children_.begin(), children_.end(),
        [id](const ChildWatch& item) { return item.id == id; }), children_.end());
    if (source_id != 0U) {
        remove_source(source_id);
    } else {
        close_nointr(pidfd);
    }
    return true;
}

void Reactor::Impl::reap_sigchld_children() {
    std::vector<std::uint64_t> ids;
    ids.reserve(children_.size());
    for (const ChildWatch& child : children_) {
        if (child.backend == ChildBackend::sigchld) {
            ids.push_back(child.id);
        }
    }
    for (const std::uint64_t id : ids) {
        (void)try_reap_child(id);
    }
}

bool Reactor::Impl::try_reap_child(std::uint64_t id) {
    ChildWatch* child = find_child(id);
    if (child == nullptr) {
        return false;
    }

    siginfo_t information{};
    bool used_pidfd_waitid = false;
    if (child->pidfd >= 0 && !pidfd_waitid_unavailable_) {
        for (;;) {
            if (::waitid(
                    kPidfdIdType,
                    static_cast<id_t>(child->pidfd),
                    &information,
                    WEXITED | WNOHANG) == 0) {
                used_pidfd_waitid = true;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EINVAL || errno == ENOSYS) {
                pidfd_waitid_unavailable_ = true;
                break;
            }
            if (errno == ECHILD) {
                complete_lost_child(id);
                return true;
            }
            throw_system_error("waitid(P_PIDFD)");
        }
    }

    child = find_child(id);
    if (child == nullptr) {
        return true;
    }
    if (!used_pidfd_waitid) {
        for (;;) {
            if (::waitid(
                    P_PID,
                    static_cast<id_t>(child->pid),
                    &information,
                    WEXITED | WNOHANG) == 0) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                complete_lost_child(id);
                return true;
            }
            throw_system_error("waitid(P_PID)");
        }
    }
    if (information.si_pid == 0) {
        return false;
    }

    ChildExit result{};
    result.pid = child->pid;
    result.backend = child->backend;
    result.status = information.si_status;
    if (information.si_code == CLD_EXITED) {
        result.kind = ChildExitKind::exited;
    } else {
        result.kind = ChildExitKind::signaled;
        result.core_dumped = information.si_code == CLD_DUMPED;
    }
    complete_child(id, result);
    return true;
}

void Reactor::Impl::complete_lost_child(std::uint64_t id) {
    ChildWatch* child = find_child(id);
    if (child == nullptr) {
        return;
    }
    ChildExit result{};
    result.pid = child->pid;
    result.backend = child->backend;
    result.kind = ChildExitKind::lost;
    complete_child(id, result);
}

void Reactor::Impl::complete_child(std::uint64_t id, const ChildExit& result) {
    ChildWatch* child = find_child(id);
    if (child == nullptr) {
        return;
    }
    Reactor::ChildCallback callback = std::move(child->callback);
    const std::uint64_t source_id = child->source_id;
    const int pidfd = child->pidfd;
    children_.erase(std::remove_if(
        children_.begin(), children_.end(),
        [id](const ChildWatch& item) { return item.id == id; }), children_.end());
    if (source_id != 0U) {
        remove_source(source_id);
    } else {
        close_nointr(pidfd);
    }
    pending_children_.push_back(PendingChild{id, std::move(callback), result});
}

std::size_t Reactor::Impl::dispatch_pending_children() {
    std::size_t count = 0U;
    while (!pending_children_.empty()) {
        PendingChild pending = std::move(pending_children_.front());
        pending_children_.pop_front();
        try {
            pending.callback(pending.result);
        } catch (...) {
            record_callback_failure(
                CallbackKind::child, pending.id, std::current_exception());
        }
        ++count;
    }
    return count;
}

}  // namespace msys::native
