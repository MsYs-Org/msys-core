#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <sys/types.h>

namespace msys::native {

enum class PidfdPolicy {
    automatic,
    disabled,
};

struct ReactorOptions {
    PidfdPolicy pidfd_policy{PidfdPolicy::automatic};
};

class Handle {
public:
    constexpr Handle() noexcept = default;
    explicit constexpr Handle(std::uint64_t value) noexcept : value_(value) {}

    [[nodiscard]] constexpr std::uint64_t value() const noexcept { return value_; }
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return value_ != 0U; }

    friend constexpr bool operator==(Handle, Handle) noexcept = default;

private:
    std::uint64_t value_{0U};
};

enum class ChildBackend {
    pidfd,
    sigchld,
};

enum class ChildExitKind {
    exited,
    signaled,
    lost,
};

struct ChildExit {
    pid_t pid{-1};
    ChildBackend backend{ChildBackend::sigchld};
    ChildExitKind kind{ChildExitKind::lost};
    int status{0};
    bool core_dumped{false};
};

struct ChildHandle {
    Handle handle{};
    pid_t pid{-1};
    ChildBackend backend{ChildBackend::sigchld};
};

struct SignalEvent {
    int signal_number{0};
    int code{0};
    pid_t sender_pid{0};
    uid_t sender_uid{0};
    int status{0};
    std::uint32_t overrun{0U};
};

enum class CallbackKind {
    fd,
    timer,
    signal,
    child,
};

struct CallbackFailure {
    CallbackKind kind{CallbackKind::fd};
    Handle handle{};
    std::exception_ptr exception;
};

struct SpawnOptions {
    // argv must be non-empty. No shell is involved.
    std::vector<std::string> argv;

    // nullopt inherits the supervisor environment. A value supplies the exact
    // environment, including an intentionally empty environment.
    std::optional<std::vector<std::string>> environment;

    // The safe default requires an absolute argv[0]. When true, a bare name is
    // resolved only through absolute entries in PATH from `environment` (or
    // the inherited environment when environment is nullopt).
    bool search_path{false};

    // Put the component in a new process group whose id is its pid.
    bool new_process_group{true};

    // Exact numeric descriptors to preserve in the child. Every other fd seen
    // in /proc/self/fd is explicitly closed by posix_spawn file actions. An
    // identity dup action also clears FD_CLOEXEC on an open whitelisted fd.
    std::vector<int> inherited_fds{0, 1, 2};
};

struct SpawnedChild {
    pid_t pid{-1};
    ChildHandle watch{};
};

class Reactor final {
public:
    using FdCallback = std::function<void(std::uint32_t)>;
    using TimerCallback = std::function<void(std::uint64_t)>;
    using SignalCallback = std::function<void(const SignalEvent&)>;
    using ChildCallback = std::function<void(const ChildExit&)>;

    explicit Reactor(ReactorOptions options = {});
    ~Reactor();

    Reactor(const Reactor&) = delete;
    Reactor& operator=(const Reactor&) = delete;
    Reactor(Reactor&&) = delete;
    Reactor& operator=(Reactor&&) = delete;

    // The fd remains owned by the caller. Only one watch per numeric fd is
    // permitted at a time.
    [[nodiscard]] Handle watch_fd(int fd, std::uint32_t events, FdCallback callback);

    // initial must be positive. interval == 0 creates a one-shot timer.
    [[nodiscard]] Handle add_timer(
        std::chrono::nanoseconds initial,
        std::chrono::nanoseconds interval,
        TimerCallback callback);

    // Signals are blocked and routed through signalfd for the lifetime of this
    // reactor. SIGKILL and SIGSTOP cannot be watched.
    [[nodiscard]] Handle watch_signal(int signal_number, SignalCallback callback);

    // Removes an fd, timer, or user signal watch. Borrowed fds are not closed.
    // A removed signal stays blocked until Reactor destruction.
    [[nodiscard]] bool remove(Handle handle);

    // Only direct children may be supervised. The callback is invoked exactly
    // once by the event loop, including when a competing reaper caused a
    // ChildExitKind::lost result.
    [[nodiscard]] ChildHandle watch_child(pid_t pid, ChildCallback callback);
    [[nodiscard]] bool unwatch_child(ChildHandle child);

    // Starts without invoking a shell. The child's signal mask is restored to
    // the mask that existed before Reactor construction.
    [[nodiscard]] SpawnedChild spawn_process(SpawnOptions options, ChildCallback callback);

    // Returns the number of user callbacks dispatched. A timeout of -1ms waits
    // indefinitely; values below -1ms are rejected.
    [[nodiscard]] std::size_t run_once(
        std::chrono::milliseconds timeout = std::chrono::milliseconds{-1});
    void run();

    // User callback exceptions never abort dispatch of the current epoll or
    // signalfd batch. They are collected here in dispatch order. Internal
    // reactor failures still throw directly from run_once()/run().
    [[nodiscard]] std::vector<CallbackFailure> take_callback_failures();

    // The only operation permitted from another thread. Destruction must not
    // race with request_stop().
    void request_stop() noexcept;
    [[nodiscard]] bool stop_requested() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace msys::native
