#include "msys/reactor.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <limits.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using msys::native::CallbackKind;
using msys::native::ChildBackend;
using msys::native::ChildExit;
using msys::native::ChildExitKind;
using msys::native::PidfdPolicy;
using msys::native::Reactor;
using msys::native::ReactorOptions;
using msys::native::SpawnOptions;

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string executable_path() {
    std::vector<char> buffer(static_cast<std::size_t>(PATH_MAX) + 1U, '\0');
    const ssize_t length = ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1U);
    if (length < 0) {
        throw std::runtime_error("readlink(/proc/self/exe) failed");
    }
    return std::string(buffer.data(), static_cast<std::size_t>(length));
}

void run_until(Reactor& reactor, const std::function<bool()>& complete) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!complete() && std::chrono::steady_clock::now() < deadline) {
        (void)reactor.run_once(50ms);
    }
    expect(complete(), "reactor integration test timed out");
}

bool kernel_allows_pidfd_open() {
#if defined(SYS_pidfd_open)
    const int fd = static_cast<int>(::syscall(SYS_pidfd_open, ::getpid(), 0U));
#elif defined(__NR_pidfd_open)
    const int fd = static_cast<int>(::syscall(__NR_pidfd_open, ::getpid(), 0U));
#else
    return false;
#endif
    if (fd < 0) {
        return false;
    }
    (void)::close(fd);
    return true;
}

void test_spawn_and_pidfd_preference() {
    Reactor reactor;
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-exit", "7"};
    options.search_path = false;
    const auto child = reactor.spawn_process(options, [&](const ChildExit& exit) {
        result = exit;
    });
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->pid == child.pid, "pidfd child pid mismatch");
    expect(result->kind == ChildExitKind::exited, "pidfd child was not exited");
    expect(result->status == 7, "pidfd child exit status mismatch");
    expect(result->backend == child.watch.backend, "reported child backend mismatch");
    if (kernel_allows_pidfd_open()) {
        expect(child.watch.backend == ChildBackend::pidfd, "available pidfd was not preferred");
    } else {
        expect(
            child.watch.backend == ChildBackend::sigchld,
            "pidfd-restricted kernel did not use SIGCHLD fallback");
    }
}

void test_forced_old_kernel_fallback() {
    Reactor reactor(ReactorOptions{PidfdPolicy::disabled});
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-exit", "9"};
    options.search_path = false;
    const auto child = reactor.spawn_process(options, [&](const ChildExit& exit) {
        result = exit;
    });
    expect(child.watch.backend == ChildBackend::sigchld, "forced fallback used pidfd");
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->kind == ChildExitKind::exited, "fallback child was not exited");
    expect(result->status == 9, "fallback child exit status mismatch");
    expect(result->backend == ChildBackend::sigchld, "fallback result backend mismatch");
}

void test_signal_termination_and_process_group() {
    Reactor reactor;
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-wait"};
    options.search_path = false;
    options.new_process_group = true;
    const auto child = reactor.spawn_process(options, [&](const ChildExit& exit) {
        result = exit;
    });
    expect(::getpgid(child.pid) == child.pid, "spawned child lacks an isolated process group");
    expect(::kill(child.pid, SIGTERM) == 0, "SIGTERM to child failed");
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->kind == ChildExitKind::signaled, "terminated child kind mismatch");
    expect(result->status == SIGTERM, "terminated child signal mismatch");
}

void test_already_exited_registration_race() {
    Reactor reactor(ReactorOptions{PidfdPolicy::disabled});
    const pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed in integration test");
    }
    if (pid == 0) {
        ::_exit(23);
    }

    std::this_thread::sleep_for(20ms);
    std::optional<ChildExit> result;
    (void)reactor.watch_child(pid, [&](const ChildExit& exit) { result = exit; });
    expect(!result.has_value(), "child callback ran synchronously during registration");
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->pid == pid, "already-exited child pid mismatch");
    expect(result->kind == ChildExitKind::exited, "already-exited child kind mismatch");
    expect(result->status == 23, "already-exited child status mismatch");
}

void test_coalesced_sigchld_reaps_all_known_children() {
    Reactor reactor(ReactorOptions{PidfdPolicy::disabled});
    std::vector<ChildExit> results;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-wait"};
    options.search_path = false;
    const auto first = reactor.spawn_process(options, [&](const ChildExit& exit) {
        results.push_back(exit);
    });
    const auto second = reactor.spawn_process(options, [&](const ChildExit& exit) {
        results.push_back(exit);
    });
    expect(::kill(first.pid, SIGTERM) == 0, "failed to terminate first fallback child");
    expect(::kill(second.pid, SIGTERM) == 0, "failed to terminate second fallback child");
    run_until(reactor, [&] { return results.size() == 2U; });
    for (const ChildExit& result : results) {
        expect(result.backend == ChildBackend::sigchld, "coalesced exit did not use fallback");
        expect(result.kind == ChildExitKind::signaled, "coalesced child kind mismatch");
        expect(result.status == SIGTERM, "coalesced child signal mismatch");
    }
}

void test_child_callback_exception_isolation() {
    Reactor reactor(ReactorOptions{PidfdPolicy::disabled});
    std::size_t callback_count = 0U;
    bool nonthrowing_callback_ran = false;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-wait"};
    const auto throwing_child = reactor.spawn_process(options, [&](const ChildExit&) {
        ++callback_count;
        throw std::runtime_error("intentional child callback failure");
    });
    const auto other_child = reactor.spawn_process(options, [&](const ChildExit&) {
        ++callback_count;
        nonthrowing_callback_ran = true;
    });
    expect(::kill(throwing_child.pid, SIGTERM) == 0, "failed to terminate throwing child");
    expect(::kill(other_child.pid, SIGTERM) == 0, "failed to terminate other child");
    run_until(reactor, [&] { return callback_count == 2U; });
    expect(nonthrowing_callback_ran, "throwing child callback swallowed another completion");
    const auto failures = reactor.take_callback_failures();
    expect(failures.size() == 1U, "child callback failure was not collected exactly once");
    expect(failures[0].kind == CallbackKind::child, "child callback failure kind mismatch");
    expect(
        failures[0].handle == throwing_child.watch.handle,
        "child callback failure handle mismatch");
}

void test_competing_reaper_reports_lost() {
    Reactor reactor;
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-wait"};
    options.search_path = false;
    const auto child = reactor.spawn_process(options, [&](const ChildExit& exit) {
        result = exit;
    });
    expect(::kill(child.pid, SIGTERM) == 0, "failed to terminate lost-child fixture");
    int status = 0;
    expect(::waitpid(child.pid, &status, 0) == child.pid, "competing waitpid failed");
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->pid == child.pid, "lost-child pid mismatch");
    expect(result->kind == ChildExitKind::lost, "competing reaper was not reported");
}

void test_register_after_reap_reports_lost_once() {
    Reactor reactor;
    const pid_t pid = ::fork();
    if (pid < 0) {
        throw std::runtime_error("fork failed for register-after-reap test");
    }
    if (pid == 0) {
        ::_exit(0);
    }
    int status = 0;
    expect(::waitpid(pid, &status, 0) == pid, "fixture waitpid failed");

    std::size_t callback_count = 0U;
    std::optional<ChildExit> result;
    const auto handle = reactor.watch_child(pid, [&](const ChildExit& exit) {
        ++callback_count;
        result = exit;
    });
    expect(static_cast<bool>(handle.handle), "ESRCH watch did not return a handle");
    expect(callback_count == 0U, "ESRCH callback ran synchronously");
    expect(reactor.run_once(0ms) == 1U, "ESRCH lost callback was not dispatched");
    expect(result.has_value(), "ESRCH result is missing");
    expect(result->pid == pid, "ESRCH result pid mismatch");
    expect(result->kind == ChildExitKind::lost, "ESRCH did not report lost");
    (void)reactor.run_once(0ms);
    (void)reactor.run_once(0ms);
    expect(callback_count == 1U, "ESRCH callback was dispatched more than once");
}

void test_spawn_closes_non_whitelisted_fds() {
    int leaked[2] = {-1, -1};
    int preserved[2] = {-1, -1};
    expect(::pipe(leaked) == 0, "non-CLOEXEC leak pipe failed");
    if (::pipe2(preserved, O_CLOEXEC) < 0) {
        (void)::close(leaked[0]);
        (void)::close(leaked[1]);
        throw std::runtime_error("CLOEXEC preserve pipe failed");
    }
    try {
        Reactor reactor;
        std::optional<ChildExit> result;
        SpawnOptions options{};
        options.argv = {
            executable_path(),
            "--child-check-fds",
            std::to_string(leaked[0]),
            std::to_string(leaked[1]),
            std::to_string(preserved[0]),
        };
        options.inherited_fds = {0, 1, 2, preserved[0]};
        const auto child = reactor.spawn_process(options, [&](const ChildExit& exit) {
            result = exit;
        });
        (void)child;
        run_until(reactor, [&] { return result.has_value(); });
        expect(result->kind == ChildExitKind::exited, "fd-audit child did not exit normally");
        expect(result->status == 0, "child observed a leaked or missing descriptor");
    } catch (...) {
        (void)::close(leaked[0]);
        (void)::close(leaked[1]);
        (void)::close(preserved[0]);
        (void)::close(preserved[1]);
        throw;
    }
    (void)::close(leaked[0]);
    (void)::close(leaked[1]);
    (void)::close(preserved[0]);
    (void)::close(preserved[1]);
}

void test_search_path_uses_supplied_environment() {
    std::vector<char> directory_template{
        '/', 't', 'm', 'p', '/', 'm', 's', 'y', 's', '-', 'p', 'a', 't', 'h', '-',
        'X', 'X', 'X', 'X', 'X', 'X', '\0'};
    char* directory = ::mkdtemp(directory_template.data());
    expect(directory != nullptr, "mkdtemp for PATH test failed");
    const std::string link_path = std::string(directory) + "/msys-reactor-path-child";
    if (::symlink(executable_path().c_str(), link_path.c_str()) < 0) {
        (void)::rmdir(directory);
        throw std::runtime_error("symlink for PATH test failed");
    }
    try {
        Reactor reactor;
        std::optional<ChildExit> result;
        SpawnOptions options{};
        options.argv = {"msys-reactor-path-child", "--child-exit", "0"};
        options.environment = std::vector<std::string>{std::string("PATH=") + directory};
        options.search_path = true;
        (void)reactor.spawn_process(options, [&](const ChildExit& exit) { result = exit; });
        run_until(reactor, [&] { return result.has_value(); });
        expect(result->kind == ChildExitKind::exited, "PATH-resolved child did not exit");
        expect(result->status == 0, "PATH-resolved child returned an error");
    } catch (...) {
        (void)::unlink(link_path.c_str());
        (void)::rmdir(directory);
        throw;
    }
    (void)::unlink(link_path.c_str());
    (void)::rmdir(directory);
}

void test_wrong_thread_destruction_is_defended() {
    Reactor reactor;
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-wrong-thread-destroy"};
    (void)reactor.spawn_process(options, [&](const ChildExit& exit) { result = exit; });
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->kind == ChildExitKind::exited, "destructor defense child was signaled");
    expect(result->status == 42, "wrong-thread destruction did not invoke terminate defense");
}

void test_exact_environment() {
    Reactor reactor;
    std::optional<ChildExit> result;
    SpawnOptions options{};
    options.argv = {executable_path(), "--child-check-env"};
    options.environment = std::vector<std::string>{"MSYS_NATIVE_REACTOR_TEST=isolated"};
    options.search_path = false;
    (void)reactor.spawn_process(options, [&](const ChildExit& exit) { result = exit; });
    run_until(reactor, [&] { return result.has_value(); });
    expect(result->kind == ChildExitKind::exited, "environment child did not exit normally");
    expect(result->status == 0, "exact child environment was not installed");
}

int run_child_mode(int argc, char** argv) {
    const std::string mode = argv[1];
    if (mode == "--child-exit" && argc == 3) {
        return std::stoi(argv[2]);
    }
    if (mode == "--child-wait" && argc == 2) {
        for (;;) {
            (void)::pause();
        }
    }
    if (mode == "--child-check-env" && argc == 2) {
        const char* value = ::getenv("MSYS_NATIVE_REACTOR_TEST");
        const char* path = ::getenv("PATH");
        return value != nullptr && std::string(value) == "isolated" && path == nullptr ? 0 : 31;
    }
    if (mode == "--child-check-fds" && argc == 5) {
        const int leaked_read = std::stoi(argv[2]);
        const int leaked_write = std::stoi(argv[3]);
        const int preserved = std::stoi(argv[4]);
        if (::fcntl(leaked_read, F_GETFD) >= 0 || errno != EBADF) {
            return 41;
        }
        if (::fcntl(leaked_write, F_GETFD) >= 0 || errno != EBADF) {
            return 42;
        }
        if (::fcntl(preserved, F_GETFD) < 0) {
            return 43;
        }
        DIR* directory = ::opendir("/proc/self/fd");
        if (directory == nullptr) {
            return 44;
        }
        const int audit_fd = ::dirfd(directory);
        int audit_result = 0;
        while (dirent* entry = ::readdir(directory)) {
            char* end = nullptr;
            const long descriptor = std::strtol(entry->d_name, &end, 10);
            if (end == entry->d_name || *end != '\0') {
                continue;
            }
            if (descriptor != 0L && descriptor != 1L && descriptor != 2L &&
                descriptor != static_cast<long>(preserved) &&
                descriptor != static_cast<long>(audit_fd)) {
                audit_result = 45;
                break;
            }
        }
        (void)::closedir(directory);
        return audit_result;
    }
    if (mode == "--child-wrong-thread-destroy" && argc == 2) {
        std::set_terminate([] { ::_exit(42); });
        Reactor* reactor = new Reactor();
        std::thread wrong_thread([reactor] { delete reactor; });
        wrong_thread.join();
        return 46;
    }
    return 125;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 1) {
        return run_child_mode(argc, argv);
    }

    const std::vector<std::pair<std::string, std::function<void()>>> tests{
        {"spawn and pidfd preference", test_spawn_and_pidfd_preference},
        {"forced old-kernel fallback", test_forced_old_kernel_fallback},
        {"signal termination and process group", test_signal_termination_and_process_group},
        {"already-exited registration race", test_already_exited_registration_race},
        {"coalesced SIGCHLD", test_coalesced_sigchld_reaps_all_known_children},
        {"child callback exception isolation", test_child_callback_exception_isolation},
        {"competing reaper", test_competing_reaper_reports_lost},
        {"register after reap", test_register_after_reap_reports_lost_once},
        {"spawn fd allowlist", test_spawn_closes_non_whitelisted_fds},
        {"controlled PATH resolution", test_search_path_uses_supplied_environment},
        {"owner-thread destructor defense", test_wrong_thread_destruction_is_defended},
        {"exact child environment", test_exact_environment},
    };

    std::size_t passed = 0U;
    for (const auto& [name, test] : tests) {
        try {
            test();
            ++passed;
            std::cout << "[pass] " << name << '\n';
        } catch (const std::exception& error) {
            std::cerr << "[fail] " << name << ": " << error.what() << '\n';
            return 1;
        }
    }
    std::cout << passed << " integration tests passed\n";
    return 0;
}
