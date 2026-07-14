#include "msys/reactor.hpp"

#include <chrono>
#include <csignal>
#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <unistd.h>

namespace {

using namespace std::chrono_literals;
using msys::native::CallbackKind;
using msys::native::Reactor;

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_timerfd_one_shot_and_remove() {
    Reactor reactor;
    std::uint64_t expirations = 0U;
    const auto timer = reactor.add_timer(5ms, 0ns, [&](std::uint64_t count) {
        expirations += count;
    });
    expect(static_cast<bool>(timer), "timer handle is empty");
    expect(reactor.run_once(500ms) == 1U, "timer callback was not dispatched");
    expect(expirations == 1U, "one-shot timer did not expire exactly once");
    expect(reactor.remove(timer), "timer removal failed");
    expect(!reactor.remove(timer), "timer removal was not idempotently reported");
}

void test_borrowed_epoll_fd() {
    int pipe_fds[2] = {-1, -1};
    if (::pipe2(pipe_fds, O_NONBLOCK | O_CLOEXEC) < 0) {
        throw std::runtime_error("pipe2 failed");
    }
    try {
        Reactor reactor;
        bool called = false;
        const auto watch = reactor.watch_fd(
            pipe_fds[0], EPOLLIN,
            [&](std::uint32_t events) {
                expect((events & EPOLLIN) != 0U, "epoll callback omitted EPOLLIN");
                char value = '\0';
                expect(::read(pipe_fds[0], &value, 1U) == 1, "pipe read failed");
                expect(value == 'x', "pipe delivered the wrong byte");
                called = true;
            });
        const char value = 'x';
        expect(::write(pipe_fds[1], &value, 1U) == 1, "pipe write failed");
        expect(reactor.run_once(500ms) == 1U, "fd callback was not counted");
        expect(called, "fd callback was not called");
        expect(reactor.remove(watch), "fd watch removal failed");

        // Removing a borrowed watch must leave the descriptor usable.
        const char second = 'y';
        expect(::write(pipe_fds[1], &second, 1U) == 1, "borrowed fd was closed");
        char received = '\0';
        expect(::read(pipe_fds[0], &received, 1U) == 1, "borrowed fd read failed");
        expect(received == second, "borrowed fd data mismatch");
    } catch (...) {
        (void)::close(pipe_fds[0]);
        (void)::close(pipe_fds[1]);
        throw;
    }
    (void)::close(pipe_fds[0]);
    (void)::close(pipe_fds[1]);
}

void test_signalfd_delivery() {
    Reactor reactor;
    bool called = false;
    const auto watch = reactor.watch_signal(SIGUSR1, [&](const auto& event) {
        expect(event.signal_number == SIGUSR1, "wrong signal number");
        expect(event.sender_pid == ::getpid(), "wrong signal sender pid");
        called = true;
    });
    expect(::kill(::getpid(), SIGUSR1) == 0, "kill(SIGUSR1) failed");
    expect(reactor.run_once(500ms) == 1U, "signal callback was not counted");
    expect(called, "signal callback was not called");
    expect(reactor.remove(watch), "signal watch removal failed");
}

void test_cross_thread_stop() {
    Reactor reactor;
    std::thread stopper([&reactor] {
        std::this_thread::sleep_for(10ms);
        reactor.request_stop();
    });
    reactor.run();
    stopper.join();
    expect(reactor.stop_requested(), "request_stop state was lost");
}

void test_signal_mask_restoration() {
    sigset_t before{};
    int result = ::pthread_sigmask(SIG_SETMASK, nullptr, &before);
    expect(result == 0, "failed to read initial signal mask");
    const int initially_blocked = ::sigismember(&before, SIGUSR2);
    {
        Reactor reactor;
        const auto watch = reactor.watch_signal(SIGUSR2, [](const auto&) {});
        expect(static_cast<bool>(watch), "signal watch handle is empty");
        sigset_t during{};
        result = ::pthread_sigmask(SIG_SETMASK, nullptr, &during);
        expect(result == 0, "failed to read reactor signal mask");
        expect(::sigismember(&during, SIGUSR2) == 1, "watched signal was not blocked");
    }
    sigset_t after{};
    result = ::pthread_sigmask(SIG_SETMASK, nullptr, &after);
    expect(result == 0, "failed to read restored signal mask");
    expect(
        ::sigismember(&after, SIGUSR2) == initially_blocked,
        "reactor did not restore the owner signal mask");
}

void test_epoll_callback_exception_isolation() {
    int first_pipe[2] = {-1, -1};
    int second_pipe[2] = {-1, -1};
    expect(::pipe2(first_pipe, O_NONBLOCK | O_CLOEXEC) == 0, "first pipe2 failed");
    if (::pipe2(second_pipe, O_NONBLOCK | O_CLOEXEC) < 0) {
        (void)::close(first_pipe[0]);
        (void)::close(first_pipe[1]);
        throw std::runtime_error("second pipe2 failed");
    }
    try {
        Reactor reactor;
        bool later_callback_ran = false;
        const auto throwing_watch = reactor.watch_fd(first_pipe[0], EPOLLIN, [&](std::uint32_t) {
            char byte = '\0';
            expect(::read(first_pipe[0], &byte, 1U) == 1, "throwing fd read failed");
            throw std::runtime_error("intentional fd callback failure");
        });
        (void)reactor.watch_fd(second_pipe[0], EPOLLIN, [&](std::uint32_t) {
            char byte = '\0';
            expect(::read(second_pipe[0], &byte, 1U) == 1, "later fd read failed");
            later_callback_ran = true;
        });
        const char byte = 'x';
        expect(::write(first_pipe[1], &byte, 1U) == 1, "first ready write failed");
        expect(::write(second_pipe[1], &byte, 1U) == 1, "second ready write failed");
        expect(reactor.run_once(500ms) == 2U, "epoll batch did not dispatch both callbacks");
        expect(later_callback_ran, "throwing fd callback swallowed a later epoll event");

        auto failures = reactor.take_callback_failures();
        expect(failures.size() == 1U, "fd callback failure was not collected exactly once");
        expect(failures[0].kind == CallbackKind::fd, "fd callback failure kind mismatch");
        expect(failures[0].handle == throwing_watch, "fd callback failure handle mismatch");
        bool expected_exception = false;
        try {
            std::rethrow_exception(failures[0].exception);
        } catch (const std::runtime_error& error) {
            expected_exception = std::string(error.what()) == "intentional fd callback failure";
        }
        expect(expected_exception, "fd callback exception payload mismatch");
        expect(reactor.take_callback_failures().empty(), "failure queue did not drain");
    } catch (...) {
        (void)::close(first_pipe[0]);
        (void)::close(first_pipe[1]);
        (void)::close(second_pipe[0]);
        (void)::close(second_pipe[1]);
        throw;
    }
    (void)::close(first_pipe[0]);
    (void)::close(first_pipe[1]);
    (void)::close(second_pipe[0]);
    (void)::close(second_pipe[1]);
}

void test_signalfd_callback_exception_isolation() {
    Reactor reactor;
    bool later_callback_ran = false;
    const auto throwing_watch = reactor.watch_signal(SIGUSR1, [](const auto&) {
        throw std::runtime_error("intentional signal callback failure");
    });
    (void)reactor.watch_signal(SIGUSR2, [&](const auto&) { later_callback_ran = true; });
    expect(::kill(::getpid(), SIGUSR1) == 0, "kill(SIGUSR1) failed");
    expect(::kill(::getpid(), SIGUSR2) == 0, "kill(SIGUSR2) failed");
    expect(reactor.run_once(500ms) == 2U, "signalfd batch did not dispatch both callbacks");
    expect(later_callback_ran, "throwing signal callback swallowed a later signalfd record");
    const auto failures = reactor.take_callback_failures();
    expect(failures.size() == 1U, "signal callback failure was not collected exactly once");
    expect(failures[0].kind == CallbackKind::signal, "signal failure kind mismatch");
    expect(failures[0].handle == throwing_watch, "signal failure handle mismatch");
}

void test_invalid_arguments() {
    Reactor reactor;
    bool timer_rejected = false;
    try {
        (void)reactor.add_timer(0ns, 0ns, [](std::uint64_t) {});
    } catch (const std::invalid_argument&) {
        timer_rejected = true;
    }
    expect(timer_rejected, "zero initial timer was accepted");

    bool signal_rejected = false;
    try {
        (void)reactor.watch_signal(SIGKILL, [](const auto&) {});
    } catch (const std::invalid_argument&) {
        signal_rejected = true;
    }
    expect(signal_rejected, "SIGKILL watch was accepted");
}

}  // namespace

int main() {
    const std::vector<std::pair<std::string, std::function<void()>>> tests{
        {"timerfd one-shot and remove", test_timerfd_one_shot_and_remove},
        {"borrowed epoll fd", test_borrowed_epoll_fd},
        {"signalfd delivery", test_signalfd_delivery},
        {"cross-thread eventfd stop", test_cross_thread_stop},
        {"signal mask restoration", test_signal_mask_restoration},
        {"epoll callback exception isolation", test_epoll_callback_exception_isolation},
        {"signalfd callback exception isolation", test_signalfd_callback_exception_isolation},
        {"invalid arguments", test_invalid_arguments},
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
    std::cout << passed << " unit tests passed\n";
    return 0;
}
