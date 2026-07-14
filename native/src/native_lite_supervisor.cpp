#include "msys/native_lite.hpp"
#include "msys/native_catalog.hpp"
#include "msys/mipc_broker.hpp"
#include "msys/native_router.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char** environ;

namespace msys::native::lite {
namespace {

using namespace std::chrono_literals;

constexpr std::string_view ready_record = "READY\n";
constexpr int terminal_component_exit = 70;
constexpr int internal_supervisor_exit = 71;

enum class RuntimeState {
    waiting,
    starting,
    ready,
    backoff,
    stopping,
    stopped,
    failed,
};

struct ComponentRuntime {
    RuntimeState state{RuntimeState::waiting};
    pid_t pid{-1};
    std::uint64_t generation{0U};
    std::uint64_t start_sequence{0U};
    std::uint32_t restart_count{0U};
    int readiness_fd{-1};
    Handle readiness_watch{};
    Handle readiness_timer{};
    Handle restart_timer{};
    Handle stop_timer{};
    Handle readiness_poll{};
    Handle idle_timer{};
    std::string readiness_buffer;
    std::uint32_t inflight_calls{0U};
    bool readiness_failed{false};
    bool manual_stop{false};
};

std::string kind_name(ComponentKind kind) {
    switch (kind) {
    case ComponentKind::display:
        return "display";
    case ComponentKind::window:
        return "window";
    case ComponentKind::shell:
        return "shell";
    case ComponentKind::other:
        return "other";
    }
    return "other";
}

std::string runtime_state_name(RuntimeState state) {
    switch (state) {
    case RuntimeState::waiting:
        return "waiting";
    case RuntimeState::starting:
        return "starting";
    case RuntimeState::ready:
        return "ready";
    case RuntimeState::backoff:
        return "backoff";
    case RuntimeState::stopping:
        return "stopping";
    case RuntimeState::stopped:
        return "stopped";
    case RuntimeState::failed:
        return "failed";
    }
    return "failed";
}

std::string restart_name(RestartPolicy policy) {
    switch (policy) {
    case RestartPolicy::never:
        return "never";
    case RestartPolicy::on_failure:
        return "on-failure";
    case RestartPolicy::always:
        return "always";
    }
    return "never";
}

std::string lifecycle_name(Lifecycle lifecycle) {
    switch (lifecycle) {
    case Lifecycle::background:
        return "background";
    case Lifecycle::on_demand:
        return "on-demand";
    case Lifecycle::manual:
        return "manual";
    }
    return "manual";
}

std::string provide_kind_name(ProvideKind kind) {
    switch (kind) {
    case ProvideKind::role:
        return "role";
    case ProvideKind::interface:
        return "interface";
    case ProvideKind::capability:
        return "capability";
    }
    return "capability";
}

std::string environment_key(std::string_view entry) {
    const std::size_t separator = entry.find('=');
    return std::string(entry.substr(0U, separator));
}

std::vector<std::string> inherited_environment() {
    std::vector<std::string> result;
    if (environ == nullptr) {
        return result;
    }
    for (char** item = environ; *item != nullptr; ++item) {
        result.emplace_back(*item);
    }
    return result;
}

void set_environment(
    std::vector<std::string>& environment,
    const std::string& key,
    const std::string& value) {
    environment.erase(
        std::remove_if(
            environment.begin(),
            environment.end(),
            [&key](const std::string& entry) { return environment_key(entry) == key; }),
        environment.end());
    environment.push_back(key + "=" + value);
}

void unset_environment(std::vector<std::string>& environment, const std::string& key) {
    environment.erase(
        std::remove_if(
            environment.begin(),
            environment.end(),
            [&key](const std::string& entry) { return environment_key(entry) == key; }),
        environment.end());
}

void close_fd(int& descriptor) noexcept {
    if (descriptor >= 0) {
        (void)::close(descriptor);
        descriptor = -1;
    }
}

bool child_failed(const ChildExit& result) {
    return result.kind != ChildExitKind::exited || result.status != 0;
}

}  // namespace

class Supervisor::Impl final {
public:
    Impl(RuntimePlan plan, SupervisorOptions options)
        : plan_(std::move(plan)),
          options_(std::move(options)),
          runtime_(plan_.components.size()),
          catalog_(plan_) {
        const bool needs_mipc = std::any_of(
            plan_.components.begin(),
            plan_.components.end(),
            [](const ComponentPlan& component) {
                return component.readiness == ReadinessMode::mipc;
            });
        if (needs_mipc && !options_.runtime_dir.has_value()) {
            throw std::invalid_argument(
                "native-lite plan uses mipc-ready but --runtime-dir is missing");
        }
        for (std::size_t index = 0U; index < runtime_.size(); ++index) {
            runtime_[index].state = should_eager_start(index)
                ? RuntimeState::waiting : RuntimeState::stopped;
        }
        if (options_.runtime_dir.has_value()) {
            msys::native::mipc::BrokerHooks hooks{};
            hooks.list_components = [this] { return broker_component_statuses(); };
            hooks.start_component = [this](std::string_view component) {
                return broker_start_component(component);
            };
            hooks.stop_component = [this](std::string_view component) {
                return broker_stop_component(component);
            };
            hooks.component_ready = [this](std::string_view component, std::uint64_t generation) {
                broker_component_ready(component, generation);
            };
            hooks.component_disconnected =
                [this](std::string_view component, std::uint64_t generation) {
                    broker_component_disconnected(component, generation);
                };
            hooks.routed_message = [this](const msys::native::mipc::RoutedMessage& routed) {
                if (router_) {
                    router_->on_message(routed);
                }
            };
            hooks.session_closed = [this](
                                       std::uint64_t session_id,
                                       const msys::native::mipc::PeerIdentity& peer) {
                if (router_) {
                    router_->session_closed(session_id, peer);
                }
            };
            hooks.authorize = [this](const msys::native::mipc::AccessRequest& request) {
                return router_ && router_->authorize_call(request);
            };
            msys::native::mipc::BrokerOptions broker_options{*options_.runtime_dir};
            broker_ = std::make_unique<msys::native::mipc::Broker>(
                reactor_, std::move(broker_options), std::move(hooks));
            RouterCallbacks callbacks{};
            callbacks.activate_component = [this](std::size_t index) {
                return router_activate_component(index);
            };
            callbacks.stop_component = [this](std::size_t index) {
                return router_stop_component(index);
            };
            callbacks.component_state = [this](std::size_t index) {
                return runtime_state_name(runtime_[index].state);
            };
            callbacks.component_generation = [this](std::size_t index) {
                return runtime_[index].generation;
            };
            callbacks.component_ready = [this](std::size_t index) {
                return runtime_[index].state == RuntimeState::ready;
            };
            callbacks.component_for_pid = [this](pid_t pid) {
                return component_for_pid(pid);
            };
            callbacks.operator_peer = [](const msys::native::mipc::PeerIdentity& peer) {
                return peer.kind == msys::native::mipc::SessionKind::public_control
                    && peer.uid == ::geteuid();
            };
            callbacks.provider_busy_delta = [this](std::size_t index, int delta) {
                provider_busy_delta(index, delta);
            };
            callbacks.component_activity = [this](std::size_t index) {
                component_activity(index);
            };
            callbacks.foreground_components = [this] { return foreground_stack_; };
            router_ = std::make_unique<NativeRouter>(
                reactor_, plan_, catalog_, *broker_, std::move(callbacks));
        }
    }

    int run() {
        try {
            (void)reactor_.watch_signal(SIGTERM, [this](const SignalEvent&) {
                begin_shutdown(0, "SIGTERM");
            });
            (void)reactor_.watch_signal(SIGINT, [this](const SignalEvent&) {
                begin_shutdown(0, "SIGINT");
            });
            if (options_.report_rss) {
                std::cerr << "msysd-native-lite: supervisor_rss_kib="
                          << current_rss_kib() << '\n';
            }
            start_eligible();
            while (!done_) {
                (void)reactor_.run_once(std::chrono::milliseconds{-1});
                const auto failures = reactor_.take_callback_failures();
                if (!failures.empty()) {
                    try {
                        std::rethrow_exception(failures.front().exception);
                    } catch (const std::exception& error) {
                        std::cerr << "msysd-native-lite: callback failure: "
                                  << error.what() << '\n';
                    } catch (...) {
                        std::cerr << "msysd-native-lite: callback failure: unknown\n";
                    }
                    if (shutting_down_) {
                        emergency_kill_all();
                        exit_code_ = internal_supervisor_exit;
                        done_ = true;
                    } else {
                        begin_shutdown(internal_supervisor_exit, "callback-failure");
                    }
                }
            }
            return exit_code_;
        } catch (const std::exception& error) {
            std::cerr << "msysd-native-lite: fatal supervisor failure: "
                      << error.what() << '\n';
        } catch (...) {
            std::cerr << "msysd-native-lite: fatal supervisor failure: unknown\n";
        }
        emergency_kill_all();
        return internal_supervisor_exit;
    }

private:
    bool should_eager_start(std::size_t index) const {
        const auto& component = plan_.components[index];
        if (std::find(plan_.startup.begin(), plan_.startup.end(), component.id)
            != plan_.startup.end()) {
            return true;
        }
        if (component.lifecycle != Lifecycle::background) {
            return false;
        }
        bool has_exclusive_role = false;
        for (const auto& provided : component.provides) {
            if (provided.kind != ProvideKind::role || !provided.exclusive) {
                continue;
            }
            has_exclusive_role = true;
            const auto preferred = catalog_.preferred_role_provider(provided.name);
            if (preferred.has_value() && *preferred == index) {
                return true;
            }
        }
        return !has_exclusive_role;
    }

    std::optional<std::size_t> component_index(std::string_view component) const {
        for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
            if (plan_.components[index].id == component) {
                return index;
            }
        }
        return std::nullopt;
    }

    std::optional<std::size_t> component_for_pid(pid_t pid) const {
        if (pid <= 0) {
            return std::nullopt;
        }
        for (std::size_t index = 0U; index < runtime_.size(); ++index) {
            if (runtime_[index].pid == pid) {
                return index;
            }
        }
        return std::nullopt;
    }

    bool router_activate_component(std::size_t index) {
        if (index >= runtime_.size() || shutting_down_) {
            return false;
        }
        auto& state = runtime_[index];
        if (state.state == RuntimeState::ready
            || state.state == RuntimeState::starting
            || state.state == RuntimeState::waiting
            || state.state == RuntimeState::backoff) {
            return true;
        }
        if (state.state == RuntimeState::stopping) {
            return false;
        }
        state.manual_stop = false;
        state.readiness_failed = false;
        state.restart_count = 0U;
        state.state = RuntimeState::waiting;
        start_eligible();
        return state.state != RuntimeState::failed;
    }

    bool router_stop_component(std::size_t index) {
        if (index >= plan_.components.size()) {
            return false;
        }
        return broker_stop_component(plan_.components[index].id).ok;
    }

    void provider_busy_delta(std::size_t index, int delta) {
        if (index >= runtime_.size()) {
            return;
        }
        auto& state = runtime_[index];
        if (delta > 0) {
            if (state.inflight_calls != std::numeric_limits<std::uint32_t>::max()) {
                ++state.inflight_calls;
            }
            remove_handle(state.idle_timer);
        } else if (delta < 0 && state.inflight_calls > 0U) {
            --state.inflight_calls;
            arm_idle_timeout(index);
        }
    }

    void component_activity(std::size_t index) {
        if (index < runtime_.size()) {
            arm_idle_timeout(index);
        }
    }

    void arm_idle_timeout(std::size_t index) {
        auto& state = runtime_[index];
        remove_handle(state.idle_timer);
        const auto& component = plan_.components[index];
        if (component.lifecycle != Lifecycle::on_demand
            || component.idle_timeout_ms == 0U
            || state.state != RuntimeState::ready
            || state.inflight_calls != 0U) {
            return;
        }
        try {
            const std::uint64_t generation = state.generation;
            state.idle_timer = reactor_.add_timer(
                std::chrono::milliseconds{
                    static_cast<std::chrono::milliseconds::rep>(component.idle_timeout_ms)},
                0ns,
                [this, index, generation](std::uint64_t) {
                    auto& current = runtime_[index];
                    remove_handle(current.idle_timer);
                    if (current.generation == generation
                        && current.state == RuntimeState::ready
                        && current.inflight_calls == 0U) {
                        std::cerr << "msysd-native-lite: idle reclaim "
                                  << plan_.components[index].id << '\n';
                        (void)router_stop_component(index);
                    }
                });
        } catch (const std::exception& error) {
            std::cerr << "msysd-native-lite: idle timer failed "
                      << component.id << ": " << error.what() << '\n';
        }
    }

    void mark_foreground(std::size_t index) {
        foreground_stack_.erase(
            std::remove(foreground_stack_.begin(), foreground_stack_.end(), index),
            foreground_stack_.end());
        foreground_stack_.insert(foreground_stack_.begin(), index);
    }

    void remove_foreground(std::size_t index) {
        foreground_stack_.erase(
            std::remove(foreground_stack_.begin(), foreground_stack_.end(), index),
            foreground_stack_.end());
    }

    std::vector<msys::native::mipc::ComponentStatus> broker_component_statuses() const {
        std::vector<msys::native::mipc::ComponentStatus> result;
        result.reserve(plan_.components.size());
        for (std::size_t index = 0U; index < plan_.components.size(); ++index) {
            const auto& component = plan_.components[index];
            msys::native::mipc::ComponentStatus status{};
            status.id = component.id;
            status.lifecycle = lifecycle_name(component.lifecycle);
            status.restart = restart_name(component.restart);
            status.state = runtime_state_name(runtime_[index].state);
            status.package = component.package_id;
            status.package_version = component.package_version;
            status.package_kind = component.package_kind;
            status.name = component.name;
            status.summary = component.summary;
            status.window_system = component.window.system;
            status.window_display = component.window.display;
            status.window_mode = component.window.mode;
            status.window_title = component.window.title;
            status.window_identity = component.window.wm_class.empty()
                ? component.window.app_id : component.window.wm_class;
            status.launchable = component.launchable;
            status.foreground = std::find(
                foreground_stack_.begin(), foreground_stack_.end(), index)
                != foreground_stack_.end();
            for (const auto& provided : component.provides) {
                status.provides.push_back(msys::native::mipc::ComponentStatus::Provided{
                    provide_kind_name(provided.kind),
                    provided.name,
                    provided.exclusive,
                    provided.priority,
                });
            }
            result.push_back(std::move(status));
        }
        return result;
    }

    msys::native::mipc::OperationReply broker_start_component(
        std::string_view component) {
        const auto found = component_index(component);
        if (!found.has_value()) {
            return {false, std::string{component}, "", "NO_COMPONENT", "unknown component"};
        }
        if (shutting_down_) {
            return {
                false,
                std::string{component},
                "",
                "SHUTTING_DOWN",
                "supervisor is shutting down",
            };
        }
        auto& state = runtime_[*found];
        if (state.state == RuntimeState::stopped || state.state == RuntimeState::failed) {
            state.manual_stop = false;
            state.readiness_failed = false;
            state.restart_count = 0U;
            state.state = RuntimeState::waiting;
            start_eligible();
        } else if (state.state == RuntimeState::waiting) {
            start_eligible();
        }
        if (plan_.components[*found].launchable
            && state.state == RuntimeState::ready) {
            mark_foreground(*found);
            component_activity(*found);
        }
        return {
            true,
            std::string{component},
            runtime_state_name(state.state),
            "",
            "",
        };
    }

    msys::native::mipc::OperationReply broker_stop_component(
        std::string_view component) {
        const auto found = component_index(component);
        if (!found.has_value()) {
            return {false, std::string{component}, "", "NO_COMPONENT", "unknown component"};
        }
        auto& state = runtime_[*found];
        state.manual_stop = true;
        remove_handle(state.restart_timer);
        remove_handle(state.idle_timer);
        remove_foreground(*found);
        if (state.pid <= 0) {
            state.state = RuntimeState::stopped;
            return {true, std::string{component}, "stopped", "", ""};
        }
        if (state.state != RuntimeState::stopping) {
            clear_readiness(state);
            state.state = RuntimeState::stopping;
            if (broker_) {
                broker_->close_component_session(
                    plan_.components[*found].id, state.generation);
            }
            std::cerr << "msysd-native-lite: public stop "
                      << plan_.components[*found].id << '\n';
            signal_group(state.pid, SIGTERM);
            arm_stop_timeout(*found, state.generation);
        }
        return {true, std::string{component}, "stopping", "", ""};
    }

    void broker_component_ready(std::string_view component, std::uint64_t generation) {
        const auto found = component_index(component);
        if (!found.has_value()
            || plan_.components[*found].readiness != ReadinessMode::mipc) {
            return;
        }
        mark_ready(*found, generation);
    }

    void broker_component_disconnected(
        std::string_view component,
        std::uint64_t generation) {
        const auto found = component_index(component);
        if (!found.has_value()) {
            return;
        }
        auto& state = runtime_[*found];
        if (state.generation == generation && state.pid > 0
            && (state.state == RuntimeState::starting || state.state == RuntimeState::ready)) {
            fail_running_component(*found, "mIPC channel failed");
        }
    }

    bool dependencies_ready(std::size_t index) const {
        const auto& component = plan_.components[index];
        for (const auto& dependency : component.after) {
            const auto iterator = std::find_if(
                plan_.components.begin(),
                plan_.components.end(),
                [&dependency](const ComponentPlan& candidate) {
                    return candidate.id == dependency;
                });
            if (iterator == plan_.components.end()) {
                return false;
            }
            const auto distance = std::distance(plan_.components.begin(), iterator);
            const auto dependency_index = static_cast<std::size_t>(distance);
            const RuntimeState dependency_state = runtime_[dependency_index].state;
            // `after` is ordering, not activation. An unselected alternative
            // provider stays stopped and must not block the selected graph.
            if (dependency_state == RuntimeState::waiting
                || dependency_state == RuntimeState::starting
                || dependency_state == RuntimeState::backoff
                || dependency_state == RuntimeState::stopping) {
                return false;
            }
        }
        return true;
    }

    void start_eligible() {
        if (shutting_down_) {
            return;
        }
        bool changed = true;
        while (changed && !shutting_down_) {
            changed = false;
            for (std::size_t index = 0U; index < runtime_.size(); ++index) {
                if (runtime_[index].state == RuntimeState::waiting
                    && dependencies_ready(index)) {
                    spawn_component(index);
                    if (shutting_down_) {
                        return;
                    }
                    changed = true;
                }
            }
        }
    }

    void remove_handle(Handle& handle) {
        if (handle) {
            (void)reactor_.remove(handle);
            handle = Handle{};
        }
    }

    void clear_readiness(ComponentRuntime& state) {
        remove_handle(state.readiness_watch);
        remove_handle(state.readiness_timer);
        remove_handle(state.readiness_poll);
        close_fd(state.readiness_fd);
        state.readiness_buffer.clear();
    }

    std::vector<std::string> child_environment(
        std::size_t index,
        int ready_fd,
        int control_fd) const {
        std::vector<std::string> environment = inherited_environment();
        const auto& component = plan_.components[index];
        for (const auto& entry : plan_.profile_environment) {
            set_environment(environment, entry.first, entry.second);
        }
        if (!component.window.display.empty()
            && component.window.display != "inherit") {
            set_environment(environment, "DISPLAY", component.window.display);
        } else if (!plan_.display.empty()) {
            set_environment(environment, "DISPLAY", plan_.display);
        }
        for (const auto& entry : component.environment) {
            set_environment(environment, entry.first, entry.second);
        }
        set_environment(environment, "MSYS_COMPONENT_ID", component.id);
        set_environment(
            environment,
            "MSYS_GENERATION",
            std::to_string(runtime_[index].generation));
        if (ready_fd >= 0) {
            set_environment(environment, "MSYS_READY_FD", std::to_string(ready_fd));
        } else {
            unset_environment(environment, "MSYS_READY_FD");
        }
        if (control_fd >= 0) {
            set_environment(environment, "MSYS_CONTROL_FD", std::to_string(control_fd));
        } else {
            unset_environment(environment, "MSYS_CONTROL_FD");
        }
        if (options_.runtime_dir.has_value()) {
            set_environment(environment, "MSYS_RUNTIME_DIR", *options_.runtime_dir);
        } else {
            unset_environment(environment, "MSYS_RUNTIME_DIR");
        }
        if (!component.window.title.empty()) {
            set_environment(environment, "MSYS_WINDOW_TITLE", component.window.title);
        }
        if (!component.window.app_id.empty()) {
            set_environment(environment, "MSYS_APP_ID", component.window.app_id);
        }
        if (!component.window.wm_class.empty()) {
            set_environment(environment, "MSYS_WINDOW_IDENTITY", component.window.wm_class);
        }
        if (!component.window.wm_instance.empty()) {
            set_environment(environment, "MSYS_X11_WM_INSTANCE", component.window.wm_instance);
        }
        if (!component.package_id.empty()) {
            set_environment(environment, "MSYS_PACKAGE_ID", component.package_id);
            set_environment(environment, "MSYS_PACKAGE_VERSION", component.package_version);
        }
        return environment;
    }

    std::optional<std::string_view> component_environment_value(
        const ComponentPlan& component,
        std::string_view key) const {
        for (auto iterator = component.environment.rbegin();
             iterator != component.environment.rend();
             ++iterator) {
            if (iterator->first == key) {
                return iterator->second;
            }
        }
        for (auto iterator = plan_.profile_environment.rbegin();
             iterator != plan_.profile_environment.rend();
             ++iterator) {
            if (iterator->first == key) {
                return iterator->second;
            }
        }
        return std::nullopt;
    }

    std::string component_display(const ComponentPlan& component) const {
        const auto environment_display = component_environment_value(component, "DISPLAY");
        if (environment_display.has_value()) {
            return std::string{*environment_display};
        }
        if (!component.window.display.empty() && component.window.display != "inherit") {
            return component.window.display;
        }
        return plan_.display;
    }

    bool x11_ready(const ComponentPlan& component) const {
        const std::string display = component_display(component);
        if (display.size() < 2U || display.front() != ':') {
            return false;
        }
        std::size_t end = 1U;
        while (end < display.size() && display[end] >= '0' && display[end] <= '9') {
            ++end;
        }
        if (end == 1U || (end < display.size() && display[end] != '.')) {
            return false;
        }
        const std::string socket_path = "/tmp/.X11-unix/X" + display.substr(1U, end - 1U);
        struct stat metadata {};
        if (::stat(socket_path.c_str(), &metadata) != 0 || !S_ISSOCK(metadata.st_mode)) {
            return false;
        }
        const auto ready_file = component_environment_value(component, "MSYS_X11_READY_FILE");
        if (!ready_file.has_value() || ready_file->empty()) {
            return true;
        }
        return ::stat(std::string{*ready_file}.c_str(), &metadata) == 0
            && S_ISREG(metadata.st_mode);
    }

    void arm_x11_readiness_poll(std::size_t index, std::uint64_t generation) {
        auto& state = runtime_[index];
        state.readiness_poll = reactor_.add_timer(
            10ms,
            50ms,
            [this, index, generation](std::uint64_t) {
                const auto& current = runtime_[index];
                if (current.generation == generation
                    && current.state == RuntimeState::starting
                    && x11_ready(plan_.components[index])) {
                    mark_ready(index, generation);
                }
            });
    }

    void arm_readiness_timeout(std::size_t index, std::uint64_t generation) {
        auto& state = runtime_[index];
        const auto& component = plan_.components[index];
        state.readiness_timer = reactor_.add_timer(
            std::chrono::milliseconds{
                static_cast<std::chrono::milliseconds::rep>(
                    component.readiness_timeout_ms)},
            0ns,
            [this, index, generation](std::uint64_t) {
                auto& current = runtime_[index];
                if (current.generation == generation
                    && current.state == RuntimeState::starting) {
                    fail_running_component(index, "readiness timeout");
                }
            });
    }

    void spawn_component(std::size_t index) {
        if (shutting_down_) {
            return;
        }
        auto& state = runtime_[index];
        const auto& component = plan_.components[index];
        state.state = RuntimeState::starting;
        state.readiness_failed = false;
        state.manual_stop = false;
        state.readiness_buffer.clear();
        ++state.generation;
        ++start_sequence_;
        state.start_sequence = start_sequence_;

        std::array<int, 2U> readiness_pipe{-1, -1};
        if (component.readiness == ReadinessMode::fd) {
            if (::pipe2(readiness_pipe.data(), O_CLOEXEC | O_NONBLOCK) != 0) {
                handle_spawn_failure(index, "pipe2 failed");
                return;
            }
        }

        int control_fd = -1;
        if (component.readiness == ReadinessMode::mipc) {
            if (!broker_) {
                handle_spawn_failure(index, "mipc-ready requires --runtime-dir");
                return;
            }
            try {
                control_fd = broker_->create_component_session(
                    component.id, state.generation);
            } catch (const std::exception& error) {
                handle_spawn_failure(index, error.what());
                return;
            }
        }

        try {
            // Keep every allocation that follows pipe/socket creation inside
            // this scope so an exception cannot leak either child endpoint or
            // leave a registered broker session behind.
            SpawnOptions spawn{};
            spawn.argv = component.argv;
            spawn.search_path = false;
            spawn.new_process_group = true;
            spawn.environment = child_environment(
                index, readiness_pipe[1U], control_fd);
            spawn.inherited_fds = {0, 1, 2};
            if (readiness_pipe[1U] >= 0) {
                spawn.inherited_fds.push_back(readiness_pipe[1U]);
            }
            if (control_fd >= 0) {
                spawn.inherited_fds.push_back(control_fd);
            }
            const std::uint64_t generation = state.generation;
            const SpawnedChild child = reactor_.spawn_process(
                std::move(spawn),
                [this, index, generation](const ChildExit& result) {
                    on_child_exit(index, generation, result);
                });
            state.pid = child.pid;
        } catch (const std::exception& error) {
            close_fd(readiness_pipe[0U]);
            close_fd(readiness_pipe[1U]);
            close_fd(control_fd);
            handle_spawn_failure(index, error.what());
            return;
        }
        close_fd(readiness_pipe[1U]);
        close_fd(control_fd);
        std::cerr << "msysd-native-lite: starting " << component.id
                  << " kind=" << kind_name(component.kind)
                  << " gen=" << state.generation << " pid=" << state.pid << '\n';

        if (component.readiness == ReadinessMode::exec) {
            mark_ready(index, state.generation);
            return;
        }
        const std::uint64_t generation = state.generation;
        try {
            if (component.readiness == ReadinessMode::fd) {
                state.readiness_fd = readiness_pipe[0U];
                state.readiness_watch = reactor_.watch_fd(
                    state.readiness_fd,
                    static_cast<std::uint32_t>(EPOLLIN | EPOLLHUP | EPOLLERR),
                    [this, index, generation](std::uint32_t events) {
                        on_readiness(index, generation, events);
                    });
            }
            if (component.readiness == ReadinessMode::x11_display) {
                arm_x11_readiness_poll(index, generation);
            }
            arm_readiness_timeout(index, generation);
        } catch (const std::exception& error) {
            fail_running_component(index, error.what());
        }
    }

    void handle_spawn_failure(std::size_t index, const std::string& reason) {
        auto& state = runtime_[index];
        state.pid = -1;
        state.readiness_failed = true;
        remove_handle(state.idle_timer);
        remove_foreground(index);
        clear_readiness(state);
        if (broker_ && plan_.components[index].readiness == ReadinessMode::mipc) {
            broker_->close_component_session(
                plan_.components[index].id, state.generation);
        }
        if (router_) {
            router_->component_unavailable(index, state.generation);
        }
        std::cerr << "msysd-native-lite: spawn failed "
                  << plan_.components[index].id << ": " << reason << '\n';
        schedule_or_fail(index, true);
    }

    void on_readiness(
        std::size_t index,
        std::uint64_t generation,
        std::uint32_t events) {
        auto& state = runtime_[index];
        if (state.generation != generation || state.state != RuntimeState::starting
            || state.readiness_fd < 0) {
            return;
        }
        std::array<char, 32U> buffer{};
        bool reached_eof = false;
        for (;;) {
            const ssize_t count = ::read(state.readiness_fd, buffer.data(), buffer.size());
            if (count > 0) {
                state.readiness_buffer.append(
                    buffer.data(), static_cast<std::size_t>(count));
                if (state.readiness_buffer.size() > ready_record.size()) {
                    fail_running_component(index, "invalid readiness record");
                    return;
                }
                continue;
            }
            if (count == 0) {
                reached_eof = true;
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            fail_running_component(index, "readiness fd read failed");
            return;
        }
        const std::string_view observed{state.readiness_buffer};
        if (observed == ready_record) {
            mark_ready(index, generation);
            return;
        }
        if (!ready_record.starts_with(observed)) {
            fail_running_component(index, "invalid readiness record");
            return;
        }
        if (reached_eof || (events & static_cast<std::uint32_t>(EPOLLHUP | EPOLLERR)) != 0U) {
            fail_running_component(index, "readiness fd closed before READY");
        }
    }

    void mark_ready(std::size_t index, std::uint64_t generation) {
        auto& state = runtime_[index];
        if (state.generation != generation
            || (state.state != RuntimeState::starting
                && state.state != RuntimeState::ready)) {
            return;
        }
        if (state.state == RuntimeState::ready) {
            return;
        }
        clear_readiness(state);
        state.state = RuntimeState::ready;
        if (plan_.components[index].launchable) {
            mark_foreground(index);
        }
        std::cerr << "msysd-native-lite: ready " << plan_.components[index].id
                  << " gen=" << generation << '\n';
        if (router_) {
            router_->component_ready(index, generation);
        }
        arm_idle_timeout(index);
        start_eligible();
    }

    void signal_group(pid_t pid, int signal_number) noexcept {
        if (pid <= 0) {
            return;
        }
        if (::kill(-pid, signal_number) != 0) {
            (void)::kill(pid, signal_number);
        }
    }

    bool kill_remaining_process_group(pid_t process_group) noexcept {
        if (process_group <= 0) {
            return false;
        }
        // The watched leader has already been reaped, so never fall back to a
        // positive pid here: that numeric pid may be reused. Any surviving
        // same-group workers are component stragglers and must not be orphaned.
        return ::kill(-process_group, SIGKILL) == 0;
    }

    void emergency_kill_all() noexcept {
        // The Reactor itself may be unusable on this path, so an ordered,
        // timer-driven shutdown is no longer reliable. Do the smallest safe
        // fallback and ensure no supervised process group is orphaned.
        for (const auto& state : runtime_) {
            if (state.pid > 0) {
                signal_group(state.pid, SIGKILL);
            }
        }
    }

    void arm_stop_timeout(std::size_t index, std::uint64_t generation) {
        auto& state = runtime_[index];
        remove_handle(state.stop_timer);
        try {
            state.stop_timer = reactor_.add_timer(
                std::chrono::milliseconds{
                    static_cast<std::chrono::milliseconds::rep>(plan_.stop_grace_ms)},
                0ns,
                [this, index, generation](std::uint64_t) {
                    auto& current = runtime_[index];
                    if (current.generation == generation && current.pid > 0) {
                        std::cerr << "msysd-native-lite: SIGKILL "
                                  << plan_.components[index].id << '\n';
                        signal_group(current.pid, SIGKILL);
                    }
                });
        } catch (const std::exception& error) {
            // A component that ignores SIGTERM must never become an orphan just
            // because timerfd/epoll resources are exhausted. Escalate now.
            std::cerr << "msysd-native-lite: stop timer failed "
                      << plan_.components[index].id << ": " << error.what()
                      << "; sending SIGKILL\n";
            signal_group(state.pid, SIGKILL);
        } catch (...) {
            std::cerr << "msysd-native-lite: stop timer failed "
                      << plan_.components[index].id
                      << ": unknown error; sending SIGKILL\n";
            signal_group(state.pid, SIGKILL);
        }
    }

    void fail_running_component(std::size_t index, const std::string& reason) {
        auto& state = runtime_[index];
        if (state.pid <= 0 || state.state == RuntimeState::stopping) {
            return;
        }
        state.readiness_failed = true;
        clear_readiness(state);
        remove_handle(state.idle_timer);
        remove_foreground(index);
        state.state = RuntimeState::stopping;
        if (broker_ && plan_.components[index].readiness == ReadinessMode::mipc) {
            broker_->close_component_session(
                plan_.components[index].id, state.generation);
        }
        if (router_) {
            router_->component_unavailable(index, state.generation);
        }
        std::cerr << "msysd-native-lite: " << reason << " "
                  << plan_.components[index].id << '\n';
        signal_group(state.pid, SIGTERM);
        arm_stop_timeout(index, state.generation);
    }

    void on_child_exit(
        std::size_t index,
        std::uint64_t generation,
        const ChildExit& result) {
        auto& state = runtime_[index];
        if (state.generation != generation || state.pid != result.pid) {
            return;
        }
        clear_readiness(state);
        remove_handle(state.stop_timer);
        remove_handle(state.idle_timer);
        remove_foreground(index);
        if (broker_ && plan_.components[index].readiness == ReadinessMode::mipc) {
            broker_->close_component_session(
                plan_.components[index].id, generation);
        }
        if (router_) {
            router_->component_unavailable(index, generation);
        }
        const pid_t process_group = state.pid;
        state.pid = -1;
        state.inflight_calls = 0U;
        if (kill_remaining_process_group(process_group)) {
            std::cerr << "msysd-native-lite: killed remaining process group "
                      << plan_.components[index].id << '\n';
        }
        const bool failed = state.readiness_failed || child_failed(result);
        std::cerr << "msysd-native-lite: exited " << plan_.components[index].id
                  << " gen=" << generation << " status=" << result.status
                  << " failed=" << (failed ? 1 : 0) << '\n';

        if (shutting_down_) {
            state.state = RuntimeState::stopped;
            if (stopping_index_.has_value() && *stopping_index_ == index) {
                stopping_index_.reset();
                stop_next();
            }
            return;
        }
        if (state.manual_stop) {
            state.manual_stop = false;
            state.readiness_failed = false;
            state.state = RuntimeState::stopped;
            return;
        }
        state.readiness_failed = false;
        schedule_or_fail(index, failed);
    }

    bool policy_restarts(const ComponentPlan& component, bool failed) const {
        if (component.restart == RestartPolicy::always) {
            return true;
        }
        return component.restart == RestartPolicy::on_failure && failed;
    }

    std::uint32_t restart_delay(const ComponentPlan& component, std::uint32_t count) const {
        std::uint64_t delay = component.backoff_initial_ms;
        for (std::uint32_t step = 1U; step < count; ++step) {
            delay = std::min<std::uint64_t>(
                static_cast<std::uint64_t>(component.backoff_max_ms), delay * 2U);
        }
        return static_cast<std::uint32_t>(delay);
    }

    void schedule_or_fail(std::size_t index, bool failed) {
        auto& state = runtime_[index];
        const auto& component = plan_.components[index];
        if (policy_restarts(component, failed)
            && state.restart_count < component.restart_limit) {
            ++state.restart_count;
            const std::uint32_t delay = restart_delay(component, state.restart_count);
            state.state = RuntimeState::backoff;
            const std::uint64_t generation = state.generation;
            std::cerr << "msysd-native-lite: restart " << component.id
                      << " attempt=" << state.restart_count
                      << " delay_ms=" << delay << '\n';
            try {
                state.restart_timer = reactor_.add_timer(
                    std::chrono::milliseconds{
                        static_cast<std::chrono::milliseconds::rep>(delay)},
                    0ns,
                    [this, index, generation](std::uint64_t) {
                        auto& current = runtime_[index];
                        if (current.generation != generation
                            || current.state != RuntimeState::backoff
                            || shutting_down_) {
                            return;
                        }
                        remove_handle(current.restart_timer);
                        current.state = RuntimeState::waiting;
                        start_eligible();
                    });
            } catch (const std::exception& error) {
                state.state = RuntimeState::failed;
                std::cerr << "msysd-native-lite: restart timer failed "
                          << component.id << ": " << error.what() << '\n';
                begin_shutdown(internal_supervisor_exit, "restart-timer-failure");
            } catch (...) {
                state.state = RuntimeState::failed;
                std::cerr << "msysd-native-lite: restart timer failed "
                          << component.id << ": unknown error\n";
                begin_shutdown(internal_supervisor_exit, "restart-timer-failure");
            }
            return;
        }
        state.state = failed ? RuntimeState::failed : RuntimeState::stopped;
        if (component.critical) {
            std::cerr << "msysd-native-lite: terminal critical component "
                      << component.id << '\n';
            begin_shutdown(terminal_component_exit, "critical-component");
        }
    }

    void begin_shutdown(int code, const std::string& reason) {
        if (shutting_down_) {
            if (code != 0 && exit_code_ == 0) {
                exit_code_ = code;
            }
            return;
        }
        shutting_down_ = true;
        exit_code_ = code;
        std::cerr << "msysd-native-lite: stopping reason=" << reason << '\n';
        stop_order_.clear();
        for (std::size_t index = 0U; index < runtime_.size(); ++index) {
            auto& state = runtime_[index];
            remove_handle(state.restart_timer);
            remove_handle(state.idle_timer);
            if (state.pid > 0) {
                stop_order_.push_back(index);
            } else if (state.state != RuntimeState::failed) {
                state.state = RuntimeState::stopped;
            }
        }
        std::sort(
            stop_order_.begin(),
            stop_order_.end(),
            [this](std::size_t left, std::size_t right) {
                return runtime_[left].start_sequence < runtime_[right].start_sequence;
            });
        stop_next();
    }

    void stop_next() {
        while (!stop_order_.empty()) {
            const std::size_t index = stop_order_.back();
            stop_order_.pop_back();
            auto& state = runtime_[index];
            if (state.pid <= 0) {
                continue;
            }
            state.state = RuntimeState::stopping;
            stopping_index_ = index;
            clear_readiness(state);
            remove_handle(state.idle_timer);
            remove_foreground(index);
            if (broker_ && plan_.components[index].readiness == ReadinessMode::mipc) {
                broker_->close_component_session(
                    plan_.components[index].id, state.generation);
            }
            std::cerr << "msysd-native-lite: SIGTERM "
                      << plan_.components[index].id << '\n';
            signal_group(state.pid, SIGTERM);
            arm_stop_timeout(index, state.generation);
            return;
        }
        done_ = true;
    }

    RuntimePlan plan_;
    SupervisorOptions options_{};
    Reactor reactor_{};
    std::vector<ComponentRuntime> runtime_;
    NativeCatalog catalog_;
    std::unique_ptr<msys::native::mipc::Broker> broker_;
    std::unique_ptr<NativeRouter> router_;
    std::vector<std::size_t> foreground_stack_;
    std::vector<std::size_t> stop_order_;
    std::optional<std::size_t> stopping_index_;
    std::uint64_t start_sequence_{0U};
    bool shutting_down_{false};
    bool done_{false};
    int exit_code_{0};
};

std::size_t current_rss_kib() {
    std::ifstream status{"/proc/self/status"};
    std::string line;
    while (std::getline(status, line)) {
        if (!line.starts_with("VmRSS:")) {
            continue;
        }
        std::istringstream values{line.substr(6U)};
        std::size_t rss = 0U;
        std::string unit;
        if (values >> rss >> unit && unit == "kB") {
            return rss;
        }
    }
    return 0U;
}

Supervisor::Supervisor(RuntimePlan plan, SupervisorOptions options)
    : impl_(std::make_unique<Impl>(std::move(plan), options)) {}

Supervisor::~Supervisor() = default;

int Supervisor::run() {
    return impl_->run();
}

}  // namespace msys::native::lite
