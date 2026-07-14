#pragma once

#include "msys/reactor.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace msys::native::lite {

inline constexpr std::size_t max_plan_bytes = 1024U * 1024U;
inline constexpr std::size_t max_components = 64U;
inline constexpr std::size_t max_arguments = 64U;
inline constexpr std::size_t max_dependencies = 32U;
inline constexpr std::size_t max_environment = 64U;
inline constexpr std::size_t max_provides = 32U;
inline constexpr std::size_t max_permissions = 128U;
inline constexpr std::size_t max_profile_roles = 64U;

enum class ComponentKind {
    display,
    window,
    shell,
    other,
};

enum class RestartPolicy {
    never,
    on_failure,
    always,
};

enum class ReadinessMode {
    exec,
    fd,
    mipc,
    x11_display,
};

enum class Lifecycle {
    background,
    on_demand,
    manual,
};

enum class ProvideKind {
    role,
    interface,
    capability,
};

struct ProvidePlan {
    ProvideKind kind{ProvideKind::capability};
    std::string name;
    bool exclusive{false};
    std::uint32_t priority{0U};
};

struct WindowPlan {
    std::string system;
    std::string display;
    std::string mode;
    std::string title;
    std::string app_id;
    std::string wm_class;
    std::string wm_instance;
};

struct ComponentPlan {
    std::string id;
    ComponentKind kind{ComponentKind::other};
    bool critical{false};
    RestartPolicy restart{RestartPolicy::never};
    ReadinessMode readiness{ReadinessMode::exec};
    Lifecycle lifecycle{Lifecycle::background};
    std::uint32_t readiness_timeout_ms{5000U};
    std::uint32_t idle_timeout_ms{0U};
    std::uint32_t backoff_initial_ms{250U};
    std::uint32_t backoff_max_ms{30000U};
    std::uint32_t restart_limit{8U};
    std::vector<std::string> argv;
    std::vector<std::string> after;
    std::vector<std::pair<std::string, std::string>> environment;
    std::vector<ProvidePlan> provides;
    std::vector<std::string> permissions;
    WindowPlan window{};
    std::string package_id;
    std::string package_name;
    std::string package_version;
    std::string package_kind;
    std::string name;
    std::string summary;
    std::string icon;
    bool launchable{false};
};

struct RolePreference {
    std::string role;
    std::vector<std::string> providers;
};

struct RuntimePlan {
    std::uint32_t stop_grace_ms{2000U};
    std::string profile_id;
    std::string display;
    std::vector<std::pair<std::string, std::string>> profile_environment;
    std::vector<std::string> startup;
    std::vector<RolePreference> role_preferences;
    std::vector<ComponentPlan> components;
};

// Parses the strict, line-oriented MSYS_NATIVE_LITE_PLAN v1 format. This API
// is useful to unit tests and trusted embedding code; normal execution should
// use load_runtime_plan_file(), which additionally checks ownership and mode.
[[nodiscard]] RuntimePlan parse_runtime_plan(std::string_view text);

// Opens with O_NOFOLLOW, requires a regular file owned by the effective user,
// rejects group/world-writable input, and enforces max_plan_bytes.
[[nodiscard]] RuntimePlan load_runtime_plan_file(const std::string& path);

[[nodiscard]] std::size_t current_rss_kib();

struct SupervisorOptions {
    bool report_rss{false};
    std::optional<std::string> runtime_dir;
};

class Supervisor final {
public:
    explicit Supervisor(RuntimePlan plan, SupervisorOptions options = {});
    ~Supervisor();

    Supervisor(const Supervisor&) = delete;
    Supervisor& operator=(const Supervisor&) = delete;
    Supervisor(Supervisor&&) = delete;
    Supervisor& operator=(Supervisor&&) = delete;

    // Runs until SIGINT/SIGTERM or a terminal critical-component failure.
    // Returns zero for an operator-requested ordered shutdown and nonzero for
    // plan/runtime failure. With runtime_dir it embeds the bounded phase-3
    // mIPC broker; it is still not the full production Core.
    [[nodiscard]] int run();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace msys::native::lite
