#include "msys/native_lite.hpp"

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace msys::native::lite {
namespace {

constexpr std::string_view plan_header_v1 = "MSYS_NATIVE_LITE_PLAN\t1";
constexpr std::string_view plan_header_v2 = "MSYS_NATIVE_LITE_PLAN\t2";
constexpr std::size_t max_line_bytes = 32768U;

[[noreturn]] void fail(const std::string& detail) {
    throw std::invalid_argument("native-lite plan: " + detail);
}

[[noreturn]] void fail_errno(const std::string& operation) {
    const int saved_errno = errno;
    throw std::runtime_error(
        operation + ": " + std::string(std::strerror(saved_errno)));
}

constexpr bool ascii_alpha(char value) noexcept {
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

constexpr bool ascii_digit(char value) noexcept {
    return value >= '0' && value <= '9';
}

constexpr bool ascii_alnum(char value) noexcept {
    return ascii_alpha(value) || ascii_digit(value);
}

bool valid_id(std::string_view value) {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    if (!ascii_alnum(value.front())) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        return ascii_alnum(character) || character == '_' || character == '-'
            || character == '.' || character == ':';
    });
}

bool valid_environment_key(std::string_view value) {
    if (value.empty() || value.size() > 128U) {
        return false;
    }
    if (!ascii_alpha(value.front()) && value.front() != '_') {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](char character) {
        return ascii_alnum(character) || character == '_';
    });
}

std::vector<std::string_view> split_lines(std::string_view text) {
    std::vector<std::string_view> lines;
    std::size_t offset = 0U;
    while (offset < text.size()) {
        const std::size_t newline = text.find('\n', offset);
        const std::size_t end = newline == std::string_view::npos ? text.size() : newline;
        const std::string_view line = text.substr(offset, end - offset);
        if (line.size() > max_line_bytes) {
            fail("line exceeds 32768 bytes");
        }
        if (line.find('\r') != std::string_view::npos) {
            fail("carriage returns are not accepted");
        }
        if (line.empty()) {
            fail("empty lines are not accepted");
        }
        lines.push_back(line);
        if (newline == std::string_view::npos) {
            break;
        }
        offset = newline + 1U;
    }
    if (lines.empty()) {
        fail("file is empty");
    }
    return lines;
}

std::vector<std::string_view> split_fields(std::string_view line) {
    std::vector<std::string_view> fields;
    std::size_t offset = 0U;
    while (true) {
        const std::size_t tab = line.find('\t', offset);
        if (tab == std::string_view::npos) {
            fields.push_back(line.substr(offset));
            break;
        }
        fields.push_back(line.substr(offset, tab - offset));
        offset = tab + 1U;
    }
    return fields;
}

std::uint32_t parse_u32(
    std::string_view value,
    std::string_view field,
    std::uint32_t minimum,
    std::uint32_t maximum) {
    std::uint32_t result = 0U;
    const char* const begin = value.data();
    const char* const end = value.data() + value.size();
    const auto parsed = std::from_chars(begin, end, result, 10);
    if (value.empty() || parsed.ec != std::errc{} || parsed.ptr != end
        || result < minimum || result > maximum) {
        fail(std::string(field) + " is outside its allowed integer range");
    }
    return result;
}

int hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

std::string decode_hex(std::string_view value, std::string_view field) {
    if (value.size() % 2U != 0U || value.size() > 8192U) {
        fail(std::string(field) + " has an invalid encoded length");
    }
    std::string decoded;
    decoded.reserve(value.size() / 2U);
    for (std::size_t index = 0U; index < value.size(); index += 2U) {
        const int high = hex_nibble(value[index]);
        const int low = hex_nibble(value[index + 1U]);
        if (high < 0 || low < 0) {
            fail(std::string(field) + " is not hexadecimal");
        }
        const auto byte = static_cast<unsigned char>((high << 4) | low);
        if (byte == 0U) {
            fail(std::string(field) + " contains NUL");
        }
        decoded.push_back(static_cast<char>(byte));
    }
    return decoded;
}

ComponentKind parse_kind(std::string_view value) {
    if (value == "display") {
        return ComponentKind::display;
    }
    if (value == "window") {
        return ComponentKind::window;
    }
    if (value == "shell") {
        return ComponentKind::shell;
    }
    if (value == "other") {
        return ComponentKind::other;
    }
    fail("unknown component kind");
}

RestartPolicy parse_restart(std::string_view value) {
    if (value == "never") {
        return RestartPolicy::never;
    }
    if (value == "on-failure") {
        return RestartPolicy::on_failure;
    }
    if (value == "always") {
        return RestartPolicy::always;
    }
    fail("unknown restart policy");
}

ReadinessMode parse_readiness(std::string_view value) {
    if (value == "exec") {
        return ReadinessMode::exec;
    }
    if (value == "fd") {
        return ReadinessMode::fd;
    }
    if (value == "mipc-ready") {
        return ReadinessMode::mipc;
    }
    if (value == "x11-display") {
        return ReadinessMode::x11_display;
    }
    fail("unknown readiness mode");
}

Lifecycle parse_lifecycle(std::string_view value) {
    if (value == "background") {
        return Lifecycle::background;
    }
    if (value == "on-demand") {
        return Lifecycle::on_demand;
    }
    if (value == "manual") {
        return Lifecycle::manual;
    }
    fail("unknown lifecycle");
}

ProvideKind parse_provide_kind(std::string_view value) {
    if (value == "role") {
        return ProvideKind::role;
    }
    if (value == "interface") {
        return ProvideKind::interface;
    }
    if (value == "capability") {
        return ProvideKind::capability;
    }
    fail("unknown provide kind");
}

void validate_graph(const RuntimePlan& plan) {
    std::unordered_map<std::string, std::size_t> by_id;
    by_id.reserve(plan.components.size());
    bool has_critical = false;
    for (std::size_t index = 0U; index < plan.components.size(); ++index) {
        const auto& component = plan.components[index];
        if (!by_id.emplace(component.id, index).second) {
            fail("duplicate component id: " + component.id);
        }
        has_critical = has_critical || component.critical;
    }
    if (!has_critical) {
        fail("at least one component must be critical");
    }
    for (const auto& component : plan.components) {
        std::unordered_set<std::string> unique_dependencies;
        for (const auto& dependency : component.after) {
            if (by_id.find(dependency) == by_id.end()) {
                fail(component.id + " references missing dependency " + dependency);
            }
            if (dependency == component.id) {
                fail(component.id + " depends on itself");
            }
            if (!unique_dependencies.insert(dependency).second) {
                fail(component.id + " repeats dependency " + dependency);
            }
        }
    }

    std::vector<unsigned char> marks(plan.components.size(), 0U);
    const auto visit = [&](const auto& self, std::size_t index) -> void {
        if (marks[index] == 1U) {
            fail("dependency graph contains a cycle");
        }
        if (marks[index] == 2U) {
            return;
        }
        marks[index] = 1U;
        for (const auto& dependency : plan.components[index].after) {
            self(self, by_id.at(dependency));
        }
        marks[index] = 2U;
    };
    for (std::size_t index = 0U; index < plan.components.size(); ++index) {
        visit(visit, index);
    }
}

}  // namespace

RuntimePlan parse_runtime_plan(std::string_view text) {
    if (text.size() > max_plan_bytes) {
        fail("file exceeds 1 MiB");
    }
    const auto lines = split_lines(text);
    const bool version_two = lines.front() == plan_header_v2;
    if (!version_two && lines.front() != plan_header_v1) {
        fail("unsupported header");
    }
    if (lines.size() < 3U) {
        fail("global settings or components are missing");
    }

    RuntimePlan plan{};
    const auto global = split_fields(lines[1U]);
    if (global.size() != 2U || global[0U] != "stop_grace_ms") {
        fail("expected stop_grace_ms after header");
    }
    plan.stop_grace_ms = parse_u32(global[1U], "stop_grace_ms", 100U, 60000U);

    std::size_t line_index = 2U;
    if (version_two) {
        if (line_index >= lines.size()) {
            fail("version 2 profile record is missing");
        }
        const auto profile = split_fields(lines[line_index]);
        ++line_index;
        if (profile.size() != 6U || profile[0U] != "profile") {
            fail("expected a 6-field profile record");
        }
        plan.profile_id = decode_hex(profile[1U], "profile id");
        plan.display = decode_hex(profile[2U], "profile display");
        if (!valid_id(plan.profile_id) || plan.display.size() > 63U) {
            fail("profile id or display is invalid");
        }
        const std::uint32_t role_count = parse_u32(
            profile[3U], "profile role count", 0U,
            static_cast<std::uint32_t>(max_profile_roles));
        const std::uint32_t profile_environment_count = parse_u32(
            profile[4U], "profile environment count", 0U,
            static_cast<std::uint32_t>(max_environment));
        const std::uint32_t startup_count = parse_u32(
            profile[5U], "profile startup count", 0U,
            static_cast<std::uint32_t>(max_components));
        std::unordered_set<std::string> role_names;
        for (std::uint32_t role_index = 0U; role_index < role_count; ++role_index) {
            if (line_index >= lines.size()) {
                fail("truncated profile role records");
            }
            const auto role_record = split_fields(lines[line_index]);
            ++line_index;
            if (role_record.size() != 3U || role_record[0U] != "role") {
                fail("expected profile role record");
            }
            RolePreference preference{};
            preference.role = decode_hex(role_record[1U], "profile role");
            if (!valid_id(preference.role) || !role_names.insert(preference.role).second) {
                fail("invalid or duplicate profile role");
            }
            const std::uint32_t provider_count = parse_u32(
                role_record[2U], "preferred provider count", 1U,
                static_cast<std::uint32_t>(max_components));
            std::unordered_set<std::string> providers;
            for (std::uint32_t provider_index = 0U;
                 provider_index < provider_count;
                 ++provider_index) {
                if (line_index >= lines.size()) {
                    fail("truncated preferred provider records");
                }
                const auto provider = split_fields(lines[line_index]);
                ++line_index;
                if (provider.size() != 2U || provider[0U] != "provider"
                    || !valid_id(provider[1U])) {
                    fail("invalid preferred provider record");
                }
                if (!providers.emplace(provider[1U]).second) {
                    fail("duplicate preferred provider");
                }
                preference.providers.emplace_back(provider[1U]);
            }
            plan.role_preferences.push_back(std::move(preference));
        }
        std::unordered_set<std::string> profile_environment_keys;
        for (std::uint32_t environment_index = 0U;
             environment_index < profile_environment_count;
             ++environment_index) {
            if (line_index >= lines.size()) {
                fail("truncated profile environment records");
            }
            const auto environment = split_fields(lines[line_index]);
            ++line_index;
            if (environment.size() != 3U || environment[0U] != "profile-env") {
                fail("expected profile-env record");
            }
            std::string key = decode_hex(environment[1U], "profile environment key");
            std::string value = decode_hex(environment[2U], "profile environment value");
            if (!valid_environment_key(key) || value.size() > 4096U
                || !profile_environment_keys.insert(key).second) {
                fail("invalid or duplicate profile environment");
            }
            if (key == "MSYS_READY_FD" || key == "MSYS_CONTROL_FD"
                || key == "MSYS_COMPONENT_ID" || key == "MSYS_GENERATION"
                || key == "MSYS_RUNTIME_DIR" || key == "MSYS_PACKAGE_ID"
                || key == "MSYS_PACKAGE_VERSION" || key == "MSYS_WINDOW_TITLE"
                || key == "MSYS_APP_ID" || key == "MSYS_WINDOW_IDENTITY"
                || key == "MSYS_X11_WM_INSTANCE") {
                fail("profile environment overrides a reserved supervisor key");
            }
            plan.profile_environment.emplace_back(std::move(key), std::move(value));
        }
        std::unordered_set<std::string> startup_components;
        for (std::uint32_t startup_index = 0U; startup_index < startup_count; ++startup_index) {
            if (line_index >= lines.size()) {
                fail("truncated profile startup records");
            }
            const auto startup = split_fields(lines[line_index]);
            ++line_index;
            if (startup.size() != 2U || startup[0U] != "startup"
                || !valid_id(startup[1U])
                || !startup_components.emplace(startup[1U]).second) {
                fail("invalid or duplicate profile startup record");
            }
            plan.startup.emplace_back(startup[1U]);
        }
    }
    while (line_index < lines.size()) {
        if (plan.components.size() >= max_components) {
            fail("component count exceeds 64");
        }
        const auto header = split_fields(lines[line_index]);
        ++line_index;
        const std::size_t expected_fields = version_two ? 18U : 13U;
        if (header.size() != expected_fields || header[0U] != "component") {
            fail(version_two
                ? "expected an 18-field component record"
                : "expected a 13-field component record");
        }
        ComponentPlan component{};
        component.id = std::string(header[1U]);
        if (!valid_id(component.id)) {
            fail("invalid component id");
        }
        component.kind = parse_kind(header[2U]);
        if (header[3U] == "1") {
            component.critical = true;
        } else if (header[3U] != "0") {
            fail("critical must be 0 or 1");
        }
        component.restart = parse_restart(header[4U]);
        component.readiness = parse_readiness(header[5U]);
        component.readiness_timeout_ms = parse_u32(
            header[6U], "readiness_timeout_ms", 1U, 300000U);
        component.backoff_initial_ms = parse_u32(
            header[7U], "backoff_initial_ms", 1U, 60000U);
        component.backoff_max_ms = parse_u32(
            header[8U], "backoff_max_ms", component.backoff_initial_ms, 300000U);
        component.restart_limit = parse_u32(header[9U], "restart_limit", 0U, 1000U);
        const std::uint32_t argument_count = parse_u32(
            header[10U], "argument_count", 1U, static_cast<std::uint32_t>(max_arguments));
        const std::uint32_t dependency_count = parse_u32(
            header[11U], "dependency_count", 0U, static_cast<std::uint32_t>(max_dependencies));
        const std::uint32_t environment_count = parse_u32(
            header[12U], "environment_count", 0U, static_cast<std::uint32_t>(max_environment));
        std::uint32_t provide_count = 0U;
        std::uint32_t permission_count = 0U;
        if (version_two) {
            component.lifecycle = parse_lifecycle(header[13U]);
            component.idle_timeout_ms = parse_u32(
                header[14U], "idle_timeout_ms", 0U, 3600000U);
            if (component.lifecycle == Lifecycle::on_demand
                && component.idle_timeout_ms < 100U) {
                fail("on-demand component requires idle_timeout_ms >= 100");
            }
            if (component.lifecycle != Lifecycle::on_demand
                && component.idle_timeout_ms != 0U) {
                fail("only on-demand components may set idle_timeout_ms");
            }
            provide_count = parse_u32(
                header[15U], "provide_count", 0U,
                static_cast<std::uint32_t>(max_provides));
            permission_count = parse_u32(
                header[16U], "permission_count", 0U,
                static_cast<std::uint32_t>(max_permissions));
            if (header[17U] == "1") {
                component.launchable = true;
            } else if (header[17U] != "0") {
                fail("launchable must be 0 or 1");
            }
        }

        for (std::uint32_t index = 0U; index < argument_count; ++index) {
            if (line_index >= lines.size()) {
                fail("truncated argument records");
            }
            const auto fields = split_fields(lines[line_index]);
            ++line_index;
            if (fields.size() != 2U || fields[0U] != "arg") {
                fail("expected arg record");
            }
            component.argv.push_back(decode_hex(fields[1U], "argument"));
        }
        if (component.argv.front().empty() || component.argv.front().front() != '/') {
            fail(component.id + " argv[0] must be absolute");
        }

        for (std::uint32_t index = 0U; index < dependency_count; ++index) {
            if (line_index >= lines.size()) {
                fail("truncated dependency records");
            }
            const auto fields = split_fields(lines[line_index]);
            ++line_index;
            if (fields.size() != 2U || fields[0U] != "after" || !valid_id(fields[1U])) {
                fail("invalid after record");
            }
            component.after.emplace_back(fields[1U]);
        }

        std::unordered_set<std::string> environment_keys;
        for (std::uint32_t index = 0U; index < environment_count; ++index) {
            if (line_index >= lines.size()) {
                fail("truncated environment records");
            }
            const auto fields = split_fields(lines[line_index]);
            ++line_index;
            if (fields.size() != 3U || fields[0U] != "env") {
                fail("expected env record");
            }
            std::string key = decode_hex(fields[1U], "environment key");
            std::string value = decode_hex(fields[2U], "environment value");
            if (!valid_environment_key(key)) {
                fail("invalid environment key");
            }
            if (value.size() > 4096U) {
                fail("environment value exceeds 4096 bytes");
            }
            if (key == "MSYS_READY_FD" || key == "MSYS_CONTROL_FD"
                || key == "MSYS_COMPONENT_ID" || key == "MSYS_GENERATION"
                || key == "MSYS_RUNTIME_DIR" || key == "MSYS_PACKAGE_ID"
                || key == "MSYS_PACKAGE_VERSION" || key == "MSYS_WINDOW_TITLE"
                || key == "MSYS_APP_ID" || key == "MSYS_WINDOW_IDENTITY"
                || key == "MSYS_X11_WM_INSTANCE") {
                fail("environment overrides a reserved supervisor key");
            }
            if (!environment_keys.insert(key).second) {
                fail("duplicate environment key");
            }
            component.environment.emplace_back(std::move(key), std::move(value));
        }

        if (version_two) {
            std::unordered_set<std::string> provided_names;
            for (std::uint32_t index = 0U; index < provide_count; ++index) {
                if (line_index >= lines.size()) {
                    fail("truncated provide records");
                }
                const auto fields = split_fields(lines[line_index]);
                ++line_index;
                if (fields.size() != 5U || fields[0U] != "provide") {
                    fail("expected provide record");
                }
                ProvidePlan provided{};
                provided.kind = parse_provide_kind(fields[1U]);
                provided.name = decode_hex(fields[2U], "provided name");
                if (!valid_id(provided.name)) {
                    fail("invalid provided name");
                }
                if (fields[3U] == "1") {
                    provided.exclusive = true;
                } else if (fields[3U] != "0") {
                    fail("provide exclusive must be 0 or 1");
                }
                provided.priority = parse_u32(fields[4U], "provide priority", 0U, 1000000U);
                const std::string unique = std::to_string(static_cast<int>(provided.kind))
                    + ":" + provided.name;
                if (!provided_names.insert(unique).second) {
                    fail("duplicate provide record");
                }
                component.provides.push_back(std::move(provided));
            }
            std::unordered_set<std::string> permissions;
            for (std::uint32_t index = 0U; index < permission_count; ++index) {
                if (line_index >= lines.size()) {
                    fail("truncated permission records");
                }
                const auto fields = split_fields(lines[line_index]);
                ++line_index;
                if (fields.size() != 2U || fields[0U] != "permission") {
                    fail("expected permission record");
                }
                std::string permission = decode_hex(fields[1U], "permission");
                if (permission.empty() || permission.size() > 256U
                    || !permissions.insert(permission).second) {
                    fail("invalid or duplicate permission");
                }
                component.permissions.push_back(std::move(permission));
            }
            if (line_index >= lines.size()) {
                fail("component package record is missing");
            }
            const auto package = split_fields(lines[line_index]);
            ++line_index;
            if (package.size() != 5U || package[0U] != "package") {
                fail("expected package record");
            }
            component.package_id = decode_hex(package[1U], "package id");
            component.package_name = decode_hex(package[2U], "package name");
            component.package_version = decode_hex(package[3U], "package version");
            component.package_kind = decode_hex(package[4U], "package kind");
            if (!valid_id(component.package_id) || component.package_name.size() > 256U
                || component.package_version.size() > 64U
                || component.package_kind.size() > 64U) {
                fail("invalid package metadata");
            }
            if (line_index >= lines.size()) {
                fail("component metadata record is missing");
            }
            const auto metadata = split_fields(lines[line_index]);
            ++line_index;
            if (metadata.size() != 4U || metadata[0U] != "metadata") {
                fail("expected metadata record");
            }
            component.name = decode_hex(metadata[1U], "component name");
            component.summary = decode_hex(metadata[2U], "component summary");
            component.icon = decode_hex(metadata[3U], "component icon");
            if (component.name.empty() || component.name.size() > 256U
                || component.summary.size() > 1024U || component.icon.size() > 4096U) {
                fail("invalid component metadata");
            }
            if (line_index >= lines.size()) {
                fail("component window record is missing");
            }
            const auto window = split_fields(lines[line_index]);
            ++line_index;
            if (window.size() != 8U || window[0U] != "window") {
                fail("expected window record");
            }
            component.window.system = decode_hex(window[1U], "window system");
            component.window.display = decode_hex(window[2U], "window display");
            component.window.mode = decode_hex(window[3U], "window mode");
            component.window.title = decode_hex(window[4U], "window title");
            component.window.app_id = decode_hex(window[5U], "window app id");
            component.window.wm_class = decode_hex(window[6U], "window class");
            component.window.wm_instance = decode_hex(window[7U], "window instance");
            if (component.window.system.size() > 32U
                || component.window.display.size() > 64U
                || component.window.mode.size() > 64U
                || component.window.title.size() > 256U
                || component.window.app_id.size() > 256U
                || component.window.wm_class.size() > 256U
                || component.window.wm_instance.size() > 256U) {
                fail("window metadata is too large");
            }
        } else {
            component.name = component.id;
        }

        if (line_index >= lines.size() || lines[line_index] != "end") {
            fail("component is missing end record");
        }
        ++line_index;
        plan.components.push_back(std::move(component));
    }
    validate_graph(plan);
    if (version_two) {
        std::unordered_set<std::string> known;
        for (const auto& component : plan.components) {
            known.insert(component.id);
        }
        for (const auto& startup : plan.startup) {
            if (known.find(startup) == known.end()) {
                fail("profile startup references missing component " + startup);
            }
        }
        for (const auto& preference : plan.role_preferences) {
            for (const auto& provider : preference.providers) {
                if (known.find(provider) == known.end()) {
                    fail("profile role references missing component " + provider);
                }
            }
        }
    }
    return plan;
}

RuntimePlan load_runtime_plan_file(const std::string& path) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        fail_errno("open native-lite plan");
    }
    struct DescriptorGuard final {
        int value;
        ~DescriptorGuard() { (void)::close(value); }
    } guard{descriptor};

    struct stat metadata {};
    if (::fstat(descriptor, &metadata) != 0) {
        fail_errno("fstat native-lite plan");
    }
    if (!S_ISREG(metadata.st_mode)) {
        throw std::runtime_error("native-lite plan is not a regular file");
    }
    if (metadata.st_uid != ::geteuid()) {
        throw std::runtime_error("native-lite plan owner does not match effective uid");
    }
    if ((metadata.st_mode & static_cast<mode_t>(S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error("native-lite plan must not be group/world writable");
    }
    if (metadata.st_size <= 0
        || static_cast<std::uintmax_t>(metadata.st_size) > max_plan_bytes) {
        throw std::runtime_error("native-lite plan size is outside 1..1048576 bytes");
    }

    const auto expected = static_cast<std::size_t>(metadata.st_size);
    std::string content(expected, '\0');
    std::size_t offset = 0U;
    while (offset < content.size()) {
        const ssize_t count = ::read(
            descriptor,
            content.data() + offset,
            content.size() - offset);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail_errno("read native-lite plan");
        }
        if (count == 0) {
            throw std::runtime_error("native-lite plan changed while being read");
        }
        offset += static_cast<std::size_t>(count);
    }
    return parse_runtime_plan(content);
}

}  // namespace msys::native::lite
