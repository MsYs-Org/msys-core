#include "msys/native_lite.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

using msys::native::lite::ComponentKind;
using msys::native::lite::Lifecycle;
using msys::native::lite::ProvideKind;
using msys::native::lite::ReadinessMode;
using msys::native::lite::RestartPolicy;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string valid_plan() {
    return
        "MSYS_NATIVE_LITE_PLAN\t1\n"
        "stop_grace_ms\t500\n"
        "component\tdisplay\tdisplay\t1\ton-failure\tfd\t5000\t10\t100\t3\t1\t0\t1\n"
        "arg\t2f62696e2f74727565\n"
        "env\t444953504c4159\t3a3234\n"
        "end\n"
        "component\tshell\tshell\t1\talways\texec\t1000\t20\t200\t4\t2\t1\t0\n"
        "arg\t2f62696e2f74727565\n"
        "arg\t2d2d68656c70\n"
        "after\tdisplay\n"
        "end\n";
}

std::string valid_v2_plan() {
    return
        "MSYS_NATIVE_LITE_PLAN\t2\n"
        "stop_grace_ms\t500\n"
        "profile\t74657374\t3a3234\t1\t0\t1\n"
        "role\t6c61756e63686572\t1\n"
        "provider\torg.test:launcher\n"
        "startup\torg.test:launcher\n"
        "component\torg.test:launcher\tshell\t1\ton-failure\tmipc-ready\t5000\t10\t100\t3\t1\t0\t0\tbackground\t0\t1\t1\t0\n"
        "arg\t2f62696e2f74727565\n"
        "provide\trole\t6c61756e63686572\t1\t50\n"
        "permission\t6d6970632e63616c6c3a6d7379732e636f7265\n"
        "package\t6f72672e74657374\t54657374\t31\t73797374656d\n"
        "metadata\t4c61756e63686572\t\t\n"
        "window\t783131\t696e6865726974\t77696e646f77\t\t\t\t\n"
        "end\n";
}

void test_valid_plan() {
    const auto plan = msys::native::lite::parse_runtime_plan(valid_plan());
    expect(plan.stop_grace_ms == 500U, "stop grace mismatch");
    expect(plan.components.size() == 2U, "component count mismatch");
    expect(plan.components[0U].kind == ComponentKind::display, "kind mismatch");
    expect(plan.components[0U].readiness == ReadinessMode::fd, "readiness mismatch");
    expect(plan.components[0U].restart == RestartPolicy::on_failure, "restart mismatch");
    expect(plan.components[0U].environment[0U].first == "DISPLAY", "env key mismatch");
    expect(plan.components[0U].environment[0U].second == ":24", "env value mismatch");
    expect(plan.components[1U].after == std::vector<std::string>{"display"}, "dependency mismatch");
}

void test_valid_v2_plan() {
    const auto plan = msys::native::lite::parse_runtime_plan(valid_v2_plan());
    expect(plan.profile_id == "test" && plan.display == ":24", "v2 profile mismatch");
    expect(plan.startup == std::vector<std::string>{"org.test:launcher"},
           "v2 startup mismatch");
    expect(plan.role_preferences.size() == 1U
               && plan.role_preferences[0U].role == "launcher",
           "v2 role preference mismatch");
    expect(plan.components.size() == 1U, "v2 component count mismatch");
    const auto& component = plan.components[0U];
    expect(component.lifecycle == Lifecycle::background, "v2 lifecycle mismatch");
    expect(component.readiness == ReadinessMode::mipc, "v2 readiness mismatch");
    expect(component.provides.size() == 1U
               && component.provides[0U].kind == ProvideKind::role,
           "v2 provide mismatch");
    expect(component.permissions == std::vector<std::string>{"mipc.call:msys.core"},
           "v2 permission mismatch");
    expect(component.window.system == "x11" && component.window.display == "inherit",
           "v2 window metadata mismatch");
}

template <typename Callback>
void expect_invalid(Callback callback, const char* message) {
    bool rejected = false;
    try {
        callback();
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    expect(rejected, message);
}

void test_invalid_plans() {
    expect_invalid(
        [] { (void)msys::native::lite::parse_runtime_plan("MSYS_NATIVE_LITE_PLAN\t2\n"); },
        "unknown header accepted");

    std::string relative = valid_plan();
    const std::size_t absolute = relative.find("2f62696e2f74727565");
    expect(absolute != std::string::npos, "fixture argument missing");
    relative.replace(absolute, 18U, "62696e2f74727565");
    expect_invalid(
        [&relative] { (void)msys::native::lite::parse_runtime_plan(relative); },
        "relative argv accepted");

    std::string cycle = valid_plan();
    const std::string old_header =
        "component\tdisplay\tdisplay\t1\ton-failure\tfd\t5000\t10\t100\t3\t1\t0\t1";
    const std::string new_header =
        "component\tdisplay\tdisplay\t1\ton-failure\tfd\t5000\t10\t100\t3\t1\t1\t1";
    const std::size_t header_offset = cycle.find(old_header);
    expect(header_offset != std::string::npos, "fixture header missing");
    cycle.replace(header_offset, old_header.size(), new_header);
    const std::size_t argument_end = cycle.find('\n', cycle.find("arg\t", header_offset));
    cycle.insert(argument_end + 1U, "after\tshell\n");
    expect_invalid(
        [&cycle] { (void)msys::native::lite::parse_runtime_plan(cycle); },
        "dependency cycle accepted");

    std::string non_ascii = valid_plan();
    const std::size_t id_offset = non_ascii.find("component\tdisplay\t");
    expect(id_offset != std::string::npos, "fixture component id missing");
    non_ascii.replace(
        id_offset,
        std::string{"component\tdisplay"}.size(),
        std::string{"component\t\xc3\xa9"});
    expect_invalid(
        [&non_ascii] { (void)msys::native::lite::parse_runtime_plan(non_ascii); },
        "non-ASCII component id accepted");
}

void write_all(int descriptor, const std::string& value) {
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const ssize_t count = ::write(
            descriptor, value.data() + offset, value.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            throw std::runtime_error("test plan write failed");
        }
        offset += static_cast<std::size_t>(count);
    }
}

void test_secure_file_loader() {
    char path[] = "/tmp/msys-native-lite-plan-XXXXXX";
    const int descriptor = ::mkstemp(path);
    expect(descriptor >= 0, "mkstemp failed");
    const std::string link_path = std::string{path} + ".link";
    write_all(descriptor, valid_plan());
    expect(::close(descriptor) == 0, "close fixture failed");
    try {
        expect(::chmod(path, 0666) == 0, "chmod insecure fixture failed");
        bool rejected = false;
        try {
            (void)msys::native::lite::load_runtime_plan_file(path);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        expect(rejected, "writable plan accepted");
        expect(::chmod(path, 0600) == 0, "chmod secure fixture failed");
        const auto plan = msys::native::lite::load_runtime_plan_file(path);
        expect(plan.components.size() == 2U, "secure plan did not load");

        expect(::symlink(path, link_path.c_str()) == 0, "symlink fixture failed");
        rejected = false;
        try {
            (void)msys::native::lite::load_runtime_plan_file(link_path);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        expect(rejected, "symlink plan accepted");
        expect(::unlink(link_path.c_str()) == 0, "unlink symlink fixture failed");
    } catch (...) {
        (void)::unlink(link_path.c_str());
        (void)::unlink(path);
        throw;
    }
    expect(::unlink(path) == 0, "unlink fixture failed");
}

}  // namespace

int main() {
    try {
        test_valid_plan();
        test_valid_v2_plan();
        test_invalid_plans();
        test_secure_file_loader();
        std::cout << "native-lite unit tests: ok\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "native-lite unit tests: " << error.what() << '\n';
        return 1;
    }
}
