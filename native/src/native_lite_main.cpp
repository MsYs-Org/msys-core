#include "msys/native_lite.hpp"

#include <exception>
#include <iostream>
#include <optional>
#include <string>

namespace {

void usage(std::ostream& output) {
    output
        << "usage: msysd-native-lite --plan FILE [--runtime-dir DIR] "
           "[--check-plan] [--report-rss]\n"
        << "\n"
        << "Bounded native process supervisor. The runtime consumes a compiled\n"
        << "MSYS_NATIVE_LITE_PLAN v1 file. --runtime-dir enables the phase-3\n"
        << "mIPC lifecycle subset; package discovery, roles, HAL selection,\n"
        << "install/update, and the full msysd APIs remain out of scope.\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::optional<std::string> plan_path;
    bool check_plan = false;
    bool report_rss = false;
    std::optional<std::string> runtime_dir;
    for (int index = 1; index < argc; ++index) {
        const std::string argument{argv[index]};
        if (argument == "--help" || argument == "-h") {
            usage(std::cout);
            return 0;
        }
        if (argument == "--version") {
            std::cout << "msysd-native-lite 0.1\n";
            return 0;
        }
        if (argument == "--check-plan") {
            check_plan = true;
            continue;
        }
        if (argument == "--report-rss") {
            report_rss = true;
            continue;
        }
        if (argument == "--runtime-dir") {
            if (runtime_dir.has_value() || index + 1 >= argc) {
                std::cerr << "msysd-native-lite: --runtime-dir requires one directory\n";
                return 2;
            }
            ++index;
            runtime_dir = std::string{argv[index]};
            continue;
        }
        if (argument == "--plan") {
            if (plan_path.has_value() || index + 1 >= argc) {
                std::cerr << "msysd-native-lite: --plan requires one file\n";
                return 2;
            }
            ++index;
            plan_path = std::string{argv[index]};
            continue;
        }
        std::cerr << "msysd-native-lite: unknown argument: " << argument << '\n';
        usage(std::cerr);
        return 2;
    }
    if (!plan_path.has_value()) {
        std::cerr << "msysd-native-lite: --plan is required\n";
        usage(std::cerr);
        return 2;
    }

    try {
        auto plan = msys::native::lite::load_runtime_plan_file(*plan_path);
        if (check_plan) {
            std::cout << "msysd-native-lite: plan ok components="
                      << plan.components.size() << '\n';
            if (report_rss) {
                std::cout << "msysd-native-lite: supervisor_rss_kib="
                          << msys::native::lite::current_rss_kib() << '\n';
            }
            return 0;
        }
        msys::native::lite::Supervisor supervisor{
            std::move(plan),
            msys::native::lite::SupervisorOptions{report_rss, std::move(runtime_dir)},
        };
        return supervisor.run();
    } catch (const std::exception& error) {
        std::cerr << "msysd-native-lite: " << error.what() << '\n';
        return 2;
    }
}
