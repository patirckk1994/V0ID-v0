#include "local_control.hpp"

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>

namespace {

void usage(const char* argv0) {
    std::cerr
        << "usage: " << argv0 << " <runtime-directory>\n\n"
        << "The daemon publishes <runtime-directory>/state.json and consumes\n"
        << "atomic JSON commands from <runtime-directory>/commands/.\n"
        << "Run the PHP frontend with V0ID_CONTROL_ROOT pointing at the same\n"
        << "directory. Keep that directory outside the HTTP document root.\n";
}

} // namespace

int main(int argc, char** argv) try {
    if (argc != 2) {
        usage(argv[0]);
        return 2;
    }

    const std::filesystem::path runtime_root = argv[1];
    v0id::control::LocalControlPlane control(runtime_root);
    control.initialize();

    std::cout << "V0ID local JSON control plane\n"
              << "runtime root : " << control.runtime_root() << '\n'
              << "state        : " << (control.runtime_root() / "state.json") << '\n'
              << "commands     : " << (control.runtime_root() / "commands") << '\n'
              << "responses    : " << (control.runtime_root() / "responses") << '\n'
              << "private root : process-local C++ memory only\n"
              << "status       : waiting for local commands...\n"
              << std::flush;

    control.run_forever();
    std::cout << "V0ID local control plane stopped\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID local control plane FAILED: " << e.what() << '\n';
    return 1;
}
