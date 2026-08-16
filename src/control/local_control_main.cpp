#include "local_control.hpp"

#ifdef V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD
#include "tfhe_remote_control.hpp"
#endif

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace {

void usage(const char* argv0) {
    std::cerr
        << "usage: " << argv0 << " <runtime-directory>\n\n"
        << "The daemon publishes <runtime-directory>/state.json and consumes\n"
        << "atomic JSON commands from <runtime-directory>/commands/.\n"
#ifdef V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD
        << "GPU builds also publish cloud_state.json and consume encrypted remote\n"
        << "job commands from <runtime-directory>/cloud_commands/.\n"
#endif
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

#ifdef V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD
    v0id::control::TfheRemoteControl remote_cloud(runtime_root);
    remote_cloud.initialize();
    std::jthread remote_thread([&](std::stop_token stop_token) {
        remote_cloud.run(stop_token);
    });
#endif

    std::cout << "V0ID local JSON control plane\n"
              << "runtime root : " << control.runtime_root() << '\n'
              << "state        : " << (control.runtime_root() / "state.json") << '\n'
              << "commands     : " << (control.runtime_root() / "commands") << '\n'
              << "responses    : " << (control.runtime_root() / "responses") << '\n'
#ifdef V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD
              << "cloud state  : " << (control.runtime_root() / "cloud_state.json") << '\n'
              << "cloud jobs   : " << (control.runtime_root() / "cloud_commands") << '\n'
              << "remote TFHE  : ENABLED (local UI -> encrypted remote evaluator)\n"
#else
              << "remote TFHE  : disabled in this build\n"
#endif
              << "private root : process-local C++ memory only\n"
              << "status       : waiting for local commands...\n"
              << std::flush;

    control.run_forever();
#ifdef V0ID_LOCAL_CONTROL_HAVE_TFHE_CLOUD
    remote_thread.request_stop();
#endif
    std::cout << "V0ID local control plane stopped\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID local control plane FAILED: " << e.what() << '\n';
    return 1;
}
