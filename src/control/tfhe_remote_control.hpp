#pragma once

#include <filesystem>
#include <memory>
#include <stop_token>

namespace v0id::control {

// GPU-build companion to LocalControlPlane. It consumes a separate
// cloud_commands/ queue and publishes cloud_state.json so the local web UI can
// submit encrypted BooleanProgramImage jobs to an existing remote TFHE evaluator
// without making the dashboard itself remote-facing.
class TfheRemoteControl {
public:
    explicit TfheRemoteControl(std::filesystem::path runtime_root);
    ~TfheRemoteControl();

    TfheRemoteControl(const TfheRemoteControl&) = delete;
    TfheRemoteControl& operator=(const TfheRemoteControl&) = delete;
    TfheRemoteControl(TfheRemoteControl&&) noexcept;
    TfheRemoteControl& operator=(TfheRemoteControl&&) noexcept;

    void initialize();
    bool process_one();
    void run(std::stop_token stop_token);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace v0id::control
