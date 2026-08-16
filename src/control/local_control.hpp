#pragma once

#include <filesystem>
#include <memory>

namespace v0id::control {

// Filesystem-backed local administrative bridge. The control plane owns the
// authoritative C++ state; web/front-end processes only exchange bounded JSON
// commands and immutable state snapshots through the configured runtime root.
//
// Directory ABI (v1):
//   state.json              atomic read-only snapshot for frontends
//   registry.json           daemon-owned persistent module/binding config
//   commands/*.json         atomically-created frontend commands
//   responses/*.json        one response per command id
//   uploads/*                untrusted local module upload staging
//   modules/<digest>.wasm   daemon-verified content-addressed module bytes
//
// Secret SeriesSeed material is intentionally process-local and never serialized
// into this control directory.
class LocalControlPlane {
public:
    explicit LocalControlPlane(std::filesystem::path runtime_root);
    ~LocalControlPlane();

    LocalControlPlane(const LocalControlPlane&) = delete;
    LocalControlPlane& operator=(const LocalControlPlane&) = delete;
    LocalControlPlane(LocalControlPlane&&) noexcept;
    LocalControlPlane& operator=(LocalControlPlane&&) noexcept;

    // Creates/validates the runtime directory, loads persisted module metadata,
    // generates a process-local issuer-private SeriesSeed and publishes state.
    void initialize();

    // Processes at most one queued JSON command. Returns true when a command was
    // consumed. This is useful for embedding the control plane in another event
    // loop later instead of requiring the standalone daemon.
    bool process_one();

    // Simple standalone polling loop used by v0id-local-control.
    void run_forever();
    void request_stop() noexcept;

    const std::filesystem::path& runtime_root() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace v0id::control
