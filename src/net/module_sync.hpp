#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::net {

using ModuleDigest512 = std::array<std::uint8_t, 64>;

enum class ModuleKind : std::uint8_t {
    strategy_wasm = 1,
    mathvm_wasm = 2,
    polymorphism_wasm = 3,
};

enum class ModuleVisibility : std::uint8_t {
    private_local = 1,
    shared_sync = 2,
};

struct ModuleDescriptor {
    std::string protocol_id{"v0id-module-sync-v1"};
    ModuleKind kind{ModuleKind::strategy_wasm};
    ModuleVisibility visibility{ModuleVisibility::private_local};
    std::string module_id;
    std::uint64_t module_version{1};
    std::uint64_t byte_size{};
    ModuleDigest512 digest{};
};

struct ModuleBundle {
    ModuleDescriptor descriptor;
    std::vector<std::uint8_t> bytes;
};

// Uses OpenSSL SHA3-512; V0ID does not implement a custom module hash.
ModuleDigest512 module_digest512(const std::vector<std::uint8_t>& bytes);

ModuleDescriptor describe_module(ModuleKind kind,
                                 ModuleVisibility visibility,
                                 const std::string& module_id,
                                 std::uint64_t module_version,
                                 const std::vector<std::uint8_t>& bytes);

// Canonical, order-independent commitment to the exact shared module set
// expected by a session/job. Duplicate (kind,id,version) identities fail closed.
// Feed this digest into SeriesFirstStackContext::shared_modules_binding.
ModuleDigest512 shared_module_set_digest512(
    const std::vector<ModuleDescriptor>& descriptors);

// Canonical content-addressed transport representation. Private-local modules
// fail closed here and cannot accidentally be serialized onto the network.
std::vector<std::uint8_t> encode_shared_module_bundle(const ModuleBundle& bundle);
ModuleBundle decode_shared_module_bundle(const void* data,
                                         std::size_t size,
                                         std::size_t max_module_bytes = 1024 * 1024);

void verify_module_bundle(const ModuleBundle& bundle,
                          std::size_t max_module_bytes = 1024 * 1024,
                          bool require_shared = true);

std::string module_digest_hex(const ModuleDigest512& digest);
std::string to_string(ModuleKind kind);
std::string to_string(ModuleVisibility visibility);

} // namespace v0id::net
