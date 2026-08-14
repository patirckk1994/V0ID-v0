#include "module_sync.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct Runner {
    int passed{};
    int failed{};
    void check(bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    }
};

std::vector<std::uint8_t> fake_wasm() {
    // Ordinary Wasm magic/version followed by deterministic test bytes. This
    // codec test does not execute or validate the module; WAMR owns that layer.
    return {0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
            0x56,0x30,0x49,0x44,0x2d,0x4d,0x4f,0x44};
}

} // namespace

int main() try {
    Runner r;
    const auto bytes = fake_wasm();

    const auto desc = v0id::net::describe_module(
        v0id::net::ModuleKind::strategy_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "v0id.stack.strategy.example", 1, bytes);
    const auto desc2 = v0id::net::describe_module(
        v0id::net::ModuleKind::strategy_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "v0id.stack.strategy.example", 1, bytes);
    r.check(desc.digest == desc2.digest,
            "module SHA3-512 identity is deterministic");

    v0id::net::ModuleBundle bundle{desc, bytes};
    const auto wire = v0id::net::encode_shared_module_bundle(bundle);
    const auto decoded = v0id::net::decode_shared_module_bundle(
        wire.data(), wire.size());
    r.check(decoded.descriptor.module_id == desc.module_id &&
            decoded.descriptor.module_version == desc.module_version &&
            decoded.descriptor.digest == desc.digest &&
            decoded.bytes == bytes,
            "shared module bundle round-trips exactly");

    auto changed_bytes = bytes;
    changed_bytes.back() ^= 1u;
    const auto changed_desc = v0id::net::describe_module(
        v0id::net::ModuleKind::strategy_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "v0id.stack.strategy.example", 1, changed_bytes);
    r.check(changed_desc.digest != desc.digest,
            "one-byte module substitution changes content identity");

    auto tampered_wire = wire;
    tampered_wire.back() ^= 1u;
    bool tamper_rejected = false;
    try {
        (void)v0id::net::decode_shared_module_bundle(
            tampered_wire.data(), tampered_wire.size());
    } catch (const std::runtime_error&) {
        tamper_rejected = true;
    }
    r.check(tamper_rejected,
            "module byte tampering fails SHA3-512 verification");

    const auto private_desc = v0id::net::describe_module(
        v0id::net::ModuleKind::polymorphism_wasm,
        v0id::net::ModuleVisibility::private_local,
        "v0id.private.polymorph", 1, bytes);
    bool private_rejected = false;
    try {
        (void)v0id::net::encode_shared_module_bundle(
            v0id::net::ModuleBundle{private_desc, bytes});
    } catch (const std::runtime_error&) {
        private_rejected = true;
    }
    r.check(private_rejected,
            "private-local polymorphism module cannot be serialized for sync");

    auto wrong_size = bundle;
    ++wrong_size.descriptor.byte_size;
    bool wrong_size_rejected = false;
    try {
        v0id::net::verify_module_bundle(wrong_size);
    } catch (const std::runtime_error&) {
        wrong_size_rejected = true;
    }
    r.check(wrong_size_rejected,
            "module descriptor size mismatch fails closed");

    auto wrong_hash = bundle;
    wrong_hash.descriptor.digest[0] ^= 1u;
    bool wrong_hash_rejected = false;
    try {
        v0id::net::verify_module_bundle(wrong_hash);
    } catch (const std::runtime_error&) {
        wrong_hash_rejected = true;
    }
    r.check(wrong_hash_rejected,
            "module descriptor digest mismatch fails closed");

    std::cout << "\nV0ID module sync tests: "
              << r.passed << " passed, " << r.failed << " failed\n"
              << "NOTE: synchronization verifies module identity/visibility only; "
                 "WAMR/MathVM must still sandbox and validate executable modules.\n";
    return r.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID module sync test fatal error: " << e.what() << '\n';
    return 1;
}
