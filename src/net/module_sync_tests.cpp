#include "module_sync.hpp"
#include "peer_transport.hpp"

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

    v0id::net::Envelope envelope;
    envelope.type = v0id::net::MessageType::module_blob;
    envelope.peer_id = "CLIENT";
    envelope.job_id = "module-sync-test";
    envelope.epoch = 7;
    envelope.payload = wire;
    const auto envelope_wire = envelope.encode();
    const auto received_envelope = v0id::net::Envelope::decode(
        envelope_wire.data(), envelope_wire.size());
    const auto received_bundle = v0id::net::decode_shared_module_bundle(
        received_envelope.payload.data(), received_envelope.payload.size());
    r.check(received_envelope.type == v0id::net::MessageType::module_blob &&
            received_bundle.descriptor.digest == desc.digest &&
            received_bundle.bytes == bytes,
            "shared module survives V0IDNET1 MODULE_BLOB transport framing");

    auto second_bytes = bytes;
    second_bytes.push_back(0x42);
    const auto second_desc = v0id::net::describe_module(
        v0id::net::ModuleKind::mathvm_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "v0id.mathvm.shared.example", 3, second_bytes);
    const auto set_ab = v0id::net::shared_module_set_digest512({desc, second_desc});
    const auto set_ba = v0id::net::shared_module_set_digest512({second_desc, desc});
    r.check(set_ab == set_ba,
            "shared module-set binding is canonical and order-independent");

    auto changed_bytes = bytes;
    changed_bytes.back() ^= 1u;
    const auto changed_desc = v0id::net::describe_module(
        v0id::net::ModuleKind::strategy_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "v0id.stack.strategy.example", 1, changed_bytes);
    r.check(changed_desc.digest != desc.digest,
            "one-byte module substitution changes content identity");
    r.check(v0id::net::shared_module_set_digest512({changed_desc, second_desc}) != set_ab,
            "one-byte module substitution changes shared module-set binding");

    bool duplicate_identity_rejected = false;
    try {
        (void)v0id::net::shared_module_set_digest512({desc, changed_desc});
    } catch (const std::runtime_error&) {
        duplicate_identity_rejected = true;
    }
    r.check(duplicate_identity_rejected,
            "duplicate shared module kind/id/version fails closed");

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

    bool private_set_rejected = false;
    try {
        (void)v0id::net::shared_module_set_digest512({private_desc});
    } catch (const std::runtime_error&) {
        private_set_rejected = true;
    }
    r.check(private_set_rejected,
            "private-local module cannot enter shared module-set binding");

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
                 "the expected module-set digest must be bound by the application/session, "
                 "and WAMR/MathVM must still sandbox executable modules.\n";
    return r.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID module sync test fatal error: " << e.what() << '\n';
    return 1;
}
