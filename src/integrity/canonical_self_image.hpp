#pragma once

#include "program.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::integrity {

// Hash-agnostic canonical subject for the embedded execution-integrity path.
//
// IMPORTANT: this is the data to be hashed, NOT the hash algorithm itself.
// SHA3-512 can be the default strong backend while private-local hooks/modules
// synthesize a different implementation of the same hash, or a deployment may
// deliberately choose another approved backend at the algorithm-later stage.
struct CanonicalSelfImageContext {
    std::array<std::uint8_t, 32> session_id{};
    std::string job_id;
    std::uint64_t epoch{};

    std::string machine_protocol;
    std::string fhe_parameter_set;

    std::size_t initial_state{};
    std::size_t initial_head{};
    std::vector<int> initial_tape;

    std::size_t semantic_rounds{};
    std::size_t integrity_rounds{};
    std::size_t total_execution_rounds{};

    std::array<std::uint8_t, 64> semantic_binding{};
    std::array<std::uint8_t, 64> generator_binding{};

    // Issuer-private, series-derived integrity challenge/binding. It is part of
    // the hash subject but is intended to enter the remote job only encrypted as
    // data used by the embedded integrity computation.
    std::vector<std::uint8_t> private_integrity_challenge;

    // Output capacity, not an algorithm identifier. SHA3-512 naturally uses 64
    // bytes. The value is part of the canonical subject so output-shape changes
    // cannot be substituted silently.
    std::size_t digest_slot_bytes{64};
};

// Canonical byte encoding over a complete program image. It intentionally names
// no hash algorithm or local implementation.
std::vector<std::uint8_t> canonical_self_image_v1(
    const v0id::core::Program& program,
    const CanonicalSelfImageContext& context);

// Preferred self-hash form for the combined polymorphic machine. The caller
// supplies the FINAL morphed combined Program plus the morphed state ids occupied
// by the integrity/hash implementation. Those rows remain present in the fixed
// public shape but their transition payload is canonically zeroed. Thus the
// subject is "the rest of the final polymorphic TM minus the hash implementation"
// without requiring a cryptographic fixed point. The excluded-state positions
// themselves remain bound, while their private implementation does not.
std::vector<std::uint8_t> canonical_self_image_v1_masked(
    const v0id::core::Program& final_morphed_program,
    const std::vector<std::size_t>& excluded_integrity_states,
    const CanonicalSelfImageContext& context);

// Exact MSB-first bit expansions. The encrypted integrity program must consume
// the same bit ordering as the client reference implementation.
std::vector<int> canonical_self_image_bits_v1(
    const v0id::core::Program& program,
    const CanonicalSelfImageContext& context);

std::vector<int> canonical_self_image_bits_v1_masked(
    const v0id::core::Program& final_morphed_program,
    const std::vector<std::size_t>& excluded_integrity_states,
    const CanonicalSelfImageContext& context);

} // namespace v0id::integrity
