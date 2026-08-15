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
// The caller supplies the non-integrity/self-hash-excluded Program image. That
// keeps SHA3/KMAC or a user-supplied private hash implementation replaceable at
// the later algorithm-selection stage without changing the canonical subject.
//
// A private local strategy/hash module may therefore synthesize or transform the
// integrity implementation before the final whole-machine polymorphic pass. The
// module bytes/semantic labels are not part of this format and need not be sent
// to the evaluator. If a deployment wants to commit to the exact final combined
// executable image as well, QuineHash512 remains the separate issuer-side image
// commitment.
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

    // Public output capacity, not an algorithm identifier. SHA3-512 naturally
    // uses 64 bytes, while a private implementation may use another algorithm
    // provided it fits the configured fixed-shape output contract.
    std::size_t digest_slot_bytes{64};
};

// Canonical byte encoding. It intentionally does not contain a SHA3/KMAC/name or
// implementation id: series-first material exists before algorithm selection.
std::vector<std::uint8_t> canonical_self_image_v1(
    const v0id::core::Program& non_integrity_program,
    const CanonicalSelfImageContext& context);

// Exact MSB-first bit expansion of canonical_self_image_v1(), useful for a
// future encrypted TM/circuit that consumes the same canonical subject bit-for-
// bit as the client's plaintext hash implementation.
std::vector<int> canonical_self_image_bits_v1(
    const v0id::core::Program& non_integrity_program,
    const CanonicalSelfImageContext& context);

} // namespace v0id::integrity
