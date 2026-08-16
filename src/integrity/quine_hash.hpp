#pragma once

#include "program.hpp"
#include "series_generator.hpp"
#include "remote_machine_codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::integrity {

using AuditChallenge256 = std::array<std::uint8_t, 32>;
using QuineDigest512 = std::array<std::uint8_t, 64>;

// Plaintext client-side context committed by QuineHash512. This uses
// standardized SHA3-512/KMAC-256 through OpenSSL and binds the issuer's intended
// job image/context. It is a commitment, not evidence that a remote evaluator
// honestly performed every requested transition; execution-bound verification
// is handled by separate round-receipt/integrity experiments.
struct QuineHashContext {
    v0id::fhe::PublicMachineShape shape;
    v0id::fhe::CryptoProfileId profile;
    v0id::fhe::EvaluatorSessionId session_id{};
    std::string job_id;
    std::uint64_t epoch{};
    std::size_t initial_state{};
    std::size_t initial_head{};
    std::vector<int> initial_tape;

    // Private bindings close two composition gaps that the public profile alone
    // cannot close. semantic_binding commits to the issuer's unmorphed bounded
    // job; generator_binding commits to the exact local generator implementation
    // (including Wasm bytes when one is used). Neither has to be sent to the
    // evaluator in the current protocol.
    QuineDigest512 semantic_binding{};
    QuineDigest512 generator_binding{};
};

// KMAC-256 PRF challenge keyed directly by the private 256-bit series root, not
// by plugin-controlled morph output. Session/job/epoch binding prevents silent
// reuse across otherwise equivalent jobs. The challenge remains client-private.
AuditChallenge256 derive_audit_challenge256(
    const v0id::polymorph::SeriesSeed& private_root,
    const v0id::fhe::EvaluatorSessionId& session_id,
    const std::string& job_id,
    std::uint64_t epoch);

// Stable commitment to the issuer's bounded semantic job before polymorphism.
// This lets a quine bind the morphed executable image back to what the issuer
// intended to run without publishing the base program.
QuineDigest512 semantic_job_hash512(const v0id::core::Program& base_program,
                                    std::size_t initial_state,
                                    std::size_t initial_head,
                                    const std::vector<int>& initial_tape,
                                    std::uint64_t rounds);

// Commit to the generator profile and, when present, the exact local plugin
// bytes. For the built-in generator implementation_bytes is empty and the
// versioned profile itself identifies the implementation.
QuineDigest512 generator_binding512(
    const v0id::polymorph::SeriesProfile& profile,
    const std::vector<std::uint8_t>& implementation_bytes = {});

// SHA3-512 over a canonical, length-delimited representation of the complete
// morphed semantic job image, private semantic/generator bindings and 256-bit
// audit challenge. The canonical encoding includes a 64-byte all-zero digest
// slot. This defines self-reference without requiring a cryptographic fixed
// point: hash(object-with-digest-slot-zeroed).
QuineDigest512 quine_hash512(const v0id::core::Program& morphed_program,
                             const QuineHashContext& context,
                             const AuditChallenge256& challenge);

// Small reusable wrapper used by known-answer and composition regression tests.
// OpenSSL supplies SHA3; V0ID does not implement Keccak arithmetic here.
QuineDigest512 sha3_512_bytes(const std::vector<std::uint8_t>& bytes);

std::string hex_digest(const QuineDigest512& digest);
std::string hex_challenge(const AuditChallenge256& challenge);

} // namespace v0id::integrity
