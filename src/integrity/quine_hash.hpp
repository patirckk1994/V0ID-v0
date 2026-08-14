#pragma once

#include "program.hpp"
#include "program_morpher.hpp"
#include "remote_machine_codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::integrity {

using AuditChallenge256 = std::array<std::uint8_t, 32>;
using QuineDigest512 = std::array<std::uint8_t, 64>;

// Plaintext client-side context committed by QuineHash512. This is deliberately
// separate from the toy FHE fingerprint. The quine commitment uses standardized
// SHA3-512/KMAC-256 through OpenSSL; it does not claim to prove remote execution.
struct QuineHashContext {
    v0id::fhe::PublicMachineShape shape;
    v0id::fhe::CryptoProfileId profile;
    v0id::fhe::EvaluatorSessionId session_id{};
    std::string job_id;
    std::uint64_t epoch{};
    std::size_t initial_state{};
    std::size_t initial_head{};
    std::vector<int> initial_tape;
};

// KMAC-256 PRF challenge. MorphSeed is the 256-bit client-side key. Session/job
// binding prevents a challenge from being silently reused across otherwise
// equivalent jobs. The challenge remains client-private in the current protocol.
AuditChallenge256 derive_audit_challenge256(
    const v0id::polymorph::MorphSeed& morph_seed,
    const v0id::fhe::EvaluatorSessionId& session_id,
    const std::string& job_id,
    std::uint64_t epoch);

// SHA3-512 over a canonical, length-delimited representation of the complete
// morphed semantic job image and 256-bit audit challenge. The canonical encoding
// includes a 64-byte all-zero digest slot. This defines self-reference without
// requiring a cryptographic fixed point: hash(object-with-digest-slot-zeroed).
QuineDigest512 quine_hash512(const v0id::core::Program& morphed_program,
                             const QuineHashContext& context,
                             const AuditChallenge256& challenge);

// Small reusable wrapper used by the known-answer regression test and audit
// harness. OpenSSL supplies the SHA3 implementation; V0ID does not implement
// Keccak arithmetic here.
QuineDigest512 sha3_512_bytes(const std::vector<std::uint8_t>& bytes);

std::string hex_digest(const QuineDigest512& digest);
std::string hex_challenge(const AuditChallenge256& challenge);

} // namespace v0id::integrity
