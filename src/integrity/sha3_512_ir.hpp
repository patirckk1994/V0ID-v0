#pragma once

#include "boolean_ir.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace v0id::integrity {

inline constexpr std::size_t kSha3_512RateBytes = 72;
inline constexpr std::size_t kSha3_512DigestBytes = 64;

// Fixed-length SHA3-512 Boolean circuit. Message length is public construction
// metadata; message contents remain Boolean inputs. This matches V0ID's intended
// private local compiler model, where the subject shape is known before the
// integrity Program is encrypted.
struct Sha3_512IR {
    BooleanIR ir;
    std::size_t message_bytes{};
    std::size_t absorb_blocks{};
};

Sha3_512IR build_sha3_512_ir(std::size_t message_bytes);

// Conversion helpers use SHA3/Keccak's little-endian bit numbering within each
// byte. They are deliberately separate from the IR so tests and callers can
// compare against byte-oriented reference implementations.
std::vector<std::uint8_t> bytes_to_lsb_bits(
    const std::vector<std::uint8_t>& bytes);
std::vector<std::uint8_t> lsb_bits_to_bytes(
    const std::vector<std::uint8_t>& bits);

} // namespace v0id::integrity
