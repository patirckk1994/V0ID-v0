#pragma once

#include "boolean_program_image.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace v0id::integrity {

struct Sha3_512ProgramImage {
    BooleanProgramImage program;
    std::size_t message_bytes{};
    std::size_t absorb_blocks{};
};

// Compact 64-bit lane program for fixed-length SHA3-512. The message contents
// are runtime input words; only the public message length affects construction.
Sha3_512ProgramImage build_sha3_512_program_image(std::size_t message_bytes);

// Apply SHA3 domain separation/padding and pack the rate blocks as little-endian
// 64-bit words. In RMJ3 these word bits become encrypted input tape data.
std::vector<std::uint64_t> sha3_512_program_input_words(
    const std::vector<std::uint8_t>& message);

// Plaintext oracle for the compact image, returning the 512-bit digest as bytes.
std::vector<std::uint8_t> evaluate_sha3_512_program_image(
    const Sha3_512ProgramImage& image,
    const std::vector<std::uint8_t>& message);

} // namespace v0id::integrity
