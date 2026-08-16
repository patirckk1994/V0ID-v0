#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace v0id::integrity {

// Compact pre-TM instruction image. Operations are 64-bit bit-slice primitives:
// the eventual binary TM interpreter still evaluates them bit-by-bit, but the
// private image remains small enough to plausibly live on encrypted RMJ3 tape.
enum class BooleanProgramOpcode : std::uint8_t {
    Xor2 = 0,
    Xor5 = 1,
    XorRot1 = 2,
    RotCopy = 3,
    Chi = 4,
    XorInput = 5,
    XorConst = 6,
};

struct BooleanProgramInstruction {
    BooleanProgramOpcode op{BooleanProgramOpcode::Xor2};
    std::uint8_t dst{};
    std::uint8_t a{};
    std::uint8_t b{};
    std::uint8_t c{};
    std::uint8_t d{};
    std::uint8_t e{};
    std::uint16_t input_index{};
    std::uint8_t rotate{};
    std::uint64_t immediate{};
};

struct BooleanProgramImage {
    // Compact v1 encoding reserves six bits per register id.
    std::size_t register_count{};
    std::size_t input_word_count{};
    std::vector<BooleanProgramInstruction> instructions;
    std::vector<std::uint8_t> output_registers;

    void validate() const;
};

struct BooleanProgramExecution {
    std::vector<std::uint64_t> registers;
    std::vector<std::uint64_t> output_words;
};

BooleanProgramExecution evaluate_boolean_program_image(
    const BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words);

// Compact LSB-first bit serialization intended to become encrypted runtime data,
// not evaluator-visible plaintext metadata. It deliberately contains the opcode
// stream and register topology so those details can be privately mutated before
// any core::Program-level polymorphism occurs.
std::vector<std::uint8_t> serialize_boolean_program_image_bits(
    const BooleanProgramImage& image);

struct BooleanProgramTapeLayout {
    std::size_t register_offset_bits{};
    std::size_t input_offset_bits{};
    std::size_t image_offset_bits{};
    std::size_t total_bits{};
};

struct PackedBooleanProgramTape {
    BooleanProgramTapeLayout layout;
    std::vector<int> bits;
};

// Plaintext layout oracle for the future <=128-state generic TM interpreter.
// Registers start zeroed, followed by input words and then the private image.
PackedBooleanProgramTape pack_boolean_program_tape(
    const BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words);

} // namespace v0id::integrity
