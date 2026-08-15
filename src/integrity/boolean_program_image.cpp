#include "boolean_program_image.hpp"

#include <bit>
#include <limits>
#include <stdexcept>

namespace v0id::integrity {
namespace {

void require_register(const BooleanProgramImage& image,
                      std::uint8_t reg,
                      const char* what) {
    if (reg >= image.register_count)
        throw std::runtime_error(what);
}

void put_bits(std::vector<std::uint8_t>& out,
              std::uint64_t value,
              std::size_t width) {
    for (std::size_t i = 0; i < width; ++i)
        out.push_back(static_cast<std::uint8_t>((value >> i) & 1u));
}

void put_reg(std::vector<std::uint8_t>& out, std::uint8_t reg) {
    put_bits(out, reg, 6);
}

} // namespace

void BooleanProgramImage::validate() const {
    if (register_count == 0 || register_count > 64)
        throw std::runtime_error("boolean program register count must be in [1,64]");
    if (input_word_count > std::numeric_limits<std::uint16_t>::max())
        throw std::runtime_error("boolean program input word count exceeds v1 encoding");
    if (instructions.empty())
        throw std::runtime_error("boolean program image has no instructions");
    if (instructions.size() > std::numeric_limits<std::uint16_t>::max())
        throw std::runtime_error("boolean program instruction count exceeds v1 encoding");
    if (output_registers.empty() || output_registers.size() > 64)
        throw std::runtime_error("boolean program output register count invalid");

    for (const auto reg : output_registers)
        require_register(*this, reg, "boolean program output register out of range");

    for (const auto& ins : instructions) {
        require_register(*this, ins.dst, "boolean program destination register out of range");
        switch (ins.op) {
        case BooleanProgramOpcode::Xor2:
            require_register(*this, ins.a, "boolean program xor a out of range");
            require_register(*this, ins.b, "boolean program xor b out of range");
            break;
        case BooleanProgramOpcode::Xor5:
            require_register(*this, ins.a, "boolean program xor5 a out of range");
            require_register(*this, ins.b, "boolean program xor5 b out of range");
            require_register(*this, ins.c, "boolean program xor5 c out of range");
            require_register(*this, ins.d, "boolean program xor5 d out of range");
            require_register(*this, ins.e, "boolean program xor5 e out of range");
            break;
        case BooleanProgramOpcode::XorRot1:
            require_register(*this, ins.a, "boolean program xorrot a out of range");
            require_register(*this, ins.b, "boolean program xorrot b out of range");
            break;
        case BooleanProgramOpcode::RotCopy:
            require_register(*this, ins.a, "boolean program rot source out of range");
            if (ins.rotate >= 64)
                throw std::runtime_error("boolean program rotation out of range");
            break;
        case BooleanProgramOpcode::Chi:
            require_register(*this, ins.a, "boolean program chi a out of range");
            require_register(*this, ins.b, "boolean program chi b out of range");
            require_register(*this, ins.c, "boolean program chi c out of range");
            break;
        case BooleanProgramOpcode::XorInput:
            require_register(*this, ins.a, "boolean program xor-input source out of range");
            if (ins.input_index >= input_word_count)
                throw std::runtime_error("boolean program input word index out of range");
            break;
        case BooleanProgramOpcode::XorConst:
            require_register(*this, ins.a, "boolean program xor-const source out of range");
            break;
        }
    }
}

BooleanProgramExecution evaluate_boolean_program_image(
    const BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words) {
    image.validate();
    if (input_words.size() != image.input_word_count)
        throw std::runtime_error("boolean program input word count mismatch");

    BooleanProgramExecution out;
    out.registers.assign(image.register_count, 0);

    for (const auto& ins : image.instructions) {
        auto& dst = out.registers[ins.dst];
        switch (ins.op) {
        case BooleanProgramOpcode::Xor2:
            dst = out.registers[ins.a] ^ out.registers[ins.b];
            break;
        case BooleanProgramOpcode::Xor5:
            dst = out.registers[ins.a] ^ out.registers[ins.b] ^
                  out.registers[ins.c] ^ out.registers[ins.d] ^
                  out.registers[ins.e];
            break;
        case BooleanProgramOpcode::XorRot1:
            dst = out.registers[ins.a] ^ std::rotl(out.registers[ins.b], 1);
            break;
        case BooleanProgramOpcode::RotCopy:
            dst = std::rotl(out.registers[ins.a], static_cast<int>(ins.rotate));
            break;
        case BooleanProgramOpcode::Chi:
            dst = out.registers[ins.a] ^
                  ((~out.registers[ins.b]) & out.registers[ins.c]);
            break;
        case BooleanProgramOpcode::XorInput:
            dst = out.registers[ins.a] ^ input_words[ins.input_index];
            break;
        case BooleanProgramOpcode::XorConst:
            dst = out.registers[ins.a] ^ ins.immediate;
            break;
        }
    }

    out.output_words.reserve(image.output_registers.size());
    for (const auto reg : image.output_registers)
        out.output_words.push_back(out.registers[reg]);
    return out;
}

std::vector<std::uint8_t> serialize_boolean_program_image_bits(
    const BooleanProgramImage& image) {
    image.validate();

    std::vector<std::uint8_t> out;
    out.reserve(image.instructions.size() * 32);

    // V0ID Boolean Program Image v1, compact LSB-first header.
    put_bits(out, 0xb017u, 16);
    put_bits(out, 1u, 4);
    put_bits(out, image.register_count - 1, 6);
    put_bits(out, image.input_word_count, 16);
    put_bits(out, image.instructions.size(), 16);
    put_bits(out, image.output_registers.size() - 1, 6);
    for (const auto reg : image.output_registers)
        put_reg(out, reg);

    for (const auto& ins : image.instructions) {
        put_bits(out, static_cast<std::uint8_t>(ins.op), 3);
        put_reg(out, ins.dst);
        switch (ins.op) {
        case BooleanProgramOpcode::Xor2:
            put_reg(out, ins.a);
            put_reg(out, ins.b);
            break;
        case BooleanProgramOpcode::Xor5:
            put_reg(out, ins.a);
            put_reg(out, ins.b);
            put_reg(out, ins.c);
            put_reg(out, ins.d);
            put_reg(out, ins.e);
            break;
        case BooleanProgramOpcode::XorRot1:
            put_reg(out, ins.a);
            put_reg(out, ins.b);
            break;
        case BooleanProgramOpcode::RotCopy:
            put_reg(out, ins.a);
            put_bits(out, ins.rotate, 6);
            break;
        case BooleanProgramOpcode::Chi:
            put_reg(out, ins.a);
            put_reg(out, ins.b);
            put_reg(out, ins.c);
            break;
        case BooleanProgramOpcode::XorInput:
            put_reg(out, ins.a);
            put_bits(out, ins.input_index, 16);
            break;
        case BooleanProgramOpcode::XorConst:
            put_reg(out, ins.a);
            put_bits(out, ins.immediate, 64);
            break;
        }
    }
    return out;
}

PackedBooleanProgramTape pack_boolean_program_tape(
    const BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words) {
    image.validate();
    if (input_words.size() != image.input_word_count)
        throw std::runtime_error("boolean program tape input word count mismatch");

    const auto image_bits = serialize_boolean_program_image_bits(image);
    PackedBooleanProgramTape out;
    out.layout.register_offset_bits = 0;
    out.layout.input_offset_bits = image.register_count * 64;
    out.layout.image_offset_bits = out.layout.input_offset_bits + input_words.size() * 64;
    out.layout.total_bits = out.layout.image_offset_bits + image_bits.size();
    out.bits.reserve(out.layout.total_bits);

    out.bits.insert(out.bits.end(), image.register_count * 64, 0);
    for (const auto word : input_words) {
        for (std::size_t bit = 0; bit < 64; ++bit)
            out.bits.push_back(static_cast<int>((word >> bit) & 1u));
    }
    for (const auto bit : image_bits)
        out.bits.push_back(static_cast<int>(bit));
    return out;
}

} // namespace v0id::integrity
