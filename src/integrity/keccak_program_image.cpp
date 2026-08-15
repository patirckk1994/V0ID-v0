#include "keccak_program_image.hpp"

#include "sha3_512_ir.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace v0id::integrity {
namespace {

constexpr std::array<std::uint64_t, 24> kRoundConstants{
    0x0000000000000001ull, 0x0000000000008082ull,
    0x800000000000808aull, 0x8000000080008000ull,
    0x000000000000808bull, 0x0000000080000001ull,
    0x8000000080008081ull, 0x8000000000008009ull,
    0x000000000000008aull, 0x0000000000000088ull,
    0x0000000080008009ull, 0x000000008000000aull,
    0x000000008000808bull, 0x800000000000008bull,
    0x8000000000008089ull, 0x8000000000008003ull,
    0x8000000000008002ull, 0x8000000000000080ull,
    0x000000000000800aull, 0x800000008000000aull,
    0x8000000080008081ull, 0x8000000000008080ull,
    0x0000000080000001ull, 0x8000000080008008ull,
};

constexpr std::array<std::array<std::uint8_t, 5>, 5> kRho{
    std::array<std::uint8_t, 5>{0, 36, 3, 41, 18},
    std::array<std::uint8_t, 5>{1, 44, 10, 45, 2},
    std::array<std::uint8_t, 5>{62, 6, 43, 15, 61},
    std::array<std::uint8_t, 5>{28, 55, 25, 21, 56},
    std::array<std::uint8_t, 5>{27, 20, 39, 8, 14},
};

constexpr std::uint8_t state_reg(std::size_t x, std::size_t y) {
    return static_cast<std::uint8_t>(x + 5 * y);
}
constexpr std::uint8_t c_reg(std::size_t x) {
    return static_cast<std::uint8_t>(25 + x);
}
constexpr std::uint8_t d_reg(std::size_t x) {
    return static_cast<std::uint8_t>(30 + x);
}
constexpr std::uint8_t b_reg(std::size_t x, std::size_t y) {
    return static_cast<std::uint8_t>(35 + x + 5 * y);
}

BooleanProgramInstruction xor2(std::uint8_t dst, std::uint8_t a, std::uint8_t b) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::Xor2;
    i.dst = dst; i.a = a; i.b = b;
    return i;
}

BooleanProgramInstruction xor5(std::uint8_t dst,
                               std::uint8_t a, std::uint8_t b,
                               std::uint8_t c, std::uint8_t d,
                               std::uint8_t e) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::Xor5;
    i.dst = dst; i.a = a; i.b = b; i.c = c; i.d = d; i.e = e;
    return i;
}

BooleanProgramInstruction xorrot1(std::uint8_t dst,
                                  std::uint8_t a, std::uint8_t b) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::XorRot1;
    i.dst = dst; i.a = a; i.b = b;
    return i;
}

BooleanProgramInstruction rotcopy(std::uint8_t dst,
                                  std::uint8_t a,
                                  std::uint8_t rotate) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::RotCopy;
    i.dst = dst; i.a = a; i.rotate = rotate;
    return i;
}

BooleanProgramInstruction chi(std::uint8_t dst,
                              std::uint8_t a,
                              std::uint8_t b,
                              std::uint8_t c) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::Chi;
    i.dst = dst; i.a = a; i.b = b; i.c = c;
    return i;
}

BooleanProgramInstruction xorinput(std::uint8_t dst,
                                   std::uint8_t a,
                                   std::uint16_t input_index) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::XorInput;
    i.dst = dst; i.a = a; i.input_index = input_index;
    return i;
}

BooleanProgramInstruction xorconst(std::uint8_t dst,
                                   std::uint8_t a,
                                   std::uint64_t value) {
    BooleanProgramInstruction i;
    i.op = BooleanProgramOpcode::XorConst;
    i.dst = dst; i.a = a; i.immediate = value;
    return i;
}

void emit_keccak_f1600(BooleanProgramImage& p) {
    for (std::size_t round = 0; round < 24; ++round) {
        // theta
        for (std::size_t x = 0; x < 5; ++x) {
            p.instructions.push_back(xor5(
                c_reg(x),
                state_reg(x, 0), state_reg(x, 1), state_reg(x, 2),
                state_reg(x, 3), state_reg(x, 4)));
        }
        for (std::size_t x = 0; x < 5; ++x) {
            p.instructions.push_back(xorrot1(
                d_reg(x), c_reg((x + 4) % 5), c_reg((x + 1) % 5)));
        }
        for (std::size_t y = 0; y < 5; ++y) {
            for (std::size_t x = 0; x < 5; ++x)
                p.instructions.push_back(xor2(
                    state_reg(x, y), state_reg(x, y), d_reg(x)));
        }

        // rho + pi. B[y, 2x+3y] = ROT(A[x,y], rho[x,y]).
        for (std::size_t y = 0; y < 5; ++y) {
            for (std::size_t x = 0; x < 5; ++x) {
                const auto bx = y;
                const auto by = (2 * x + 3 * y) % 5;
                p.instructions.push_back(rotcopy(
                    b_reg(bx, by), state_reg(x, y), kRho[x][y]));
            }
        }

        // chi
        for (std::size_t y = 0; y < 5; ++y) {
            for (std::size_t x = 0; x < 5; ++x) {
                p.instructions.push_back(chi(
                    state_reg(x, y),
                    b_reg(x, y),
                    b_reg((x + 1) % 5, y),
                    b_reg((x + 2) % 5, y)));
            }
        }

        // iota
        p.instructions.push_back(
            xorconst(state_reg(0, 0), state_reg(0, 0), kRoundConstants[round]));
    }
}

std::size_t padded_bytes_for(std::size_t message_bytes) {
    const auto needed = message_bytes + 1;
    const auto blocks = (needed + kSha3_512RateBytes - 1) / kSha3_512RateBytes;
    return blocks * kSha3_512RateBytes;
}

} // namespace

Sha3_512ProgramImage build_sha3_512_program_image(std::size_t message_bytes) {
    Sha3_512ProgramImage out;
    out.message_bytes = message_bytes;
    out.absorb_blocks = padded_bytes_for(message_bytes) / kSha3_512RateBytes;
    if (out.absorb_blocks * 9 > 0xffffu)
        throw std::runtime_error("SHA3-512 program image input word count exceeds v1 encoding");

    out.program.register_count = 60;
    out.program.input_word_count = out.absorb_blocks * 9;
    out.program.output_registers = {0,1,2,3,4,5,6,7};

    for (std::size_t block = 0; block < out.absorb_blocks; ++block) {
        for (std::size_t lane = 0; lane < 9; ++lane) {
            out.program.instructions.push_back(xorinput(
                state_reg(lane % 5, lane / 5),
                state_reg(lane % 5, lane / 5),
                static_cast<std::uint16_t>(block * 9 + lane)));
        }
        emit_keccak_f1600(out.program);
    }

    out.program.validate();
    return out;
}

std::vector<std::uint64_t> sha3_512_program_input_words(
    const std::vector<std::uint8_t>& message) {
    const auto padded_bytes = padded_bytes_for(message.size());
    std::vector<std::uint8_t> padded(padded_bytes, 0);
    for (std::size_t i = 0; i < message.size(); ++i)
        padded[i] = message[i];
    padded[message.size()] ^= 0x06u;
    padded.back() ^= 0x80u;

    std::vector<std::uint64_t> words(padded.size() / 8, 0);
    for (std::size_t i = 0; i < padded.size(); ++i)
        words[i / 8] |= static_cast<std::uint64_t>(padded[i]) << ((i % 8) * 8);
    return words;
}

std::vector<std::uint8_t> evaluate_sha3_512_program_image(
    const Sha3_512ProgramImage& image,
    const std::vector<std::uint8_t>& message) {
    if (message.size() != image.message_bytes)
        throw std::runtime_error("SHA3-512 program image message length mismatch");
    const auto input_words = sha3_512_program_input_words(message);
    const auto exec = evaluate_boolean_program_image(image.program, input_words);
    if (exec.output_words.size() != 8)
        throw std::runtime_error("SHA3-512 program image produced wrong output word count");

    std::vector<std::uint8_t> digest;
    digest.reserve(kSha3_512DigestBytes);
    for (const auto word : exec.output_words) {
        for (std::size_t i = 0; i < 8; ++i)
            digest.push_back(static_cast<std::uint8_t>((word >> (i * 8)) & 0xffu));
    }
    return digest;
}

} // namespace v0id::integrity
