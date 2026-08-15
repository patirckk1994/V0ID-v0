#include "boolean_program_image_mutator.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace v0id::integrity {
namespace {

class SeedRng {
public:
    explicit SeedRng(const BooleanMutationSeed& seed) {
        std::uint64_t x = 0x9e3779b97f4a7c15ull;
        for (std::size_t i = 0; i < seed.size(); ++i) {
            x ^= static_cast<std::uint64_t>(seed[i]) << ((i % 8) * 8);
            x += 0x9e3779b97f4a7c15ull + (x << 6) + (x >> 2);
        }
        state_ = x;
    }

    std::uint64_t next() {
        state_ += 0x9e3779b97f4a7c15ull;
        auto z = state_;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        return z ^ (z >> 31);
    }

    std::size_t index(std::size_t n) {
        if (n == 0)
            throw std::runtime_error("mutation RNG asked for empty index range");
        return static_cast<std::size_t>(next() % n);
    }

private:
    std::uint64_t state_{};
};

void remap_registers(BooleanProgramInstruction& ins,
                     const std::vector<std::uint8_t>& p) {
    auto map = [&](std::uint8_t r) { return p[r]; };
    ins.dst = map(ins.dst);
    switch (ins.op) {
    case BooleanProgramOpcode::Xor2:
        ins.a = map(ins.a); ins.b = map(ins.b);
        break;
    case BooleanProgramOpcode::Xor5:
        ins.a = map(ins.a); ins.b = map(ins.b); ins.c = map(ins.c);
        ins.d = map(ins.d); ins.e = map(ins.e);
        break;
    case BooleanProgramOpcode::XorRot1:
        ins.a = map(ins.a); ins.b = map(ins.b);
        break;
    case BooleanProgramOpcode::RotCopy:
        ins.a = map(ins.a);
        break;
    case BooleanProgramOpcode::Chi:
        ins.a = map(ins.a); ins.b = map(ins.b); ins.c = map(ins.c);
        break;
    case BooleanProgramOpcode::XorInput:
        ins.a = map(ins.a);
        break;
    case BooleanProgramOpcode::XorConst:
        ins.a = map(ins.a);
        break;
    }
}

} // namespace

BooleanProgramImage mutate_boolean_program_image(
    const BooleanProgramImage& original,
    const BooleanMutationSeed& seed,
    std::size_t identity_instructions,
    BooleanProgramMutationStats* stats) {
    original.validate();
    SeedRng rng(seed);

    BooleanProgramImage out = original;
    std::vector<std::uint8_t> permutation(original.register_count);
    for (std::size_t i = 0; i < permutation.size(); ++i)
        permutation[i] = static_cast<std::uint8_t>(i);
    for (std::size_t i = permutation.size(); i > 1; --i)
        std::swap(permutation[i - 1], permutation[rng.index(i)]);

    for (auto& ins : out.instructions)
        remap_registers(ins, permutation);
    for (auto& reg : out.output_registers)
        reg = permutation[reg];

    for (std::size_t i = 0; i < identity_instructions; ++i) {
        const auto reg = static_cast<std::uint8_t>(rng.index(out.register_count));
        BooleanProgramInstruction noop;
        noop.op = BooleanProgramOpcode::XorConst;
        noop.dst = reg;
        noop.a = reg;
        noop.immediate = 0;
        const auto pos = rng.index(out.instructions.size() + 1);
        out.instructions.insert(out.instructions.begin() +
                                static_cast<std::ptrdiff_t>(pos), noop);
    }

    out.validate();
    if (stats) {
        stats->permuted_registers = permutation.size();
        stats->identity_instructions_inserted = identity_instructions;
    }
    return out;
}

} // namespace v0id::integrity
