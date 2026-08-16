#include "boolean_ir_mutator.hpp"

#include <cstdint>
#include <random>
#include <stdexcept>
#include <vector>

namespace v0id::integrity {
namespace {

std::mt19937_64 make_rng(const BooleanMutationSeed& seed) {
    std::vector<std::uint32_t> words;
    words.reserve(8);
    for (std::size_t i = 0; i < seed.size(); i += 4) {
        std::uint32_t w = 0;
        for (std::size_t j = 0; j < 4; ++j)
            w |= static_cast<std::uint32_t>(seed[i + j]) << (8 * j);
        words.push_back(w);
    }
    std::seed_seq seq(words.begin(), words.end());
    return std::mt19937_64(seq);
}

bool coin(std::mt19937_64& rng) {
    return (rng() & 1ULL) != 0;
}

} // namespace

BooleanIR mutate_boolean_ir(const BooleanIR& base,
                            const BooleanMutationSeed& seed,
                            const BooleanMutationOptions& options) {
    base.validate();

    BooleanIR out;
    std::vector<BoolWire> map(base.nodes().size(), kInvalidBoolWire);
    for (std::size_t i = 0; i < base.input_count(); ++i)
        map[i] = out.add_input();

    auto rng = make_rng(seed);
    const auto zero = out.constant(false);

    for (std::size_t i = base.input_count(); i < base.nodes().size(); ++i) {
        const auto& n = base.nodes()[i];
        const auto mapped = [&](BoolWire w) -> BoolWire {
            if (w >= map.size() || map[w] == kInvalidBoolWire)
                throw std::runtime_error("BooleanIR mutator saw unavailable dependency");
            return map[w];
        };

        BoolWire result = kInvalidBoolWire;
        switch (n.op) {
        case BoolOp::Input:
            throw std::runtime_error("BooleanIR input outside canonical prefix");
        case BoolOp::Const0:
            result = zero;
            break;
        case BoolOp::Const1:
            result = out.constant(true);
            break;
        case BoolOp::Not: {
            auto a = mapped(n.a);
            if (options.wrap_some_gates && coin(rng))
                a = out.bit_xor(a, zero);
            result = out.bit_not(a);
            if (options.wrap_some_gates && coin(rng))
                result = out.bit_not(out.bit_not(result));
            break;
        }
        case BoolOp::Xor: {
            auto a = mapped(n.a);
            auto b = mapped(n.b);
            if (options.expand_some_xors && coin(rng)) {
                // a xor b = (a & !b) xor (!a & b). The conjunctions are
                // disjoint, so XOR is also OR for this pair.
                const auto na = out.bit_not(a);
                const auto nb = out.bit_not(b);
                const auto left = out.bit_and(a, nb);
                const auto right = out.bit_and(na, b);
                result = out.bit_xor(left, right);
            } else {
                if (options.wrap_some_gates && coin(rng))
                    a = out.bit_xor(a, zero);
                if (options.wrap_some_gates && coin(rng))
                    b = out.bit_xor(b, zero);
                result = out.bit_xor(a, b);
            }
            if (options.wrap_some_gates && coin(rng))
                result = out.bit_xor(result, zero);
            break;
        }
        case BoolOp::And: {
            auto a = mapped(n.a);
            auto b = mapped(n.b);
            if (options.wrap_some_gates && coin(rng))
                a = out.bit_not(out.bit_not(a));
            if (options.wrap_some_gates && coin(rng))
                b = out.bit_xor(b, zero);
            result = out.bit_and(a, b);
            if (options.wrap_some_gates && coin(rng))
                result = out.bit_not(out.bit_not(result));
            break;
        }
        }

        map[i] = result;

        if (options.dummy_identity_period != 0 &&
            (rng() % options.dummy_identity_period) == 0) {
            // Deliberately unreachable identity work. It remains part of the DAG
            // and therefore becomes extra lowering structure, but no output or
            // dependency points at it.
            (void)out.bit_xor(result, zero);
        }
    }

    std::vector<BoolWire> outputs;
    outputs.reserve(base.outputs().size());
    for (const auto wire : base.outputs()) {
        auto w = map[wire];
        if (options.wrap_some_gates && coin(rng))
            w = out.bit_not(out.bit_not(w));
        outputs.push_back(w);
    }
    out.set_outputs(std::move(outputs));
    out.validate();
    return out;
}

} // namespace v0id::integrity
