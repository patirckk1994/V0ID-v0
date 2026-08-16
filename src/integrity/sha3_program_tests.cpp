#include "boolean_ir_mutator.hpp"
#include "boolean_ir_to_program.hpp"
#include "polymorphic_hash_camouflage.hpp"
#include "sha3_512_ir.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::integrity::BooleanIR;
using v0id::integrity::BooleanMutationSeed;

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

std::vector<std::uint8_t> openssl_sha3_512(
    const std::vector<std::uint8_t>& message) {
    using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha3_512(), nullptr) != 1)
        throw std::runtime_error("EVP SHA3-512 init failed");
    if (EVP_DigestUpdate(ctx.get(), message.data(), message.size()) != 1)
        throw std::runtime_error("EVP SHA3-512 update failed");

    std::vector<std::uint8_t> out(64);
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &n) != 1 || n != out.size())
        throw std::runtime_error("EVP SHA3-512 final failed");
    return out;
}

std::vector<std::uint8_t> ir_sha3_512(
    const std::vector<std::uint8_t>& message) {
    const auto built = v0id::integrity::build_sha3_512_ir(message.size());
    const auto bits = v0id::integrity::bytes_to_lsb_bits(message);
    return v0id::integrity::lsb_bits_to_bytes(built.ir.evaluate(bits));
}

std::vector<std::uint8_t> run_tm(
    const v0id::integrity::LoweredBooleanProgram& lowered,
    const std::vector<std::uint8_t>& inputs) {
    require(inputs.size() == lowered.input_cells.size(),
            "TM test input count mismatch");
    std::vector<int> tape(lowered.tape_cells, 0);
    for (std::size_t i = 0; i < inputs.size(); ++i)
        tape[lowered.input_cells[i]] = inputs[i] != 0 ? 1 : 0;

    std::size_t state = lowered.initial_state;
    std::ptrdiff_t head = static_cast<std::ptrdiff_t>(lowered.required_initial_head);
    for (std::size_t step = 0; step < lowered.execution_rounds; ++step) {
        require(head >= 0 && static_cast<std::size_t>(head) < tape.size(),
                "TM head escaped reference tape");
        const auto& r = lowered.program.rule(
            state, tape[static_cast<std::size_t>(head)]);
        tape[static_cast<std::size_t>(head)] = r.write;
        head += r.move;
        state = r.next_state;
    }

    std::vector<std::uint8_t> outputs;
    outputs.reserve(lowered.output_cells.size());
    for (const auto cell : lowered.output_cells)
        outputs.push_back(static_cast<std::uint8_t>(tape[cell] != 0));
    return outputs;
}

BooleanIR tiny_ir() {
    BooleanIR ir;
    const auto a = ir.add_input();
    const auto b = ir.add_input();
    const auto c = ir.add_input();
    const auto x = ir.bit_xor(a, b);
    const auto nc = ir.bit_not(c);
    const auto y = ir.bit_and(x, nc);
    ir.set_outputs({y, x});
    ir.validate();
    return ir;
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    for (const std::size_t n : {std::size_t{0}, std::size_t{3}, std::size_t{71},
                                std::size_t{72}, std::size_t{73}}) {
        std::vector<std::uint8_t> message(n);
        for (std::size_t i = 0; i < n; ++i)
            message[i] = static_cast<std::uint8_t>((i * 37u + 11u) & 0xffu);
        if (n == 3)
            message = {'a', 'b', 'c'};
        pass(ir_sha3_512(message) == openssl_sha3_512(message),
             "SHA3-512 BooleanIR matches OpenSSL across padding boundaries");
    }

    const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
    const auto sha3 = v0id::integrity::build_sha3_512_ir(abc.size());
    BooleanMutationSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(0xa5u ^ (i * 13u));
    const auto mutated = v0id::integrity::mutate_boolean_ir(sha3.ir, seed);
    const auto abc_bits = v0id::integrity::bytes_to_lsb_bits(abc);
    pass(mutated.evaluate(abc_bits) == sha3.ir.evaluate(abc_bits),
         "seeded BooleanIR mutation preserves SHA3-512 output");
    pass(mutated.nodes().size() != sha3.ir.nodes().size(),
         "seeded BooleanIR mutation changes circuit structure");

    v0id::integrity::HashCamouflageSpec camouflage_spec;
    camouflage_spec.seed = 0x0123456789abcdefull;
    camouflage_spec.signal_terms = 3;
    const auto camouflaged =
        v0id::integrity::camouflage_hash_input_edges(sha3.ir, camouflage_spec);
    v0id::integrity::validate_hash_camouflage(sha3.ir, camouflaged);
    pass(camouflaged.ir.input_count() == sha3.ir.input_count(),
         "hash camouflage preserves the physical input tape");
    pass(camouflaged.trace.inputs.size() == sha3.ir.input_count(),
         "hash camouflage traces every selected hash input edge");
    pass(camouflaged.ir.nodes().size() > sha3.ir.nodes().size(),
         "hash camouflage adds a non-trivial graph morphology region");
    pass(v0id::integrity::equivalent_on_inputs(sha3.ir, camouflaged, abc_bits),
         "hash camouflage preserves SHA3-512 semantics");
    pass(v0id::integrity::lsb_bits_to_bytes(camouflaged.ir.evaluate(abc_bits)) ==
             openssl_sha3_512(abc),
         "camouflaged SHA3-512 output still matches OpenSSL");

    bool input_prefix_unchanged = true;
    for (std::size_t i = 0; i < sha3.ir.input_count(); ++i) {
        const auto& node = camouflaged.ir.nodes()[i];
        input_prefix_unchanged = input_prefix_unchanged &&
            node.op == v0id::integrity::BoolOp::Input &&
            node.input_index == i;
    }
    pass(input_prefix_unchanged,
         "hash camouflage leaves BooleanIR input nodes unchanged");

    auto alternate_spec = camouflage_spec;
    alternate_spec.signal_terms = 2;
    const auto alternate_camouflaged =
        v0id::integrity::camouflage_hash_input_edges(sha3.ir, alternate_spec);
    v0id::integrity::validate_hash_camouflage(sha3.ir, alternate_camouflaged);
    pass(alternate_camouflaged.ir.nodes().size() != camouflaged.ir.nodes().size(),
         "different camouflage parameters produce a different graph shape");
    pass(v0id::integrity::equivalent_on_inputs(
             sha3.ir, alternate_camouflaged, abc_bits),
         "different camouflage graph shape preserves the same SHA3 output");

    v0id::integrity::HashCamouflageSpec partial_spec;
    partial_spec.seed = 0xfeedfacecafebeefull;
    partial_spec.signal_terms = 2;
    partial_spec.input_indices = {0, 7, 15};
    const auto partial =
        v0id::integrity::camouflage_hash_input_edges(sha3.ir, partial_spec);
    v0id::integrity::validate_hash_camouflage(sha3.ir, partial);
    pass(partial.trace.inputs.size() == partial_spec.input_indices.size(),
         "partial hash camouflage wraps exactly the requested input edges");
    pass(partial.ir.nodes().size() < camouflaged.ir.nodes().size(),
         "partial hash camouflage adds less morphology than full camouflage");
    pass(v0id::integrity::equivalent_on_inputs(sha3.ir, partial, abc_bits),
         "partial hash camouflage preserves SHA3 output");

    const auto tiny = tiny_ir();
    auto plan = v0id::integrity::make_default_boolean_ir_lowering_plan(tiny);
    plan.max_states = 100000;
    const auto lowered = v0id::integrity::lower_boolean_ir_to_program(tiny, plan);
    pass(lowered.program.rules.size() == lowered.program.states * 2,
         "reference lowerer emits exactly two rules per state");
    bool canonical = true;
    for (std::size_t q = 0; q < lowered.program.states; ++q) {
        for (int bit = 0; bit <= 1; ++bit) {
            const auto& r = lowered.program.rules[q * 2 + static_cast<std::size_t>(bit)];
            canonical = canonical && r.state == q && r.read == bit;
        }
    }
    pass(canonical, "reference lowerer emits canonical rules[2*q+read] layout");

    bool all_truth_table_rows = true;
    for (int a = 0; a <= 1; ++a) {
        for (int b = 0; b <= 1; ++b) {
            for (int c = 0; c <= 1; ++c) {
                const std::vector<std::uint8_t> in{
                    static_cast<std::uint8_t>(a),
                    static_cast<std::uint8_t>(b),
                    static_cast<std::uint8_t>(c)};
                all_truth_table_rows = all_truth_table_rows &&
                    run_tm(lowered, in) == tiny.evaluate(in);
            }
        }
    }
    pass(all_truth_table_rows,
         "reference BooleanIR-to-Program lowerer matches exhaustive tiny truth table");

    auto tiny_budget = plan;
    tiny_budget.max_states = 1;
    bool budget_rejected = false;
    try {
        (void)v0id::integrity::lower_boolean_ir_to_program(tiny, tiny_budget);
    } catch (const std::runtime_error&) {
        budget_rejected = true;
    }
    pass(budget_rejected,
         "reference lowerer fails closed when state budget would be exceeded");

    std::cout << "sha3-program tests passed: " << passed << '\n';
    return 0;
} catch (const std::exception& e) {
    std::cerr << "sha3-program tests FAILED: " << e.what() << '\n';
    return 1;
}
