#pragma once

#include "boolean_ir.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace v0id::integrity {

// Graph-level camouflage for a Boolean hash circuit. The physical input tape is
// unchanged; selected input edges are replaced downstream by an exactly
// equivalent expression containing a non-trivial input-dependent branch:
//
//     z = m XOR m       == 0
//     n = m AND z       == 0
//     x' = x XOR n      == x
//
// This is circuit morphology, not cryptographic masking. A compiler that is
// allowed to algebraically simplify the graph may erase the neutral branch.
// The trace exists so a client can verify that the branch was present and that
// the original Boolean DAG was preserved after the substitution.
struct HashCamouflageSpec {
    std::uint64_t seed{0x9e3779b97f4a7c15ull};
    std::size_t signal_terms{3};

    // Empty means every input edge. Otherwise only these logical input indices
    // are wrapped. The BooleanIR input prefix itself is never modified.
    std::vector<std::size_t> input_indices;
};

struct HashCamouflageInputTrace {
    std::size_t input_index{};
    BoolWire source_input{kInvalidBoolWire};
    std::vector<std::size_t> signal_inputs;
    BoolWire signal{kInvalidBoolWire};
    BoolWire zero{kInvalidBoolWire};
    BoolWire neutral_term{kInvalidBoolWire};
    BoolWire wrapped_input{kInvalidBoolWire};
};

struct HashCamouflageTrace {
    std::uint64_t seed{};
    std::size_t signal_terms{};
    std::size_t original_node_count{};
    std::size_t camouflage_end_wire{};

    // Logical original wire -> corresponding wire in the transformed graph.
    // Wrapped inputs point at their neutralized edge; non-input wires point at
    // the structurally cloned hash graph.
    std::vector<BoolWire> original_to_camouflaged;
    std::vector<BoolWire> original_outputs;
    std::vector<BoolWire> camouflaged_outputs;
    std::vector<HashCamouflageInputTrace> inputs;
};

struct HashCamouflagedIR {
    BooleanIR ir;
    HashCamouflageTrace trace;
};

namespace hash_camouflage_detail {

inline std::uint64_t mix64(std::uint64_t x) noexcept {
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    return x ^ (x >> 31);
}

inline std::vector<std::size_t> selected_inputs(
    const HashCamouflageSpec& spec, std::size_t input_count) {
    if (spec.input_indices.empty()) {
        std::vector<std::size_t> all(input_count);
        for (std::size_t i = 0; i < input_count; ++i) all[i] = i;
        return all;
    }

    auto selected = spec.input_indices;
    std::sort(selected.begin(), selected.end());
    if (std::adjacent_find(selected.begin(), selected.end()) != selected.end())
        throw std::runtime_error("hash camouflage input_indices contain duplicates");
    for (const auto index : selected)
        if (index >= input_count)
            throw std::runtime_error("hash camouflage input index outside input count");
    return selected;
}

inline std::vector<std::size_t> signal_inputs(
    const HashCamouflageSpec& spec,
    std::size_t target_input,
    std::size_t input_count) {
    if (input_count == 0) return {};
    if (spec.signal_terms == 0)
        throw std::runtime_error("hash camouflage signal_terms must be non-zero");

    const auto count = std::min(spec.signal_terms, input_count);
    std::vector<std::size_t> selected;
    selected.reserve(count);
    auto state = mix64(spec.seed ^
                       (static_cast<std::uint64_t>(target_input) *
                        0xd6e8feb86659fd93ull));
    while (selected.size() < count) {
        state = mix64(state);
        const auto candidate = static_cast<std::size_t>(state % input_count);
        if (std::find(selected.begin(), selected.end(), candidate) == selected.end())
            selected.push_back(candidate);
    }
    return selected;
}

inline void require_wire(const BooleanIR& ir, BoolWire wire, const char* label) {
    if (wire >= ir.nodes().size())
        throw std::runtime_error(std::string("hash camouflage ") + label +
                                 " wire outside graph");
}

inline bool same_node(const BooleanIR& ir, BoolWire wire, BoolOp op,
                      BoolWire a = kInvalidBoolWire,
                      BoolWire b = kInvalidBoolWire) {
    const auto& node = ir.nodes().at(wire);
    return node.op == op &&
           (a == kInvalidBoolWire || node.a == a) &&
           (b == kInvalidBoolWire || node.b == b);
}

inline void collect_xor_inputs(const BooleanIR& ir, BoolWire wire,
                               std::vector<std::size_t>& leaves) {
    const auto& node = ir.nodes().at(wire);
    if (node.op == BoolOp::Xor) {
        collect_xor_inputs(ir, node.a, leaves);
        collect_xor_inputs(ir, node.b, leaves);
        return;
    }
    if (node.op != BoolOp::Input)
        throw std::runtime_error("hash camouflage signal is not an input XOR tree");
    leaves.push_back(node.input_index);
}

inline void validate_signal_inputs(const BooleanIR& ir,
                                   const HashCamouflageInputTrace& entry) {
    std::vector<std::size_t> leaves;
    collect_xor_inputs(ir, entry.signal, leaves);
    auto expected = entry.signal_inputs;
    std::sort(expected.begin(), expected.end());
    std::sort(leaves.begin(), leaves.end());
    if (expected != leaves)
        throw std::runtime_error("hash camouflage signal input trace mismatch");
}

} // namespace hash_camouflage_detail

inline HashCamouflagedIR camouflage_hash_input_edges(
    const BooleanIR& original, const HashCamouflageSpec& spec) {
    using namespace hash_camouflage_detail;
    original.validate();

    HashCamouflagedIR out;
    out.trace.seed = spec.seed;
    out.trace.signal_terms = spec.signal_terms;
    out.trace.original_node_count = original.nodes().size();
    out.trace.original_outputs = original.outputs();
    out.trace.original_to_camouflaged.resize(original.nodes().size(),
                                             kInvalidBoolWire);

    // Keep the input tape as an exact dense prefix. We only alter the wires used
    // by the cloned hash body after this point.
    for (std::size_t i = 0; i < original.input_count(); ++i) {
        if (out.ir.add_input() != i)
            throw std::runtime_error("hash camouflage input prefix construction failed");
        out.trace.original_to_camouflaged[i] = i;
    }

    for (const auto input_index : selected_inputs(spec, original.input_count())) {
        const auto signal_indices =
            signal_inputs(spec, input_index, original.input_count());
        if (signal_indices.empty())
            throw std::runtime_error("hash camouflage could not construct signal");

        // Signals intentionally reference the raw input prefix, never another
        // wrapper. This keeps every neutral branch independently traceable.
        BoolWire signal = signal_indices.front();
        for (std::size_t i = 1; i < signal_indices.size(); ++i)
            signal = out.ir.bit_xor(signal, signal_indices[i]);

        const auto zero = out.ir.bit_xor(signal, signal);
        const auto neutral_term = out.ir.bit_and(signal, zero);
        const auto wrapped = out.ir.bit_xor(input_index, neutral_term);

        out.trace.original_to_camouflaged[input_index] = wrapped;
        out.trace.inputs.push_back(HashCamouflageInputTrace{
            input_index, input_index, signal_indices,
            signal, zero, neutral_term, wrapped});
    }

    out.trace.camouflage_end_wire = out.ir.nodes().size();

    // Clone the original hash DAG exactly, replacing only dependencies on the
    // selected logical input wires with their traced neutralized counterparts.
    for (std::size_t i = original.input_count(); i < original.nodes().size(); ++i) {
        const auto& node = original.nodes()[i];
        BoolWire mapped = kInvalidBoolWire;
        switch (node.op) {
        case BoolOp::Const0:
            mapped = out.ir.constant(false);
            break;
        case BoolOp::Const1:
            mapped = out.ir.constant(true);
            break;
        case BoolOp::Not:
            mapped = out.ir.bit_not(out.trace.original_to_camouflaged.at(node.a));
            break;
        case BoolOp::Xor:
            mapped = out.ir.bit_xor(
                out.trace.original_to_camouflaged.at(node.a),
                out.trace.original_to_camouflaged.at(node.b));
            break;
        case BoolOp::And:
            mapped = out.ir.bit_and(
                out.trace.original_to_camouflaged.at(node.a),
                out.trace.original_to_camouflaged.at(node.b));
            break;
        case BoolOp::Input:
            throw std::runtime_error("unexpected input node outside BooleanIR prefix");
        }
        out.trace.original_to_camouflaged[i] = mapped;
    }

    for (const auto wire : original.outputs())
        out.trace.camouflaged_outputs.push_back(
            out.trace.original_to_camouflaged.at(wire));
    out.ir.set_outputs(out.trace.camouflaged_outputs);
    out.ir.validate();
    return out;
}

// Structural proof that the original DAG is embedded unchanged after neutral
// input-edge substitutions. This does not rely on a finite set of test vectors.
inline void validate_hash_camouflage(
    const BooleanIR& original, const HashCamouflagedIR& camouflaged) {
    using namespace hash_camouflage_detail;
    original.validate();
    camouflaged.ir.validate();

    const auto& trace = camouflaged.trace;
    if (trace.original_node_count != original.nodes().size() ||
        trace.original_to_camouflaged.size() != original.nodes().size())
        throw std::runtime_error("hash camouflage original graph mapping mismatch");
    if (trace.original_outputs != original.outputs() ||
        trace.camouflaged_outputs != camouflaged.ir.outputs())
        throw std::runtime_error("hash camouflage output mapping mismatch");
    if (trace.camouflage_end_wire < original.input_count() ||
        trace.camouflage_end_wire > camouflaged.ir.nodes().size())
        throw std::runtime_error("hash camouflage region boundary invalid");
    if (camouflaged.ir.input_count() != original.input_count())
        throw std::runtime_error("hash camouflage changed input tape width");

    std::unordered_set<std::size_t> wrapped;
    for (const auto& entry : trace.inputs) {
        if (entry.input_index >= original.input_count() ||
            !wrapped.insert(entry.input_index).second)
            throw std::runtime_error("invalid or duplicate hash camouflage input trace");
        if (entry.source_input != entry.input_index || entry.signal_inputs.empty())
            throw std::runtime_error("hash camouflage input trace source mismatch");
        for (const auto index : entry.signal_inputs)
            if (index >= original.input_count())
                throw std::runtime_error("hash camouflage signal input outside tape");

        require_wire(camouflaged.ir, entry.signal, "signal");
        require_wire(camouflaged.ir, entry.zero, "zero");
        require_wire(camouflaged.ir, entry.neutral_term, "neutral term");
        require_wire(camouflaged.ir, entry.wrapped_input, "wrapped input");
        if (entry.signal >= trace.camouflage_end_wire ||
            entry.zero >= trace.camouflage_end_wire ||
            entry.neutral_term >= trace.camouflage_end_wire ||
            entry.wrapped_input >= trace.camouflage_end_wire)
            throw std::runtime_error("hash camouflage branch escaped morphology region");

        validate_signal_inputs(camouflaged.ir, entry);
        if (!same_node(camouflaged.ir, entry.zero, BoolOp::Xor,
                       entry.signal, entry.signal))
            throw std::runtime_error("hash camouflage zero is not signal XOR signal");
        if (!same_node(camouflaged.ir, entry.neutral_term, BoolOp::And,
                       entry.signal, entry.zero))
            throw std::runtime_error("hash camouflage neutral term is not signal AND zero");
        if (!same_node(camouflaged.ir, entry.wrapped_input, BoolOp::Xor,
                       entry.source_input, entry.neutral_term))
            throw std::runtime_error("hash camouflage wrapper is not source XOR neutral");
        if (trace.original_to_camouflaged.at(entry.input_index) != entry.wrapped_input)
            throw std::runtime_error("hash camouflage input mapping does not point at wrapper");
    }

    for (std::size_t i = 0; i < original.nodes().size(); ++i) {
        const auto mapped = trace.original_to_camouflaged.at(i);
        require_wire(camouflaged.ir, mapped, "mapped");
        if (i < original.input_count()) {
            if (!wrapped.contains(i) && mapped != i)
                throw std::runtime_error("untouched input wire was remapped");
            continue;
        }
        if (mapped < trace.camouflage_end_wire)
            throw std::runtime_error("non-input hash node entered camouflage region");

        const auto& source = original.nodes()[i];
        const auto& target = camouflaged.ir.nodes()[mapped];
        if (source.op != target.op || source.input_index != target.input_index)
            throw std::runtime_error("hash camouflage changed a hash node");

        switch (source.op) {
        case BoolOp::Const0:
        case BoolOp::Const1:
            break;
        case BoolOp::Not:
            if (target.a != trace.original_to_camouflaged.at(source.a))
                throw std::runtime_error("hash camouflage changed NOT dependency");
            break;
        case BoolOp::Xor:
        case BoolOp::And:
            if (target.a != trace.original_to_camouflaged.at(source.a) ||
                target.b != trace.original_to_camouflaged.at(source.b))
                throw std::runtime_error("hash camouflage changed binary dependency");
            break;
        case BoolOp::Input:
            throw std::runtime_error("unexpected input node in hash clone");
        }
    }

    for (std::size_t i = 0; i < trace.original_outputs.size(); ++i)
        if (trace.camouflaged_outputs[i] !=
            trace.original_to_camouflaged.at(trace.original_outputs[i]))
            throw std::runtime_error("hash camouflage output wire mismatch");
}

inline bool equivalent_on_inputs(
    const BooleanIR& original,
    const HashCamouflagedIR& camouflaged,
    const std::vector<std::uint8_t>& inputs) {
    validate_hash_camouflage(original, camouflaged);
    return original.evaluate(inputs) == camouflaged.ir.evaluate(inputs);
}

} // namespace v0id::integrity
