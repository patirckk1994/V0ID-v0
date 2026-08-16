#pragma once

#include "mlp_precompiler.hpp"
#include "neural_integrity.hpp"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace v0id::neural {
namespace integrity_regression_detail {

inline void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

inline void expect_throw(const std::function<void()>& fn,
                         const std::string& what) {
    try {
        fn();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("expected neural integrity failure: " + what);
}

inline const NeuralPort& require_port(const NeuralGraph& graph,
                                      const std::string& node_id,
                                      const std::string& port_name) {
    const auto node = std::find_if(graph.nodes.begin(), graph.nodes.end(),
                                   [&](const auto& candidate) {
                                       return candidate.id == node_id;
                                   });
    if (node == graph.nodes.end())
        throw std::runtime_error("missing integrity regression node: " + node_id);
    const auto port = std::find_if(node->ports.begin(), node->ports.end(),
                                   [&](const auto& candidate) {
                                       return candidate.name == port_name;
                                   });
    if (port == node->ports.end())
        throw std::runtime_error("missing integrity regression port: " +
                                 node_id + "." + port_name);
    return *port;
}

inline NeuralTraceEntry trace_entry(const NeuralGraph& graph,
                                    std::uint64_t step,
                                    std::string node_id,
                                    std::string port_name,
                                    std::vector<std::uint8_t> bytes,
                                    NeuralTraceRepresentation representation =
                                        NeuralTraceRepresentation::canonical_plaintext) {
    const auto& port = require_port(graph, node_id, port_name);
    NeuralTraceEntry entry;
    entry.step_index = step;
    entry.node_id = std::move(node_id);
    entry.port_name = std::move(port_name);
    entry.role = port.role;
    entry.format = port.format;
    entry.shape = port.shape;
    entry.representation = representation;
    entry.value_bytes = std::move(bytes);
    return entry;
}

} // namespace integrity_regression_detail

// Additive regression suite for the execution-trace/integrity ABI. It uses fake
// canonical value bytes intentionally: this suite verifies commitments, graph
// binding and checkpoint behavior, not DENSE arithmetic. The future plain fixed-
// point backend will supply the semantic replay tests.
inline std::size_t run_neural_integrity_regression_tests() {
    using namespace integrity_regression_detail;
    std::size_t passed = 0;

    MlpPrecompileSpec spec;
    spec.graph_id = "integrity-trace-mlp";
    spec.batch_size = 1;
    spec.input_size = 2;
    spec.layers = {{3, true}, {1, false}};
    spec.training = MlpTrainingMode::inference;
    const auto compiled = MlpPortPrecompiler::compile(spec);

    NeuralInvocation invocation;
    invocation.execution_mode = NeuralExecutionMode::plain_cpu;
    invocation.validate(compiled.graph);

    NeuralExecutionTrace trace;
    trace.graph_digest = compiled.graph.digest512();
    trace.invocation_digest = invocation.digest512(compiled.graph);
    trace.entries = {
        trace_entry(compiled.graph, 0, "forward.input", "activation",
                    {0x10, 0x20}),
        trace_entry(compiled.graph, 1, "forward.layer.0.dense", "y",
                    {0x31, 0x32, 0x33}),
        trace_entry(compiled.graph, 2, "forward.layer.0.activation", "y",
                    {0x41, 0x42, 0x43}),
        trace_entry(compiled.graph, 3, "forward.layer.1.dense", "y",
                    {0x55}),
    };

    trace.validate(compiled.graph, invocation);
    ++passed;

    const auto trace_digest = trace.digest512(compiled.graph, invocation);
    require(std::any_of(trace_digest.begin(), trace_digest.end(),
                        [](auto byte) { return byte != 0; }),
            "neural execution trace digest unexpectedly zero");
    auto reordered_trace = trace;
    std::reverse(reordered_trace.entries.begin(), reordered_trace.entries.end());
    require(reordered_trace.digest512(compiled.graph, invocation) == trace_digest,
            "trace commitment changed under entry vector reordering");
    ++passed;

    auto changed_value = trace;
    changed_value.entries.back().value_bytes[0] ^= 0x01u;
    require(changed_value.digest512(compiled.graph, invocation) != trace_digest,
            "trace commitment ignored changed neural value bytes");
    ++passed;

    auto bad_schema = trace;
    bad_schema.entries[1].shape.dimensions = {1, 4};
    expect_throw([&] { bad_schema.validate(compiled.graph, invocation); },
                 "trace endpoint schema mismatch");
    ++passed;

    NeuralIntegrityPlan plan;
    plan.plan_id = "ordinary-output-checkpoints";
    plan.checkpoints = {
        {"middle", 2, "forward.layer.0.activation", "y"},
        {"final", 3, "forward.layer.1.dense", "y"},
    };
    plan.validate(compiled.graph);
    const auto plan_digest = plan.digest512(compiled.graph);
    require(std::any_of(plan_digest.begin(), plan_digest.end(),
                        [](auto byte) { return byte != 0; }),
            "neural integrity plan digest unexpectedly zero");
    ++passed;

    const auto receipt = make_neural_integrity_receipt(
        compiled.graph, invocation, trace, plan);
    require(receipt.observed.size() == 2 &&
            receipt.trace_digest == trace_digest &&
            receipt.plan_digest == plan_digest,
            "neural integrity receipt binding mismatch");
    ++passed;

    auto forged_receipt = receipt;
    forged_receipt.observed[0].entry_commitment[0] ^= 0x01u;
    expect_throw([&] {
        forged_receipt.validate(compiled.graph, invocation, trace, plan);
    }, "receipt observation detached from actual trace value");
    ++passed;

    NeuralIntegrityExpectation expectation;
    expectation.graph_digest = compiled.graph.digest512();
    expectation.invocation_digest = invocation.digest512(compiled.graph);
    expectation.plan_digest = plan_digest;
    expectation.expected = receipt.observed;
    expectation.validate(compiled.graph, invocation, plan);
    require(verify_neural_integrity_receipt(
                compiled.graph, invocation, trace, plan, expectation, receipt),
            "known-answer neural integrity receipt did not verify");
    ++passed;

    auto wrong_expectation = expectation;
    wrong_expectation.expected[0].entry_commitment[0] ^= 0x01u;
    require(!verify_neural_integrity_receipt(
                compiled.graph, invocation, trace, plan,
                wrong_expectation, receipt),
            "changed expected neural integrity value was accepted");
    ++passed;

    auto opaque_trace = trace;
    for (auto& entry : opaque_trace.entries) {
        if ((entry.step_index == 2 &&
             entry.node_id == "forward.layer.0.activation") ||
            (entry.step_index == 3 &&
             entry.node_id == "forward.layer.1.dense")) {
            entry.representation = NeuralTraceRepresentation::opaque_ciphertext;
        }
    }
    opaque_trace.validate(compiled.graph, invocation);
    expect_throw([&] {
        (void)make_neural_integrity_receipt(
            compiled.graph, invocation, opaque_trace, plan);
    }, "known-answer receipt from opaque ciphertext without client normalization");
    ++passed;

    auto wrong_binding = trace;
    wrong_binding.graph_digest[0] ^= 0x01u;
    expect_throw([&] { wrong_binding.validate(compiled.graph, invocation); },
                 "trace graph binding mismatch");
    ++passed;

    auto input_checkpoint = plan;
    input_checkpoint.checkpoints[0] =
        {"bad-input-port", 4, compiled.output_node, "activation"};
    expect_throw([&] { input_checkpoint.validate(compiled.graph); },
                 "integrity checkpoint on graph input port");
    ++passed;

    return passed;
}

} // namespace v0id::neural
