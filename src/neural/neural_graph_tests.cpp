#include "neural_graph.hpp"

#include <algorithm>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace v0id::neural;

void require(bool condition, const std::string& what) {
    if (!condition) throw std::runtime_error(what);
}

void expect_throw(const std::function<void()>& fn, const std::string& what) {
    try {
        fn();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("expected failure: " + what);
}

NeuralPort port(std::string name,
                NeuralPortDirection direction,
                NeuralPortRole role,
                std::vector<std::uint32_t> dimensions,
                bool mutable_state = false) {
    NeuralPort out;
    out.name = std::move(name);
    out.direction = direction;
    out.role = role;
    out.shape.dimensions = std::move(dimensions);
    out.format = NeuralNumericFormat::fixed16_16;
    out.mutable_state = mutable_state;
    return out;
}

NeuralGraph example_graph() {
    const std::vector<std::uint8_t> wasm_bytes{'n','e','u','r','a','l','-','w','a','s','m'};
    const auto wasm = v0id::net::describe_module(
        v0id::net::ModuleKind::neural_wasm,
        v0id::net::ModuleVisibility::private_local,
        "example.activation",
        1,
        wasm_bytes);

    NeuralGraph graph;
    graph.graph_id = "example-modular-nn";

    graph.nodes.push_back(NeuralModuleNode{"model", "", NeuralModuleOp::group, {}, std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{"encoder", "model", NeuralModuleOp::group, {}, std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "input", "encoder", NeuralModuleOp::input,
        {port("activation", NeuralPortDirection::output,
              NeuralPortRole::activation, {1, 4})},
        std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "dense", "encoder", NeuralModuleOp::dense,
        {
            port("x", NeuralPortDirection::input, NeuralPortRole::activation, {1, 4}),
            port("weight", NeuralPortDirection::input, NeuralPortRole::weight, {4, 3}, true),
            port("bias", NeuralPortDirection::input, NeuralPortRole::bias, {3}, true),
            port("y", NeuralPortDirection::output, NeuralPortRole::activation, {1, 3}),
        },
        std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "custom-activation", "encoder", NeuralModuleOp::wasm_custom,
        {
            port("x", NeuralPortDirection::input, NeuralPortRole::activation, {1, 3}),
            port("y", NeuralPortDirection::output, NeuralPortRole::activation, {1, 3}),
        },
        wasm});
    graph.nodes.push_back(NeuralModuleNode{
        "output", "model", NeuralModuleOp::output,
        {port("activation", NeuralPortDirection::input,
              NeuralPortRole::activation, {1, 3})},
        std::nullopt});

    graph.nodes.push_back(NeuralModuleNode{"trainer", "model", NeuralModuleOp::group, {}, std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "loss", "trainer", NeuralModuleOp::loss,
        {
            port("prediction", NeuralPortDirection::input, NeuralPortRole::activation, {1, 3}),
            port("loss", NeuralPortDirection::output, NeuralPortRole::loss, {1}),
            port("gradient", NeuralPortDirection::output, NeuralPortRole::gradient, {1, 3}),
        },
        std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "backprop", "trainer", NeuralModuleOp::backprop,
        {
            port("gradient_in", NeuralPortDirection::input, NeuralPortRole::gradient, {1, 3}),
            port("gradient_out", NeuralPortDirection::output, NeuralPortRole::gradient, {1, 4}),
            port("weight_gradient", NeuralPortDirection::output, NeuralPortRole::gradient, {4, 3}),
        },
        std::nullopt});
    graph.nodes.push_back(NeuralModuleNode{
        "weight-update", "trainer", NeuralModuleOp::weight_update,
        {
            port("weight", NeuralPortDirection::input, NeuralPortRole::weight, {4, 3}, true),
            port("gradient", NeuralPortDirection::input, NeuralPortRole::gradient, {4, 3}),
            port("updated_weight", NeuralPortDirection::output, NeuralPortRole::weight, {4, 3}, true),
        },
        std::nullopt});

    graph.edges.push_back(NeuralEdge{"input", "activation", "dense", "x"});
    graph.edges.push_back(NeuralEdge{"dense", "y", "custom-activation", "x"});
    graph.edges.push_back(NeuralEdge{"custom-activation", "y", "output", "activation"});
    graph.edges.push_back(NeuralEdge{"loss", "gradient", "backprop", "gradient_in"});
    graph.edges.push_back(NeuralEdge{"backprop", "weight_gradient", "weight-update", "gradient"});
    return graph;
}

} // namespace

int main() try {
    std::size_t passed = 0;

    auto graph = example_graph();
    graph.validate();
    ++passed;

    const auto digest = graph.digest512();
    require(std::any_of(digest.begin(), digest.end(), [](auto b) { return b != 0; }),
            "neural graph digest unexpectedly zero");
    ++passed;

    auto reordered = graph;
    std::reverse(reordered.nodes.begin(), reordered.nodes.end());
    std::reverse(reordered.edges.begin(), reordered.edges.end());
    require(reordered.digest512() == digest,
            "canonical neural graph digest changed under vector reordering");
    ++passed;

    NeuralInvocation plain;
    plain.execution_mode = NeuralExecutionMode::plain_cpu;
    plain.contexts.push_back(NeuralContextRef{
        "conversation",
        NeuralContextLocation::local_client,
        v0id::net::module_digest512(std::vector<std::uint8_t>{'l','o','c','a','l'})});
    plain.validate(graph);
    require(to_string(plain.execution_mode) == "PLAIN_CPU",
            "plain execution mode string mismatch");
    ++passed;

    auto encrypted = plain;
    encrypted.execution_mode = NeuralExecutionMode::tfhe_cuda;
    encrypted.contexts[0].location = NeuralContextLocation::cloud_content_addressed;
    encrypted.contexts[0].digest =
        v0id::net::module_digest512(std::vector<std::uint8_t>{'c','l','o','u','d'});
    encrypted.model_state_digest =
        v0id::net::module_digest512(std::vector<std::uint8_t>{'w','e','i','g','h','t','s'});
    encrypted.validate(graph);
    require(to_string(encrypted.execution_mode) == "TFHE_CUDA",
            "encrypted execution mode string mismatch");
    ++passed;

    require(plain.digest512(graph) != encrypted.digest512(graph),
            "plain and TFHE invocations must have different commitments");
    ++passed;

    auto multi_context = encrypted;
    multi_context.contexts.push_back(NeuralContextRef{
        "retrieval-cache",
        NeuralContextLocation::cloud_content_addressed,
        v0id::net::module_digest512(std::vector<std::uint8_t>{'c','a','c','h','e'})});
    const auto invocation_digest = multi_context.digest512(graph);
    std::reverse(multi_context.contexts.begin(), multi_context.contexts.end());
    require(multi_context.digest512(graph) == invocation_digest,
            "neural invocation digest changed under context vector reordering");
    ++passed;

    auto changed_context = multi_context;
    changed_context.contexts[0].digest =
        v0id::net::module_digest512(std::vector<std::uint8_t>{'o','t','h','e','r'});
    require(changed_context.digest512(graph) != invocation_digest,
            "changing selected context checksum did not change invocation commitment");
    ++passed;

    auto bad_shape = graph;
    for (auto& node : bad_shape.nodes) {
        if (node.id == "custom-activation") {
            for (auto& p : node.ports) {
                if (p.name == "x") p.shape.dimensions = {1, 2};
            }
        }
    }
    expect_throw([&] { bad_shape.validate(); }, "edge shape mismatch");
    ++passed;

    auto parent_cycle = graph;
    for (auto& node : parent_cycle.nodes) {
        if (node.id == "model") node.parent_id = "encoder";
    }
    expect_throw([&] { parent_cycle.validate(); }, "module-tree parent cycle");
    ++passed;

    auto wrong_module_kind = graph;
    const auto wrong = v0id::net::describe_module(
        v0id::net::ModuleKind::mathvm_wasm,
        v0id::net::ModuleVisibility::private_local,
        "wrong.kind",
        1,
        std::vector<std::uint8_t>{1,2,3});
    for (auto& node : wrong_module_kind.nodes) {
        if (node.id == "custom-activation") node.wasm_module = wrong;
    }
    expect_throw([&] { wrong_module_kind.validate(); }, "non-neural Wasm module reference");
    ++passed;

    auto bad_context = plain;
    bad_context.contexts[0].digest = {};
    expect_throw([&] { bad_context.validate(graph); }, "zero context checksum");
    ++passed;

    const std::vector<std::uint8_t> shared_bytes{'w','a','s','m','-','m','o','d'};
    v0id::net::ModuleBundle bundle;
    bundle.descriptor = v0id::net::describe_module(
        v0id::net::ModuleKind::neural_wasm,
        v0id::net::ModuleVisibility::shared_sync,
        "shared.neural.module",
        1,
        shared_bytes);
    bundle.bytes = shared_bytes;
    const auto wire = v0id::net::encode_shared_module_bundle(bundle);
    const auto decoded = v0id::net::decode_shared_module_bundle(wire.data(), wire.size());
    require(decoded.descriptor.kind == v0id::net::ModuleKind::neural_wasm &&
            decoded.descriptor.digest == bundle.descriptor.digest &&
            decoded.bytes == bundle.bytes,
            "NEURAL_WASM module-sync round trip failed");
    ++passed;

    std::cout << "V0ID neural graph tests PASS: " << passed << "/" << passed << '\n';
    std::cout << "module tree          : YES\n"
              << "typed dataflow       : YES\n"
              << "local context hash   : YES\n"
              << "cloud context hash   : YES\n"
              << "plain mode           : YES\n"
              << "TFHE mode            : ABI/selection scaffold\n"
              << "invocation commitment: YES\n"
              << "neural Wasm kind     : YES\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID neural graph tests FAILED: " << e.what() << '\n';
    return 1;
}
