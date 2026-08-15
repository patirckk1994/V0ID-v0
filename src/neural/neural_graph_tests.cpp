#include "mlp_precompiler.hpp"
#include "neural_graph.hpp"
#include "neural_integrity_regression.hpp"

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

const NeuralModuleNode& require_node(const NeuralGraph& graph, const std::string& id) {
    const auto it = std::find_if(graph.nodes.begin(), graph.nodes.end(),
                                 [&](const auto& node) { return node.id == id; });
    if (it == graph.nodes.end())
        throw std::runtime_error("missing neural node: " + id);
    return *it;
}

const NeuralPort& require_port(const NeuralModuleNode& node, const std::string& name) {
    const auto it = std::find_if(node.ports.begin(), node.ports.end(),
                                 [&](const auto& p) { return p.name == name; });
    if (it == node.ports.end())
        throw std::runtime_error("missing neural port: " + node.id + "." + name);
    return *it;
}

bool has_edge(const NeuralGraph& graph,
              const std::string& from_node,
              const std::string& from_port,
              const std::string& to_node,
              const std::string& to_port) {
    return std::any_of(graph.edges.begin(), graph.edges.end(), [&](const auto& edge) {
        return edge.from_node == from_node && edge.from_port == from_port &&
               edge.to_node == to_node && edge.to_port == to_port;
    });
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

    MlpPrecompileSpec inference_spec;
    inference_spec.graph_id = "mlp-inference";
    inference_spec.batch_size = 2;
    inference_spec.input_size = 4;
    inference_spec.layers = {{8, true}, {6, true}, {3, false}};
    inference_spec.training = MlpTrainingMode::inference;
    const auto inference = MlpPortPrecompiler::compile(inference_spec);
    require(inference.dense_nodes.size() == 3 &&
            inference.weight_nodes.size() == 3 &&
            inference.bias_nodes.size() == 3 &&
            inference.activation_nodes.size() == 2 &&
            inference.backprop_nodes.empty() &&
            inference.weight_update_nodes.empty(),
            "MLP inference precompiler expansion counts mismatch");
    ++passed;

    const auto& dense0 = require_node(inference.graph, "forward.layer.0.dense");
    require(require_port(dense0, "x").shape.dimensions ==
                std::vector<std::uint32_t>({2, 4}) &&
            require_port(dense0, "weight").shape.dimensions ==
                std::vector<std::uint32_t>({4, 8}) &&
            require_port(dense0, "bias").shape.dimensions ==
                std::vector<std::uint32_t>({8}) &&
            require_port(dense0, "y").shape.dimensions ==
                std::vector<std::uint32_t>({2, 8}),
            "MLP dense macro did not derive generic matrix/port dimensions");
    ++passed;

    const auto& dense2 = require_node(inference.graph, "forward.layer.2.dense");
    require(require_port(dense2, "weight").shape.dimensions ==
                std::vector<std::uint32_t>({6, 3}) &&
            has_edge(inference.graph,
                     "forward.layer.1.activation", "y",
                     "forward.layer.2.dense", "x") &&
            has_edge(inference.graph,
                     "forward.layer.2.dense", "y",
                     inference.output_node, "activation"),
            "MLP forward layer wiring mismatch");
    ++passed;

    auto training_spec = inference_spec;
    training_spec.graph_id = "mlp-training";
    training_spec.training = MlpTrainingMode::backprop_sgd;
    const auto training = MlpPortPrecompiler::compile(training_spec);
    require(training.backprop_nodes.size() == 3 &&
            training.weight_update_nodes.size() == 3 &&
            !training.loss_node.empty() &&
            !training.target_node.empty() &&
            !training.learning_rate_node.empty(),
            "MLP training precompiler did not emit loss/backprop/SGD structure");
    ++passed;

    const auto& bp2 = require_node(training.graph, "trainer.layer.2.backprop");
    const auto& update2 = require_node(training.graph, "trainer.layer.2.weight-update");
    require(require_port(bp2, "gradient_in").shape.dimensions ==
                std::vector<std::uint32_t>({2, 3}) &&
            require_port(bp2, "gradient_out").shape.dimensions ==
                std::vector<std::uint32_t>({2, 6}) &&
            require_port(bp2, "weight_gradient").shape.dimensions ==
                std::vector<std::uint32_t>({6, 3}) &&
            require_port(update2, "updated_weight").shape.dimensions ==
                std::vector<std::uint32_t>({6, 3}) &&
            require_port(update2, "updated_bias").shape.dimensions ==
                std::vector<std::uint32_t>({3}),
            "MLP backprop/weight-update macro dimensions mismatch");
    ++passed;

    require(has_edge(training.graph,
                     training.loss_node, "gradient",
                     "trainer.layer.2.backprop", "gradient_in") &&
            has_edge(training.graph,
                     "trainer.layer.2.backprop", "gradient_out",
                     "trainer.layer.1.backprop", "gradient_in") &&
            has_edge(training.graph,
                     "trainer.layer.0.backprop", "weight_gradient",
                     "trainer.layer.0.weight-update", "weight_gradient") &&
            has_edge(training.graph,
                     training.learning_rate_node, "learning_rate",
                     "trainer.layer.0.weight-update", "learning_rate"),
            "MLP training reverse/SGD wiring mismatch");
    ++passed;

    const auto training_digest = training.graph.digest512();
    const auto training_again = MlpPortPrecompiler::compile(training_spec);
    require(training_again.graph.digest512() == training_digest,
            "MLP precompiler is not deterministic");
    ++passed;

    auto changed_width_spec = training_spec;
    changed_width_spec.layers[1].width = 7;
    require(MlpPortPrecompiler::compile(changed_width_spec).graph.digest512() !=
                training_digest,
            "MLP graph commitment ignored layer width change");
    ++passed;

    auto invalid_spec = inference_spec;
    invalid_spec.input_size = 0;
    expect_throw([&] { (void)MlpPortPrecompiler::compile(invalid_spec); },
                 "zero MLP input width");
    invalid_spec = inference_spec;
    invalid_spec.layers[1].width = 0;
    expect_throw([&] { (void)MlpPortPrecompiler::compile(invalid_spec); },
                 "zero MLP layer width");
    ++passed;

    passed += run_neural_integrity_regression_tests();

    std::cout << "V0ID neural graph tests PASS: " << passed << "/" << passed << '\n';
    std::cout << "module tree          : YES\n"
              << "typed dataflow       : YES\n"
              << "local context hash   : YES\n"
              << "cloud context hash   : YES\n"
              << "plain mode           : YES\n"
              << "TFHE mode            : ABI/selection scaffold\n"
              << "invocation commitment: YES\n"
              << "neural Wasm kind     : YES\n"
              << "MLP port precompiler : YES\n"
              << "generic weight matrix: YES\n"
              << "backprop macro       : YES\n"
              << "SGD update macro     : YES\n"
              << "execution trace      : STRUCTURAL COMMITMENT\n"
              << "integrity checkpoints: ORDINARY OUTPUT PORTS\n"
              << "known-answer receipt : YES\n"
              << "semantic proof       : NOT CLAIMED\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID neural graph tests FAILED: " << e.what() << '\n';
    return 1;
}