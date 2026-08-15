#pragma once

#include "neural_graph.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace v0id::neural {

enum class MlpTrainingMode : std::uint8_t {
    inference = 1,
    backprop_sgd = 2,
};

struct MlpLayerSpec {
    std::uint32_t width{};
    bool activation{true};
};

struct MlpPrecompileSpec {
    std::string graph_id{"mlp"};
    std::uint64_t graph_version{1};
    std::uint32_t batch_size{1};
    std::uint32_t input_size{};
    std::vector<MlpLayerSpec> layers;
    NeuralNumericFormat format{NeuralNumericFormat::fixed16_16};
    MlpTrainingMode training{MlpTrainingMode::inference};
};

struct MlpCompiledGraph {
    NeuralGraph graph;

    std::string input_node;
    std::string output_node;
    std::string target_node;
    std::string loss_node;
    std::string learning_rate_node;

    std::vector<std::string> dense_nodes;
    std::vector<std::string> activation_nodes;
    std::vector<std::string> weight_nodes;
    std::vector<std::string> bias_nodes;
    std::vector<std::string> backprop_nodes;
    std::vector<std::string> weight_update_nodes;
};

// Expands a compact multilayer-perceptron description into the low-level V0ID
// NeuralGraph port/dataflow representation. It is deliberately backend-neutral:
// the same compiled graph can be selected by a PLAIN_CPU or TFHE_CUDA invocation.
class MlpPortPrecompiler {
public:
    static MlpCompiledGraph compile(const MlpPrecompileSpec& spec) {
        validate_spec(spec);

        MlpCompiledGraph out;
        out.graph.graph_id = spec.graph_id;
        out.graph.graph_version = spec.graph_version;

        auto& graph = out.graph;
        graph.nodes.push_back(node("model", "", NeuralModuleOp::group, {}));
        graph.nodes.push_back(node("forward", "model", NeuralModuleOp::group, {}));
        graph.nodes.push_back(node("parameters", "model", NeuralModuleOp::group, {}));

        out.input_node = "forward.input";
        graph.nodes.push_back(node(
            out.input_node,
            "forward",
            NeuralModuleOp::input,
            {port("activation", NeuralPortDirection::output,
                  NeuralPortRole::activation,
                  {spec.batch_size, spec.input_size}, spec.format)}));

        struct Endpoint {
            std::string node_id;
            std::string port_name;
        };

        struct LayerExpansion {
            std::uint32_t input_width{};
            std::uint32_t output_width{};
            Endpoint forward_input;
            Endpoint preactivation;
            Endpoint forward_output;
            std::string weight_node;
            std::string bias_node;
        };

        std::vector<LayerExpansion> expanded;
        expanded.reserve(spec.layers.size());

        Endpoint current{out.input_node, "activation"};
        std::uint32_t input_width = spec.input_size;

        for (std::size_t i = 0; i < spec.layers.size(); ++i) {
            const auto output_width = spec.layers[i].width;
            const auto prefix = std::string("layer.") + std::to_string(i);
            const auto weight_id = "parameters." + prefix + ".weight";
            const auto bias_id = "parameters." + prefix + ".bias";
            const auto dense_id = "forward." + prefix + ".dense";

            graph.nodes.push_back(node(
                weight_id,
                "parameters",
                NeuralModuleOp::input,
                {port("weight", NeuralPortDirection::output,
                      NeuralPortRole::weight,
                      {input_width, output_width}, spec.format, true)}));
            graph.nodes.push_back(node(
                bias_id,
                "parameters",
                NeuralModuleOp::input,
                {port("bias", NeuralPortDirection::output,
                      NeuralPortRole::bias,
                      {output_width}, spec.format, true)}));

            graph.nodes.push_back(node(
                dense_id,
                "forward",
                NeuralModuleOp::dense,
                {
                    port("x", NeuralPortDirection::input,
                         NeuralPortRole::activation,
                         {spec.batch_size, input_width}, spec.format),
                    port("weight", NeuralPortDirection::input,
                         NeuralPortRole::weight,
                         {input_width, output_width}, spec.format, true),
                    port("bias", NeuralPortDirection::input,
                         NeuralPortRole::bias,
                         {output_width}, spec.format, true),
                    port("y", NeuralPortDirection::output,
                         NeuralPortRole::activation,
                         {spec.batch_size, output_width}, spec.format),
                }));

            graph.edges.push_back({current.node_id, current.port_name, dense_id, "x"});
            graph.edges.push_back({weight_id, "weight", dense_id, "weight"});
            graph.edges.push_back({bias_id, "bias", dense_id, "bias"});

            out.dense_nodes.push_back(dense_id);
            out.weight_nodes.push_back(weight_id);
            out.bias_nodes.push_back(bias_id);

            const Endpoint preactivation{dense_id, "y"};
            Endpoint layer_output = preactivation;
            if (spec.layers[i].activation) {
                const auto activation_id = "forward." + prefix + ".activation";
                graph.nodes.push_back(node(
                    activation_id,
                    "forward",
                    NeuralModuleOp::activation,
                    {
                        port("x", NeuralPortDirection::input,
                             NeuralPortRole::activation,
                             {spec.batch_size, output_width}, spec.format),
                        port("y", NeuralPortDirection::output,
                             NeuralPortRole::activation,
                             {spec.batch_size, output_width}, spec.format),
                    }));
                graph.edges.push_back({dense_id, "y", activation_id, "x"});
                layer_output = Endpoint{activation_id, "y"};
                out.activation_nodes.push_back(activation_id);
            }

            expanded.push_back(LayerExpansion{
                input_width,
                output_width,
                current,
                preactivation,
                layer_output,
                weight_id,
                bias_id,
            });

            current = layer_output;
            input_width = output_width;
        }

        out.output_node = "forward.output";
        graph.nodes.push_back(node(
            out.output_node,
            "forward",
            NeuralModuleOp::output,
            {port("activation", NeuralPortDirection::input,
                  NeuralPortRole::activation,
                  {spec.batch_size, input_width}, spec.format)}));
        graph.edges.push_back({current.node_id, current.port_name,
                               out.output_node, "activation"});

        if (spec.training == MlpTrainingMode::backprop_sgd) {
            graph.nodes.push_back(node("trainer", "model", NeuralModuleOp::group, {}));

            out.target_node = "trainer.target";
            graph.nodes.push_back(node(
                out.target_node,
                "trainer",
                NeuralModuleOp::input,
                {port("target", NeuralPortDirection::output,
                      NeuralPortRole::activation,
                      {spec.batch_size, input_width}, spec.format)}));

            out.loss_node = "trainer.loss";
            graph.nodes.push_back(node(
                out.loss_node,
                "trainer",
                NeuralModuleOp::loss,
                {
                    port("prediction", NeuralPortDirection::input,
                         NeuralPortRole::activation,
                         {spec.batch_size, input_width}, spec.format),
                    port("target", NeuralPortDirection::input,
                         NeuralPortRole::activation,
                         {spec.batch_size, input_width}, spec.format),
                    port("loss", NeuralPortDirection::output,
                         NeuralPortRole::loss,
                         {1}, spec.format),
                    port("gradient", NeuralPortDirection::output,
                         NeuralPortRole::gradient,
                         {spec.batch_size, input_width}, spec.format),
                }));
            graph.edges.push_back({current.node_id, current.port_name,
                                   out.loss_node, "prediction"});
            graph.edges.push_back({out.target_node, "target",
                                   out.loss_node, "target"});

            out.learning_rate_node = "trainer.learning-rate";
            graph.nodes.push_back(node(
                out.learning_rate_node,
                "trainer",
                NeuralModuleOp::input,
                {port("learning_rate", NeuralPortDirection::output,
                      NeuralPortRole::control,
                      {1}, spec.format)}));

            Endpoint gradient_source{out.loss_node, "gradient"};

            for (std::size_t reverse = expanded.size(); reverse-- > 0;) {
                const auto& layer = expanded[reverse];
                const auto prefix = std::string("layer.") + std::to_string(reverse);
                const auto backprop_id = "trainer." + prefix + ".backprop";
                const auto update_id = "trainer." + prefix + ".weight-update";

                graph.nodes.push_back(node(
                    backprop_id,
                    "trainer",
                    NeuralModuleOp::backprop,
                    {
                        port("gradient_in", NeuralPortDirection::input,
                             NeuralPortRole::gradient,
                             {spec.batch_size, layer.output_width}, spec.format),
                        port("activation_in", NeuralPortDirection::input,
                             NeuralPortRole::activation,
                             {spec.batch_size, layer.input_width}, spec.format),
                        port("preactivation", NeuralPortDirection::input,
                             NeuralPortRole::activation,
                             {spec.batch_size, layer.output_width}, spec.format),
                        port("activation_out", NeuralPortDirection::input,
                             NeuralPortRole::activation,
                             {spec.batch_size, layer.output_width}, spec.format),
                        port("weight", NeuralPortDirection::input,
                             NeuralPortRole::weight,
                             {layer.input_width, layer.output_width}, spec.format, true),
                        port("gradient_out", NeuralPortDirection::output,
                             NeuralPortRole::gradient,
                             {spec.batch_size, layer.input_width}, spec.format),
                        port("weight_gradient", NeuralPortDirection::output,
                             NeuralPortRole::gradient,
                             {layer.input_width, layer.output_width}, spec.format),
                        port("bias_gradient", NeuralPortDirection::output,
                             NeuralPortRole::gradient,
                             {layer.output_width}, spec.format),
                    }));

                graph.edges.push_back({gradient_source.node_id,
                                       gradient_source.port_name,
                                       backprop_id,
                                       "gradient_in"});
                graph.edges.push_back({layer.forward_input.node_id,
                                       layer.forward_input.port_name,
                                       backprop_id,
                                       "activation_in"});
                graph.edges.push_back({layer.preactivation.node_id,
                                       layer.preactivation.port_name,
                                       backprop_id,
                                       "preactivation"});
                graph.edges.push_back({layer.forward_output.node_id,
                                       layer.forward_output.port_name,
                                       backprop_id,
                                       "activation_out"});
                graph.edges.push_back({layer.weight_node,
                                       "weight",
                                       backprop_id,
                                       "weight"});

                graph.nodes.push_back(node(
                    update_id,
                    "trainer",
                    NeuralModuleOp::weight_update,
                    {
                        port("weight", NeuralPortDirection::input,
                             NeuralPortRole::weight,
                             {layer.input_width, layer.output_width}, spec.format, true),
                        port("weight_gradient", NeuralPortDirection::input,
                             NeuralPortRole::gradient,
                             {layer.input_width, layer.output_width}, spec.format),
                        port("bias", NeuralPortDirection::input,
                             NeuralPortRole::bias,
                             {layer.output_width}, spec.format, true),
                        port("bias_gradient", NeuralPortDirection::input,
                             NeuralPortRole::gradient,
                             {layer.output_width}, spec.format),
                        port("learning_rate", NeuralPortDirection::input,
                             NeuralPortRole::control,
                             {1}, spec.format),
                        port("updated_weight", NeuralPortDirection::output,
                             NeuralPortRole::weight,
                             {layer.input_width, layer.output_width}, spec.format, true),
                        port("updated_bias", NeuralPortDirection::output,
                             NeuralPortRole::bias,
                             {layer.output_width}, spec.format, true),
                    }));

                graph.edges.push_back({layer.weight_node, "weight",
                                       update_id, "weight"});
                graph.edges.push_back({backprop_id, "weight_gradient",
                                       update_id, "weight_gradient"});
                graph.edges.push_back({layer.bias_node, "bias",
                                       update_id, "bias"});
                graph.edges.push_back({backprop_id, "bias_gradient",
                                       update_id, "bias_gradient"});
                graph.edges.push_back({out.learning_rate_node, "learning_rate",
                                       update_id, "learning_rate"});

                out.backprop_nodes.push_back(backprop_id);
                out.weight_update_nodes.push_back(update_id);
                gradient_source = Endpoint{backprop_id, "gradient_out"};
            }
        }

        graph.validate();
        return out;
    }

private:
    static NeuralPort port(std::string name,
                           NeuralPortDirection direction,
                           NeuralPortRole role,
                           std::vector<std::uint32_t> dimensions,
                           NeuralNumericFormat format,
                           bool mutable_state = false) {
        NeuralPort out;
        out.name = std::move(name);
        out.direction = direction;
        out.role = role;
        out.shape.dimensions = std::move(dimensions);
        out.format = format;
        out.mutable_state = mutable_state;
        return out;
    }

    static NeuralModuleNode node(std::string id,
                                 std::string parent_id,
                                 NeuralModuleOp op,
                                 std::vector<NeuralPort> ports) {
        NeuralModuleNode out;
        out.id = std::move(id);
        out.parent_id = std::move(parent_id);
        out.op = op;
        out.ports = std::move(ports);
        return out;
    }

    static void validate_spec(const MlpPrecompileSpec& spec) {
        if (spec.graph_id.empty() || spec.graph_version == 0)
            throw std::runtime_error("MLP precompiler requires graph id/version");
        if (spec.batch_size == 0)
            throw std::runtime_error("MLP precompiler batch size must be nonzero");
        if (spec.input_size == 0)
            throw std::runtime_error("MLP precompiler input size must be nonzero");
        if (spec.layers.empty())
            throw std::runtime_error("MLP precompiler requires at least one layer");
        for (const auto& layer : spec.layers) {
            if (layer.width == 0)
                throw std::runtime_error("MLP precompiler layer width must be nonzero");
        }
        switch (spec.training) {
            case MlpTrainingMode::inference:
            case MlpTrainingMode::backprop_sgd:
                break;
            default:
                throw std::runtime_error("unknown MLP training mode");
        }
    }
};

} // namespace v0id::neural
