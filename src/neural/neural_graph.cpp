#include "neural_graph.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace v0id::neural {
namespace {

constexpr std::size_t MAX_TENSOR_RANK = 8;
constexpr std::size_t MAX_GRAPH_NODES = 4096;
constexpr std::size_t MAX_NODE_PORTS = 256;
constexpr std::size_t MAX_GRAPH_EDGES = 65536;
constexpr std::size_t MAX_CONTEXTS = 256;

bool digest_all_zero(const NeuralDigest512& digest) {
    return std::all_of(digest.begin(), digest.end(),
                       [](std::uint8_t b) { return b == 0; });
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

void put_string(std::vector<std::uint8_t>& out, std::string_view value) {
    put_u64(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void put_digest(std::vector<std::uint8_t>& out, const NeuralDigest512& digest) {
    out.insert(out.end(), digest.begin(), digest.end());
}

void validate_execution_mode(NeuralExecutionMode mode) {
    switch (mode) {
        case NeuralExecutionMode::plain_cpu:
        case NeuralExecutionMode::tfhe_cuda:
            return;
    }
    throw std::runtime_error("unknown neural execution mode");
}

void validate_numeric_format(NeuralNumericFormat format) {
    switch (format) {
        case NeuralNumericFormat::uint8:
        case NeuralNumericFormat::int8:
        case NeuralNumericFormat::uint16:
        case NeuralNumericFormat::int16:
        case NeuralNumericFormat::fixed16_16:
        case NeuralNumericFormat::fixed8_24:
            return;
    }
    throw std::runtime_error("unknown neural numeric format");
}

void validate_port_direction(NeuralPortDirection direction) {
    switch (direction) {
        case NeuralPortDirection::input:
        case NeuralPortDirection::output:
            return;
    }
    throw std::runtime_error("unknown neural port direction");
}

void validate_port_role(NeuralPortRole role) {
    switch (role) {
        case NeuralPortRole::activation:
        case NeuralPortRole::gradient:
        case NeuralPortRole::weight:
        case NeuralPortRole::bias:
        case NeuralPortRole::context:
        case NeuralPortRole::loss:
        case NeuralPortRole::control:
            return;
    }
    throw std::runtime_error("unknown neural port role");
}

void validate_module_op(NeuralModuleOp op) {
    switch (op) {
        case NeuralModuleOp::group:
        case NeuralModuleOp::input:
        case NeuralModuleOp::output:
        case NeuralModuleOp::dense:
        case NeuralModuleOp::activation:
        case NeuralModuleOp::loss:
        case NeuralModuleOp::backprop:
        case NeuralModuleOp::weight_update:
        case NeuralModuleOp::wasm_custom:
            return;
    }
    throw std::runtime_error("unknown neural module operation");
}

void validate_context_location(NeuralContextLocation location) {
    switch (location) {
        case NeuralContextLocation::local_client:
        case NeuralContextLocation::cloud_content_addressed:
            return;
    }
    throw std::runtime_error("unknown neural context location");
}

void validate_wasm_descriptor(const v0id::net::ModuleDescriptor& descriptor) {
    if (descriptor.protocol_id != "v0id-module-sync-v1")
        throw std::runtime_error("neural Wasm module uses unsupported module-sync protocol");
    if (descriptor.kind != v0id::net::ModuleKind::neural_wasm)
        throw std::runtime_error("neural Wasm node must reference a NEURAL_WASM module");
    switch (descriptor.visibility) {
        case v0id::net::ModuleVisibility::private_local:
        case v0id::net::ModuleVisibility::shared_sync:
            break;
        default:
            throw std::runtime_error("neural Wasm module has invalid visibility");
    }
    if (descriptor.module_id.empty() || descriptor.module_version == 0)
        throw std::runtime_error("neural Wasm module descriptor missing id/version");
    if (descriptor.byte_size == 0 || digest_all_zero(descriptor.digest))
        throw std::runtime_error("neural Wasm module descriptor lacks content identity");
}

const NeuralPort& require_port(const NeuralModuleNode& node,
                               const std::string& name) {
    const auto it = std::find_if(node.ports.begin(), node.ports.end(),
                                 [&](const NeuralPort& port) {
                                     return port.name == name;
                                 });
    if (it == node.ports.end())
        throw std::runtime_error("neural edge references unknown port " +
                                 node.id + "." + name);
    return *it;
}

std::string endpoint_key(const std::string& node, const std::string& port) {
    return node + "\x1f" + port;
}

} // namespace

std::size_t TensorShape::element_count() const {
    validate();
    std::size_t total = 1;
    for (const auto dimension : dimensions) {
        if (total > std::numeric_limits<std::size_t>::max() / dimension)
            throw std::runtime_error("neural tensor element count overflows size_t");
        total *= dimension;
    }
    return total;
}

void TensorShape::validate() const {
    if (dimensions.empty() || dimensions.size() > MAX_TENSOR_RANK)
        throw std::runtime_error("neural tensor rank must be in [1,8]");
    for (const auto dimension : dimensions) {
        if (dimension == 0)
            throw std::runtime_error("neural tensor dimensions must be nonzero");
    }
}

void NeuralGraph::validate() const {
    if (protocol_id != "v0id-neural-graph-v1")
        throw std::runtime_error("unsupported neural graph protocol");
    if (graph_id.empty() || graph_version == 0)
        throw std::runtime_error("neural graph requires id/version");
    if (nodes.empty() || nodes.size() > MAX_GRAPH_NODES)
        throw std::runtime_error("neural graph node count outside limit");
    if (edges.size() > MAX_GRAPH_EDGES)
        throw std::runtime_error("neural graph edge count outside limit");

    std::unordered_map<std::string, const NeuralModuleNode*> by_id;
    by_id.reserve(nodes.size());

    for (const auto& node : nodes) {
        if (node.id.empty())
            throw std::runtime_error("neural module node id must not be empty");
        validate_module_op(node.op);
        if (!by_id.emplace(node.id, &node).second)
            throw std::runtime_error("duplicate neural module node id: " + node.id);
        if (node.ports.size() > MAX_NODE_PORTS)
            throw std::runtime_error("neural module has too many ports: " + node.id);

        std::unordered_set<std::string> port_names;
        for (const auto& port : node.ports) {
            if (port.name.empty())
                throw std::runtime_error("neural port name must not be empty");
            if (!port_names.insert(port.name).second)
                throw std::runtime_error("duplicate neural port name on node: " + node.id);
            validate_port_direction(port.direction);
            validate_port_role(port.role);
            validate_numeric_format(port.format);
            port.shape.validate();
        }

        if (node.op == NeuralModuleOp::wasm_custom) {
            if (!node.wasm_module)
                throw std::runtime_error("WASM_CUSTOM neural node lacks module descriptor");
            validate_wasm_descriptor(*node.wasm_module);
        } else if (node.wasm_module) {
            throw std::runtime_error("only WASM_CUSTOM neural nodes may carry Wasm descriptors");
        }
    }

    // Validate the composition tree independently from the dataflow graph.
    for (const auto& node : nodes) {
        if (node.parent_id.empty())
            continue;
        if (!by_id.contains(node.parent_id))
            throw std::runtime_error("neural module parent does not exist: " + node.parent_id);
        if (node.parent_id == node.id)
            throw std::runtime_error("neural module cannot parent itself");

        std::unordered_set<std::string> seen;
        const NeuralModuleNode* current = &node;
        while (!current->parent_id.empty()) {
            if (!seen.insert(current->id).second)
                throw std::runtime_error("cycle in neural module composition tree");
            const auto parent = by_id.find(current->parent_id);
            if (parent == by_id.end())
                throw std::runtime_error("neural module parent vanished during validation");
            current = parent->second;
        }
    }

    std::unordered_set<std::string> driven_inputs;
    std::unordered_set<std::string> edge_ids;
    for (const auto& edge : edges) {
        const auto source_it = by_id.find(edge.from_node);
        const auto dest_it = by_id.find(edge.to_node);
        if (source_it == by_id.end() || dest_it == by_id.end())
            throw std::runtime_error("neural edge references unknown node");

        const auto& source = require_port(*source_it->second, edge.from_port);
        const auto& dest = require_port(*dest_it->second, edge.to_port);
        if (source.direction != NeuralPortDirection::output)
            throw std::runtime_error("neural edge source port is not an output");
        if (dest.direction != NeuralPortDirection::input)
            throw std::runtime_error("neural edge destination port is not an input");
        if (source.shape != dest.shape || source.format != dest.format ||
            source.role != dest.role)
            throw std::runtime_error("neural edge port schema mismatch");

        const auto dest_key = endpoint_key(edge.to_node, edge.to_port);
        if (!driven_inputs.insert(dest_key).second)
            throw std::runtime_error("neural input port has multiple graph drivers: " + dest_key);

        const auto edge_key = endpoint_key(edge.from_node, edge.from_port) + "->" + dest_key;
        if (!edge_ids.insert(edge_key).second)
            throw std::runtime_error("duplicate neural dataflow edge");
    }
}

NeuralDigest512 NeuralGraph::digest512() const {
    validate();

    std::vector<const NeuralModuleNode*> sorted_nodes;
    sorted_nodes.reserve(nodes.size());
    for (const auto& node : nodes) sorted_nodes.push_back(&node);
    std::sort(sorted_nodes.begin(), sorted_nodes.end(),
              [](const auto* a, const auto* b) { return a->id < b->id; });

    std::vector<NeuralEdge> sorted_edges = edges;
    std::sort(sorted_edges.begin(), sorted_edges.end(), [](const auto& a, const auto& b) {
        return std::tie(a.from_node, a.from_port, a.to_node, a.to_port) <
               std::tie(b.from_node, b.from_port, b.to_node, b.to_port);
    });

    std::vector<std::uint8_t> canonical;
    put_string(canonical, "V0ID-NEURAL-GRAPH-CANONICAL-v1");
    put_string(canonical, protocol_id);
    put_string(canonical, graph_id);
    put_u64(canonical, graph_version);
    put_u64(canonical, static_cast<std::uint64_t>(sorted_nodes.size()));

    for (const auto* node : sorted_nodes) {
        put_string(canonical, node->id);
        put_string(canonical, node->parent_id);
        put_u64(canonical, static_cast<std::uint64_t>(node->op));

        std::vector<NeuralPort> ports = node->ports;
        std::sort(ports.begin(), ports.end(),
                  [](const auto& a, const auto& b) { return a.name < b.name; });
        put_u64(canonical, static_cast<std::uint64_t>(ports.size()));
        for (const auto& port : ports) {
            put_string(canonical, port.name);
            put_u64(canonical, static_cast<std::uint64_t>(port.direction));
            put_u64(canonical, static_cast<std::uint64_t>(port.role));
            put_u64(canonical, static_cast<std::uint64_t>(port.format));
            put_u64(canonical, port.mutable_state ? 1u : 0u);
            put_u64(canonical, static_cast<std::uint64_t>(port.shape.dimensions.size()));
            for (const auto dimension : port.shape.dimensions)
                put_u64(canonical, dimension);
        }

        put_u64(canonical, node->wasm_module ? 1u : 0u);
        if (node->wasm_module) {
            const auto& module = *node->wasm_module;
            put_string(canonical, module.protocol_id);
            put_u64(canonical, static_cast<std::uint64_t>(module.kind));
            put_u64(canonical, static_cast<std::uint64_t>(module.visibility));
            put_string(canonical, module.module_id);
            put_u64(canonical, module.module_version);
            put_u64(canonical, module.byte_size);
            put_digest(canonical, module.digest);
        }
    }

    put_u64(canonical, static_cast<std::uint64_t>(sorted_edges.size()));
    for (const auto& edge : sorted_edges) {
        put_string(canonical, edge.from_node);
        put_string(canonical, edge.from_port);
        put_string(canonical, edge.to_node);
        put_string(canonical, edge.to_port);
    }

    return v0id::net::module_digest512(canonical);
}

void NeuralInvocation::validate(const NeuralGraph& graph) const {
    graph.validate();
    validate_execution_mode(execution_mode);
    if (contexts.size() > MAX_CONTEXTS)
        throw std::runtime_error("neural invocation has too many contexts");

    std::unordered_set<std::string> names;
    for (const auto& context : contexts) {
        if (context.name.empty())
            throw std::runtime_error("neural context reference name must not be empty");
        if (!names.insert(context.name).second)
            throw std::runtime_error("duplicate neural context reference name");
        validate_context_location(context.location);
        if (digest_all_zero(context.digest))
            throw std::runtime_error("neural context reference requires a nonzero checksum");
    }

    if (model_state_digest && digest_all_zero(*model_state_digest))
        throw std::runtime_error("neural model-state checksum must be nonzero when present");
}

NeuralDigest512 NeuralInvocation::digest512(const NeuralGraph& graph) const {
    validate(graph);

    std::vector<NeuralContextRef> sorted_contexts = contexts;
    std::sort(sorted_contexts.begin(), sorted_contexts.end(),
              [](const auto& a, const auto& b) { return a.name < b.name; });

    std::vector<std::uint8_t> canonical;
    put_string(canonical, "V0ID-NEURAL-INVOCATION-v1");
    put_digest(canonical, graph.digest512());
    put_u64(canonical, static_cast<std::uint64_t>(execution_mode));
    put_u64(canonical, static_cast<std::uint64_t>(sorted_contexts.size()));
    for (const auto& context : sorted_contexts) {
        put_string(canonical, context.name);
        put_u64(canonical, static_cast<std::uint64_t>(context.location));
        put_digest(canonical, context.digest);
    }
    put_u64(canonical, model_state_digest ? 1u : 0u);
    if (model_state_digest)
        put_digest(canonical, *model_state_digest);

    return v0id::net::module_digest512(canonical);
}

std::string to_string(NeuralExecutionMode mode) {
    switch (mode) {
        case NeuralExecutionMode::plain_cpu: return "PLAIN_CPU";
        case NeuralExecutionMode::tfhe_cuda: return "TFHE_CUDA";
    }
    return "UNKNOWN_NEURAL_EXECUTION_MODE";
}

std::string to_string(NeuralNumericFormat format) {
    switch (format) {
        case NeuralNumericFormat::uint8: return "UINT8";
        case NeuralNumericFormat::int8: return "INT8";
        case NeuralNumericFormat::uint16: return "UINT16";
        case NeuralNumericFormat::int16: return "INT16";
        case NeuralNumericFormat::fixed16_16: return "FIXED16_16";
        case NeuralNumericFormat::fixed8_24: return "FIXED8_24";
    }
    return "UNKNOWN_NEURAL_NUMERIC_FORMAT";
}

std::string to_string(NeuralPortDirection direction) {
    switch (direction) {
        case NeuralPortDirection::input: return "INPUT";
        case NeuralPortDirection::output: return "OUTPUT";
    }
    return "UNKNOWN_NEURAL_PORT_DIRECTION";
}

std::string to_string(NeuralPortRole role) {
    switch (role) {
        case NeuralPortRole::activation: return "ACTIVATION";
        case NeuralPortRole::gradient: return "GRADIENT";
        case NeuralPortRole::weight: return "WEIGHT";
        case NeuralPortRole::bias: return "BIAS";
        case NeuralPortRole::context: return "CONTEXT";
        case NeuralPortRole::loss: return "LOSS";
        case NeuralPortRole::control: return "CONTROL";
    }
    return "UNKNOWN_NEURAL_PORT_ROLE";
}

std::string to_string(NeuralModuleOp op) {
    switch (op) {
        case NeuralModuleOp::group: return "GROUP";
        case NeuralModuleOp::input: return "INPUT";
        case NeuralModuleOp::output: return "OUTPUT";
        case NeuralModuleOp::dense: return "DENSE";
        case NeuralModuleOp::activation: return "ACTIVATION";
        case NeuralModuleOp::loss: return "LOSS";
        case NeuralModuleOp::backprop: return "BACKPROP";
        case NeuralModuleOp::weight_update: return "WEIGHT_UPDATE";
        case NeuralModuleOp::wasm_custom: return "WASM_CUSTOM";
    }
    return "UNKNOWN_NEURAL_MODULE_OP";
}

std::string to_string(NeuralContextLocation location) {
    switch (location) {
        case NeuralContextLocation::local_client: return "LOCAL_CLIENT";
        case NeuralContextLocation::cloud_content_addressed:
            return "CLOUD_CONTENT_ADDRESSED";
    }
    return "UNKNOWN_NEURAL_CONTEXT_LOCATION";
}

} // namespace v0id::neural
