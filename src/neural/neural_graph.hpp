#pragma once

#include "module_sync.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace v0id::neural {

using NeuralDigest512 = v0id::net::ModuleDigest512;

enum class NeuralExecutionMode : std::uint8_t {
    plain_cpu = 1,
    tfhe_cuda = 2,
};

enum class NeuralNumericFormat : std::uint8_t {
    uint8 = 1,
    int8 = 2,
    uint16 = 3,
    int16 = 4,
    fixed16_16 = 5,
    fixed8_24 = 6,
};

enum class NeuralPortDirection : std::uint8_t {
    input = 1,
    output = 2,
};

enum class NeuralPortRole : std::uint8_t {
    activation = 1,
    gradient = 2,
    weight = 3,
    bias = 4,
    context = 5,
    loss = 6,
    control = 7,
};

enum class NeuralModuleOp : std::uint8_t {
    group = 1,
    input = 2,
    output = 3,
    dense = 4,
    activation = 5,
    loss = 6,
    backprop = 7,
    weight_update = 8,
    wasm_custom = 9,
};

enum class NeuralContextLocation : std::uint8_t {
    local_client = 1,
    cloud_content_addressed = 2,
};

struct TensorShape {
    std::vector<std::uint32_t> dimensions;

    std::size_t element_count() const;
    void validate() const;

    bool operator==(const TensorShape&) const = default;
};

struct NeuralPort {
    std::string name;
    NeuralPortDirection direction{NeuralPortDirection::input};
    NeuralPortRole role{NeuralPortRole::activation};
    TensorShape shape;
    NeuralNumericFormat format{NeuralNumericFormat::fixed16_16};
    bool mutable_state{};

    bool operator==(const NeuralPort&) const = default;
};

// parent_id is composition only: it gives the model a human/auditable module
// tree. Tensor flow is represented separately by NeuralEdge, so residual,
// gradient and shared-state connections are not forced into a tree shape.
struct NeuralModuleNode {
    std::string id;
    std::string parent_id;
    NeuralModuleOp op{NeuralModuleOp::group};
    std::vector<NeuralPort> ports;

    // Only present for wasm_custom. The descriptor may be PRIVATE_LOCAL or
    // SHARED_SYNC, but it must be a NEURAL_WASM module with content identity.
    std::optional<v0id::net::ModuleDescriptor> wasm_module;
};

struct NeuralEdge {
    std::string from_node;
    std::string from_port;
    std::string to_node;
    std::string to_port;

    bool operator==(const NeuralEdge&) const = default;
};

struct NeuralContextRef {
    std::string name;
    NeuralContextLocation location{NeuralContextLocation::local_client};
    NeuralDigest512 digest{};
};

struct NeuralGraph {
    std::string protocol_id{"v0id-neural-graph-v1"};
    std::string graph_id;
    std::uint64_t graph_version{1};
    std::vector<NeuralModuleNode> nodes;
    std::vector<NeuralEdge> edges;

    void validate() const;

    // SHA3-512 over a canonical, order-independent representation of the module
    // tree, port schemas, dataflow edges and referenced Wasm module identities.
    NeuralDigest512 digest512() const;
};

struct NeuralInvocation {
    NeuralExecutionMode execution_mode{NeuralExecutionMode::plain_cpu};
    std::vector<NeuralContextRef> contexts;
    std::optional<NeuralDigest512> model_state_digest;

    void validate(const NeuralGraph& graph) const;
};

// Backend boundary. A graph does not become a different model just because the
// caller chooses clear execution or encrypted execution. Implementations are
// expected to validate the same graph/port ABI and differ only in how tensor
// values are represented and executed.
class NeuralExecutionBackend {
public:
    virtual ~NeuralExecutionBackend() = default;
    virtual NeuralExecutionMode mode() const noexcept = 0;
};

std::string to_string(NeuralExecutionMode mode);
std::string to_string(NeuralNumericFormat format);
std::string to_string(NeuralPortDirection direction);
std::string to_string(NeuralPortRole role);
std::string to_string(NeuralModuleOp op);
std::string to_string(NeuralContextLocation location);

} // namespace v0id::neural
