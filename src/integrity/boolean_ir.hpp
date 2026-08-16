#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace v0id::integrity {

using BoolWire = std::size_t;
inline constexpr BoolWire kInvalidBoolWire = std::numeric_limits<BoolWire>::max();

enum class BoolOp : std::uint8_t {
    Input,
    Const0,
    Const1,
    Xor,
    And,
    Not,
};

struct BoolNode {
    BoolOp op{BoolOp::Const0};
    BoolWire a{kInvalidBoolWire};
    BoolWire b{kInvalidBoolWire};
    std::size_t input_index{};
};

// Small auditable Boolean DAG used as the construction boundary between
// cryptographic equations and the binary single-tape core::Program ABI.
//
// Invariants:
//   * input nodes are a dense prefix and input_index == wire id;
//   * every non-input dependency points to an earlier wire;
//   * wire permutations/rotations are represented by changing references, not
//     by manufacturing gates;
//   * outputs are merely wire aliases and may appear in any order.
class BooleanIR {
public:
    BoolWire add_input();
    BoolWire constant(bool value);
    BoolWire bit_not(BoolWire a);
    BoolWire bit_xor(BoolWire a, BoolWire b);
    BoolWire bit_and(BoolWire a, BoolWire b);

    void set_outputs(std::vector<BoolWire> outputs);

    std::size_t input_count() const { return input_count_; }
    const std::vector<BoolNode>& nodes() const { return nodes_; }
    const std::vector<BoolWire>& outputs() const { return outputs_; }

    void validate() const;

    // Plaintext reference evaluator. Values are normalized to {0,1}.
    std::vector<std::uint8_t> evaluate(
        const std::vector<std::uint8_t>& inputs) const;

private:
    void require_wire(BoolWire wire) const;
    BoolWire push(BoolNode node);

    std::vector<BoolNode> nodes_;
    std::vector<BoolWire> outputs_;
    std::size_t input_count_{};
    BoolWire const0_{kInvalidBoolWire};
    BoolWire const1_{kInvalidBoolWire};
};

} // namespace v0id::integrity
