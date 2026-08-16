#include "boolean_ir.hpp"

#include <stdexcept>

namespace v0id::integrity {

BoolWire BooleanIR::push(BoolNode node) {
    const BoolWire wire = nodes_.size();
    nodes_.push_back(node);
    return wire;
}

void BooleanIR::require_wire(BoolWire wire) const {
    if (wire >= nodes_.size())
        throw std::runtime_error("BooleanIR wire out of range");
}

BoolWire BooleanIR::add_input() {
    if (nodes_.size() != input_count_)
        throw std::runtime_error("BooleanIR inputs must be a dense prefix");
    const BoolWire wire = push(BoolNode{BoolOp::Input, kInvalidBoolWire,
                                        kInvalidBoolWire, input_count_});
    ++input_count_;
    return wire;
}

BoolWire BooleanIR::constant(bool value) {
    BoolWire& cached = value ? const1_ : const0_;
    if (cached != kInvalidBoolWire)
        return cached;
    cached = push(BoolNode{value ? BoolOp::Const1 : BoolOp::Const0});
    return cached;
}

BoolWire BooleanIR::bit_not(BoolWire a) {
    require_wire(a);
    return push(BoolNode{BoolOp::Not, a});
}

BoolWire BooleanIR::bit_xor(BoolWire a, BoolWire b) {
    require_wire(a);
    require_wire(b);
    return push(BoolNode{BoolOp::Xor, a, b});
}

BoolWire BooleanIR::bit_and(BoolWire a, BoolWire b) {
    require_wire(a);
    require_wire(b);
    return push(BoolNode{BoolOp::And, a, b});
}

void BooleanIR::set_outputs(std::vector<BoolWire> outputs) {
    for (const auto wire : outputs)
        require_wire(wire);
    outputs_ = std::move(outputs);
}

void BooleanIR::validate() const {
    if (input_count_ > nodes_.size())
        throw std::runtime_error("BooleanIR input count exceeds node count");

    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        const auto& n = nodes_[i];
        switch (n.op) {
        case BoolOp::Input:
            if (i >= input_count_ || n.input_index != i)
                throw std::runtime_error("BooleanIR input prefix is not canonical");
            break;
        case BoolOp::Const0:
        case BoolOp::Const1:
            if (i < input_count_)
                throw std::runtime_error("BooleanIR non-input inside input prefix");
            break;
        case BoolOp::Not:
            if (i < input_count_ || n.a >= i)
                throw std::runtime_error("BooleanIR NOT dependency is not topological");
            break;
        case BoolOp::Xor:
        case BoolOp::And:
            if (i < input_count_ || n.a >= i || n.b >= i)
                throw std::runtime_error("BooleanIR binary dependency is not topological");
            break;
        }
    }

    for (const auto wire : outputs_)
        if (wire >= nodes_.size())
            throw std::runtime_error("BooleanIR output wire out of range");
}

std::vector<std::uint8_t> BooleanIR::evaluate(
    const std::vector<std::uint8_t>& inputs) const {
    validate();
    if (inputs.size() != input_count_)
        throw std::runtime_error("BooleanIR input vector has wrong size");

    std::vector<std::uint8_t> values(nodes_.size(), 0);
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        const auto& n = nodes_[i];
        switch (n.op) {
        case BoolOp::Input:
            values[i] = static_cast<std::uint8_t>(inputs[n.input_index] != 0);
            break;
        case BoolOp::Const0:
            values[i] = 0;
            break;
        case BoolOp::Const1:
            values[i] = 1;
            break;
        case BoolOp::Not:
            values[i] = static_cast<std::uint8_t>(values[n.a] ^ 1u);
            break;
        case BoolOp::Xor:
            values[i] = static_cast<std::uint8_t>(values[n.a] ^ values[n.b]);
            break;
        case BoolOp::And:
            values[i] = static_cast<std::uint8_t>(values[n.a] & values[n.b]);
            break;
        }
    }

    std::vector<std::uint8_t> out;
    out.reserve(outputs_.size());
    for (const auto wire : outputs_)
        out.push_back(values[wire]);
    return out;
}

} // namespace v0id::integrity
