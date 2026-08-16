#include "boolean_ir_lowering_plan.hpp"

#include <stdexcept>
#include <vector>

namespace v0id::integrity {

BooleanIRLoweringPlan make_default_boolean_ir_lowering_plan(const BooleanIR& ir) {
    ir.validate();
    BooleanIRLoweringPlan plan;
    plan.evaluation_order.reserve(ir.nodes().size() - ir.input_count());
    for (BoolWire wire = ir.input_count(); wire < ir.nodes().size(); ++wire)
        plan.evaluation_order.push_back(wire);
    return plan;
}

void validate_boolean_ir_lowering_plan(const BooleanIR& ir,
                                       const BooleanIRLoweringPlan& plan) {
    ir.validate();
    if (plan.initial_head >= ir.nodes().size() && !ir.nodes().empty())
        throw std::runtime_error("BooleanIR lowering initial head is outside wire bank");

    const std::size_t expected = ir.nodes().size() - ir.input_count();
    if (plan.evaluation_order.size() != expected)
        throw std::runtime_error("BooleanIR lowering plan does not schedule every non-input wire");

    std::vector<bool> ready(ir.nodes().size(), false);
    std::vector<bool> seen(ir.nodes().size(), false);
    for (std::size_t i = 0; i < ir.input_count(); ++i)
        ready[i] = true;

    for (const auto wire : plan.evaluation_order) {
        if (wire < ir.input_count() || wire >= ir.nodes().size() || seen[wire])
            throw std::runtime_error("BooleanIR lowering plan contains invalid/duplicate wire");

        const auto& n = ir.nodes()[wire];
        const auto require_ready = [&](BoolWire dep) {
            if (dep >= ready.size() || !ready[dep])
                throw std::runtime_error("BooleanIR lowering order violates dependency");
        };

        switch (n.op) {
        case BoolOp::Input:
            throw std::runtime_error("BooleanIR lowering plan schedules an input node");
        case BoolOp::Const0:
        case BoolOp::Const1:
            break;
        case BoolOp::Not:
            require_ready(n.a);
            break;
        case BoolOp::Xor:
        case BoolOp::And:
            require_ready(n.a);
            require_ready(n.b);
            break;
        }
        ready[wire] = true;
        seen[wire] = true;
    }
}

} // namespace v0id::integrity
