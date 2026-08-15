#pragma once

#include "boolean_ir.hpp"

#include <cstddef>
#include <vector>

namespace v0id::integrity {

struct BooleanIRLoweringPlan {
    // Topological order in which non-input wires are materialized on tape.
    // Independent nodes may be reordered by a private planner before lowering.
    std::vector<BoolWire> evaluation_order;

    // Reference lowerer safety valve. The naive single-tape compiler is useful
    // as a correctness oracle but can explode in states for large circuits.
    std::size_t max_states{1'000'000};

    // Reference tape convention. Inputs/wires begin at cell zero and lowering
    // assumes the integrity fragment is entered with the head at this cell.
    std::size_t initial_head{0};

    // Copy logical outputs into a contiguous bank after all wire cells.
    bool append_output_bank{true};
};

BooleanIRLoweringPlan make_default_boolean_ir_lowering_plan(const BooleanIR& ir);
void validate_boolean_ir_lowering_plan(const BooleanIR& ir,
                                       const BooleanIRLoweringPlan& plan);

} // namespace v0id::integrity
