#pragma once

#include "boolean_ir.hpp"
#include "boolean_ir_lowering_plan.hpp"
#include "program.hpp"

#include <cstddef>
#include <vector>

namespace v0id::integrity {

struct LoweredBooleanProgram {
    v0id::core::Program program;
    std::size_t initial_state{};
    std::size_t required_initial_head{};
    std::size_t execution_rounds{};
    std::size_t tape_cells{};

    // input_cells[input_index] gives the tape cell populated by the caller.
    std::vector<std::size_t> input_cells;

    // Digest/logical outputs are returned in IR output order. With the default
    // plan they form a contiguous bank after all IR wire cells.
    std::vector<std::size_t> output_cells;
};

// Conservative exact count for this reference compiler's state construction.
// It is intentionally exposed so production code can reject an impractical
// lowering before allocating the transition table.
std::size_t estimate_reference_tm_states(
    const BooleanIR& ir,
    const BooleanIRLoweringPlan& plan);

// Mechanical single-tape binary lowering used as a plaintext correctness
// oracle. It materializes one Boolean wire per tape cell and encodes temporary
// gate values in TM control states. This is deliberately not the final compact
// SHA3 lowering strategy; large circuits should trip plan.max_states instead of
// silently allocating an absurd machine.
LoweredBooleanProgram lower_boolean_ir_to_program(
    const BooleanIR& ir,
    const BooleanIRLoweringPlan& plan);

} // namespace v0id::integrity
