#pragma once

#include "boolean_ir_mutator.hpp"
#include "boolean_program_image.hpp"

#include <cstddef>

namespace v0id::integrity {

struct BooleanProgramMutationStats {
    std::size_t permuted_registers{};
    std::size_t identity_instructions_inserted{};
};

BooleanProgramImage mutate_boolean_program_image(
    const BooleanProgramImage& original,
    const BooleanMutationSeed& seed,
    std::size_t identity_instructions = 8,
    BooleanProgramMutationStats* stats = nullptr);

} // namespace v0id::integrity
