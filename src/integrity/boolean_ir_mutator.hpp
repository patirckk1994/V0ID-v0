#pragma once

#include "boolean_ir.hpp"

#include <array>
#include <cstddef>

namespace v0id::integrity {

using BooleanMutationSeed = std::array<unsigned char, 32>;

struct BooleanMutationOptions {
    // Approximate inverse frequency of inserting an unused identity node after
    // a reconstructed node. 0 disables dummy identities.
    std::size_t dummy_identity_period{7};
    bool expand_some_xors{true};
    bool wrap_some_gates{true};
};

// Deterministic semantics-preserving Boolean DAG diversification. The seed is
// expected to be derived from private PQR material by the caller. The mutator
// changes wire allocation and equivalent gate structure before TM lowering;
// it is intentionally separate from ProgramMorpher state permutation.
BooleanIR mutate_boolean_ir(const BooleanIR& base,
                            const BooleanMutationSeed& seed,
                            const BooleanMutationOptions& options = {});

} // namespace v0id::integrity
