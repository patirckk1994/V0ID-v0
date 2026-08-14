#pragma once

#include "program.hpp"

#include <array>
#include <cstddef>
#include <vector>

namespace v0id::polymorph {

using MorphSeed = std::array<unsigned char, 32>;

struct MorphedProgram {
    v0id::core::Program program;
    std::size_t initial_state{};

    // Client-side metadata. These mappings are for testing/compiler bookkeeping
    // and are not intended to be sent to an untrusted evaluator.
    std::vector<std::size_t> base_to_morphed;
    std::vector<std::size_t> dummy_states;
};

class ProgramMorpher {
public:
    static MorphSeed random_seed();

    // Builds an equivalent program with a fixed public state count. Base states
    // are placed at secret pseudorandom state IDs; remaining states are harmless
    // identity/no-op states. The initial state is mapped along with the program.
    static MorphedProgram morph(const v0id::core::Program& base,
                                std::size_t base_initial_state,
                                std::size_t public_state_count,
                                const MorphSeed& seed);
};

} // namespace v0id::polymorph
