#pragma once

#include "program.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace v0id::polymorph {

using MorphSeed = std::array<unsigned char, 32>;

// Client-only bookkeeping generated together with a morph. This manifest is
// deliberately separate from the encrypted program image and must not be sent
// to an untrusted evaluator unless a later protocol explicitly requires it.
struct MorphManifest {
    std::vector<std::size_t> base_to_morphed;
    std::vector<std::size_t> dummy_states;

    // Toy integrity plumbing. The encrypted evaluator will produce a fixed bank
    // of masked candidate digests. Only the client manifest says which returned
    // slot it intends to check and how to unmask it.
    std::uint32_t integrity_nonce{};
    std::size_t integrity_output_slot{};
    std::vector<std::uint32_t> integrity_output_masks;
};

struct MorphedProgram {
    v0id::core::Program program;
    std::size_t initial_state{};
    MorphManifest manifest;
};

class ProgramMorpher {
public:
    static MorphSeed random_seed();

    // Builds an equivalent program with a fixed public state count. Base states
    // are placed at secret pseudorandom state IDs; remaining states are harmless
    // identity/no-op states. The same seed also derives client-only integrity
    // placement metadata. integrity_candidate_count is public and fixed across
    // jobs; the selected slot and masks remain client-only.
    static MorphedProgram morph(const v0id::core::Program& base,
                                std::size_t base_initial_state,
                                std::size_t public_state_count,
                                const MorphSeed& seed,
                                std::size_t integrity_candidate_count = 4);
};

} // namespace v0id::polymorph
