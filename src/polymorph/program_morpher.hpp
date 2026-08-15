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

// Execution-bound variant of the morph. Instead of one stable secret state
// permutation for the entire job, the client derives a secret permutation for
// every round boundary. Round r's encrypted transition table consumes state IDs
// in boundary-r encoding and emits state IDs in boundary-(r+1) encoding.
//
// This matters for the malicious-evaluator threat model: reaching a semantic
// fixed point no longer means the encrypted machine representation is also a
// fixed point. A 2/4 evaluator may already have the right tape, but its hidden
// state is still encoded for boundary 2 while the client expects boundary 4.
// The evaluator is not sent this manifest.
struct RoundMorphManifest {
    // [boundary][logical state] -> evaluator-visible public state ID.
    // There are round_programs.size()+1 boundaries. Logical state IDs
    // [0, base_state_count) are semantic states; the rest are dummy identities.
    std::vector<std::vector<std::size_t>> logical_to_morphed;

    // Same private integrity placement material as MorphManifest. Keeping it in
    // the schedule manifest lets the existing encrypted self-fingerprint bind
    // the complete round-polymorphic schedule without revealing which returned
    // candidate the client checks.
    std::uint32_t integrity_nonce{};
    std::size_t integrity_output_slot{};
    std::vector<std::uint32_t> integrity_output_masks;
};

struct RoundMorphedProgramSchedule {
    // One complete fixed-shape transition table per requested round. Table r
    // maps boundary-r state labels to boundary-(r+1) state labels.
    std::vector<v0id::core::Program> round_programs;
    std::size_t initial_state{};
    std::size_t base_state_count{};
    RoundMorphManifest manifest;
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

    // Builds a round-polymorphic schedule for exactly `rounds` fixed-path
    // evaluator steps. The public state count must be at least max(base.states,
    // rounds+1) in this first construction. That allows every logical state to
    // occupy a different public label at every boundary, so an early-return
    // state cannot accidentally equal the requested final-round encoding.
    //
    // This is an execution-binding experiment, not a universal proof of work:
    // a future shortcut that transforms the encrypted representation without
    // performing the reference circuit remains UNCERTAIN and should be attacked
    // explicitly. The immediate property is narrower: ordinary skip-and-stop no
    // longer survives merely because the semantic tape reached a fixed point.
    static RoundMorphedProgramSchedule morph_round_schedule(
        const v0id::core::Program& base,
        std::size_t base_initial_state,
        std::size_t public_state_count,
        std::size_t rounds,
        const MorphSeed& seed,
        std::size_t integrity_candidate_count = 4);
};

} // namespace v0id::polymorph
