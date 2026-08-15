#pragma once

#include "program.hpp"

#include <cstddef>
#include <limits>
#include <stdexcept>

namespace v0id::core {

// Client-side compiler boundary for execution-integrity experiments.
//
// The important ordering invariant is:
//
//   semantic Program + integrity/hash Program
//                  |
//                  v
//       compose_bounded_with_integrity()
//                  |
//                  v
//          one combined Program
//                  |
//                  v
//           ProgramMorpher::morph()
//                  |
//                  v
//              encryption
//
// In other words, integrity code is part of the same program image BEFORE the
// private polymorphic transform is applied. It must not be appended as a
// recognizable evaluator-side phase after morphing/encryption.
//
// The semantic program is time-expanded for exactly semantic_rounds so a
// non-halting/reference TM can enter the integrity fragment after the requested
// bounded computation. The caller must also state how many integrity transitions
// are part of the accepted execution. This prevents the old off-by-one trap where
// the last semantic transition merely ENTERS integrity code and a fixed-round
// evaluator stops before executing any of it.
//
// This compiler does not define a hash primitive itself; the integrity fragment
// is supplied by the caller. A future SHA3/KMAC TM or equivalent hidden machine
// fragment plugs into this boundary.
struct BoundedIntegrityProgram {
    Program program;
    std::size_t initial_state{};

    // Number of states occupied by the time-expanded semantic prefix.
    std::size_t semantic_state_count{};

    // First state belonging to the integrity fragment before polymorphism.
    // This is CLIENT-SIDE construction metadata only. The evaluator must never
    // receive it as a semantic label.
    std::size_t integrity_state_offset{};

    // Explicit execution accounting. The public evaluator budget for this
    // combined program is total_execution_rounds, not semantic_rounds.
    std::size_t semantic_rounds{};
    std::size_t integrity_rounds{};
    std::size_t total_execution_rounds{};
};

inline BoundedIntegrityProgram compose_bounded_with_integrity(
    const Program& semantic,
    std::size_t semantic_initial_state,
    std::size_t semantic_rounds,
    const Program& integrity,
    std::size_t integrity_initial_state,
    std::size_t integrity_rounds) {

    semantic.validate();
    integrity.validate();

    if (semantic_initial_state >= semantic.states)
        throw std::runtime_error("semantic initial state out of range");
    if (integrity_initial_state >= integrity.states)
        throw std::runtime_error("integrity initial state out of range");
    if (semantic_rounds == 0)
        throw std::runtime_error("bounded semantic prefix requires at least one round");
    if (integrity_rounds == 0)
        throw std::runtime_error("bounded integrity suffix requires at least one round");
    if (integrity_rounds >
        std::numeric_limits<std::size_t>::max() - semantic_rounds)
        throw std::runtime_error("combined execution round count overflows");

    if (semantic_rounds >
        std::numeric_limits<std::size_t>::max() / semantic.states)
        throw std::runtime_error("semantic time expansion overflows state count");

    const std::size_t semantic_state_count = semantic_rounds * semantic.states;
    if (integrity.states >
        std::numeric_limits<std::size_t>::max() - semantic_state_count)
        throw std::runtime_error("combined program state count overflows");

    BoundedIntegrityProgram out;
    out.semantic_state_count = semantic_state_count;
    out.integrity_state_offset = semantic_state_count;
    out.semantic_rounds = semantic_rounds;
    out.integrity_rounds = integrity_rounds;
    out.total_execution_rounds = semantic_rounds + integrity_rounds;
    out.initial_state = semantic_initial_state; // layer zero
    out.program.states = semantic_state_count + integrity.states;
    out.program.rules.resize(out.program.states * 2);

    // Time-expand the bounded semantic prefix. Every layer executes the exact
    // original read/write/move semantics. Intermediate layers route the hidden
    // control state into the next time layer. The final semantic layer routes
    // into the integrity fragment while preserving the final semantic write and
    // head move of the requested round.
    for (std::size_t round = 0; round < semantic_rounds; ++round) {
        for (std::size_t q = 0; q < semantic.states; ++q) {
            const std::size_t source = round * semantic.states + q;
            for (int read = 0; read <= 1; ++read) {
                const auto& r = semantic.rule(q, read);
                const std::size_t next =
                    (round + 1 < semantic_rounds)
                        ? (round + 1) * semantic.states + r.next_state
                        : out.integrity_state_offset + integrity_initial_state;

                out.program.rules[source * 2 + static_cast<std::size_t>(read)] =
                    Rule{source, read, next, r.write, r.move};
            }
        }
    }

    // Copy the complete integrity fragment into the same state namespace. A
    // subsequent ProgramMorpher pass therefore permutes semantic and integrity
    // states together using one private morph seed.
    for (std::size_t q = 0; q < integrity.states; ++q) {
        const std::size_t source = out.integrity_state_offset + q;
        for (int read = 0; read <= 1; ++read) {
            const auto& r = integrity.rule(q, read);
            out.program.rules[source * 2 + static_cast<std::size_t>(read)] =
                Rule{
                    source,
                    read,
                    out.integrity_state_offset + r.next_state,
                    r.write,
                    r.move,
                };
        }
    }

    out.program.validate();
    return out;
}

} // namespace v0id::core
