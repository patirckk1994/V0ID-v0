#include "program_morpher.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::RoundMorphedProgramSchedule;

struct RunResult {
    std::size_t state{};
    std::size_t head{};
    std::vector<int> tape;
};

RunResult run_schedule(const RoundMorphedProgramSchedule& schedule,
                       const std::vector<int>& input,
                       std::size_t rounds) {
    if (rounds > schedule.round_programs.size())
        throw std::runtime_error("requested schedule prefix exceeds schedule length");
    if (input.empty())
        throw std::runtime_error("schedule test tape must not be empty");

    RunResult out{schedule.initial_state, 0, input};
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto& program = schedule.round_programs[round];
        const auto& rule = program.rule(out.state, out.tape.at(out.head));
        out.tape[out.head] = rule.write;
        out.state = rule.next_state;
        if (rule.move < 0 && out.head > 0)
            --out.head;
        else if (rule.move > 0 && out.head + 1 < out.tape.size())
            ++out.head;
    }
    return out;
}

std::size_t run_base_state(const Program& program,
                           std::size_t initial_state,
                           const std::vector<int>& input,
                           std::size_t rounds) {
    auto tape = input;
    auto state = initial_state;
    std::size_t head = 0;
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto& rule = program.rule(state, tape.at(head));
        tape[head] = rule.write;
        state = rule.next_state;
        if (rule.move < 0 && head > 0)
            --head;
        else if (rule.move > 0 && head + 1 < tape.size())
            ++head;
    }
    return state;
}

std::vector<int> run_base_tape(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t rounds) {
    auto tape = input;
    auto state = initial_state;
    std::size_t head = 0;
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto& rule = program.rule(state, tape.at(head));
        tape[head] = rule.write;
        state = rule.next_state;
        if (rule.move < 0 && head > 0)
            --head;
        else if (rule.move > 0 && head + 1 < tape.size())
            ++head;
    }
    return tape;
}

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

MorphSeed seed_a() {
    MorphSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i + 1);
    return seed;
}

MorphSeed seed_b() {
    auto seed = seed_a();
    seed[7] ^= 0x5au;
    return seed;
}

} // namespace

int main() try {
    const Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
    increment.validate();

    constexpr std::size_t rounds = 4;
    constexpr std::size_t public_states = 5;
    const std::vector<int> input{1,0,1,1,0,0,0,0};

    const auto schedule = ProgramMorpher::morph_round_schedule(
        increment, 0, public_states, rounds, seed_a(), 4);
    const auto schedule_again = ProgramMorpher::morph_round_schedule(
        increment, 0, public_states, rounds, seed_a(), 4);
    const auto schedule_other = ProgramMorpher::morph_round_schedule(
        increment, 0, public_states, rounds, seed_b(), 4);

    int passed = 0;
    auto pass = [&](bool condition, const char* label) {
        require(condition, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    pass(schedule.round_programs.size() == rounds,
         "schedule contains exactly one transition table per requested round");
    pass(schedule.manifest.logical_to_morphed.size() == rounds + 1,
         "schedule contains one hidden state encoding per round boundary");

    bool all_valid = true;
    for (const auto& program : schedule.round_programs) {
        try {
            program.validate();
        } catch (...) {
            all_valid = false;
        }
    }
    pass(all_valid, "every round-specific polymorphic transition table validates");

    bool unique_boundary_labels = true;
    for (std::size_t logical = 0; logical < public_states; ++logical) {
        std::array<bool, public_states> seen{};
        for (std::size_t boundary = 0; boundary <= rounds; ++boundary) {
            const auto label = schedule.manifest.logical_to_morphed[boundary][logical];
            if (label >= public_states || seen[label])
                unique_boundary_labels = false;
            seen[label] = true;
        }
    }
    pass(unique_boundary_labels,
         "each logical state has a distinct secret public label at every boundary");

    const auto full = run_schedule(schedule, input, rounds);
    const auto two = run_schedule(schedule, input, 2);
    const auto base_full_tape = run_base_tape(increment, 0, input, rounds);
    const auto base_two_tape = run_base_tape(increment, 0, input, 2);
    const auto base_full_state = run_base_state(increment, 0, input, rounds);
    const auto base_two_state = run_base_state(increment, 0, input, 2);

    pass(full.tape == base_full_tape,
         "round-polymorphic schedule preserves the requested 4-round semantics");
    pass(two.tape == base_two_tape,
         "round-polymorphic schedule preserves the 2-round semantic prefix");
    pass(two.tape == full.tape,
         "benchmark still reaches the same semantic tape after 2 and 4 rounds");

    const auto expected_full_encoded_state =
        schedule.manifest.logical_to_morphed[rounds][base_full_state];
    const auto expected_two_encoded_state =
        schedule.manifest.logical_to_morphed[2][base_two_state];

    pass(full.state == expected_full_encoded_state,
         "4/4 execution ends in the client-expected boundary-4 hidden state encoding");
    pass(two.state == expected_two_encoded_state,
         "2/4 execution ends in the boundary-2 hidden state encoding");
    pass(two.state != full.state,
         "2/4 early return is distinguishable even when its semantic tape is already correct");

    bool deterministic =
        schedule.initial_state == schedule_again.initial_state &&
        schedule.manifest.logical_to_morphed == schedule_again.manifest.logical_to_morphed &&
        schedule.manifest.integrity_nonce == schedule_again.manifest.integrity_nonce &&
        schedule.manifest.integrity_output_slot == schedule_again.manifest.integrity_output_slot &&
        schedule.manifest.integrity_output_masks == schedule_again.manifest.integrity_output_masks;
    if (deterministic) {
        for (std::size_t r = 0; r < rounds; ++r) {
            const auto& a = schedule.round_programs[r];
            const auto& b = schedule_again.round_programs[r];
            if (a.states != b.states || a.rules.size() != b.rules.size()) {
                deterministic = false;
                break;
            }
            for (std::size_t i = 0; i < a.rules.size(); ++i) {
                const auto& x = a.rules[i];
                const auto& y = b.rules[i];
                if (x.state != y.state || x.read != y.read ||
                    x.next_state != y.next_state || x.write != y.write ||
                    x.move != y.move) {
                    deterministic = false;
                    break;
                }
            }
        }
    }
    pass(deterministic, "same private seed deterministically reproduces the full round schedule");

    pass(schedule.manifest.logical_to_morphed != schedule_other.manifest.logical_to_morphed,
         "changing the private morph seed changes the round-boundary encoding schedule");

    bool rejected_small_shape = false;
    try {
        (void)ProgramMorpher::morph_round_schedule(
            increment, 0, rounds, rounds, seed_a(), 4);
    } catch (const std::runtime_error&) {
        rejected_small_shape = true;
    }
    pass(rejected_small_shape,
         "schedule rejects a public state count that cannot encode all round boundaries distinctly");

    std::cout << "V0ID round-polymorphic execution-binding tests: "
              << passed << " passed, 0 failed\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "[FAIL] " << e.what() << '\n';
    return 1;
}
