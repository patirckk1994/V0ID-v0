#include "program_morpher.hpp"
#include "integrity_program_compiler.hpp"
#include "series_generator.hpp"
#include "stack_polymorph_bridge.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::core::compose_bounded_with_integrity;
using v0id::crypto::SeriesFirstStackContext;
using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::RoundMorphedProgramSchedule;
using v0id::polymorph::SeriesSeed;

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

RunResult run_program(const Program& program,
                      std::size_t initial_state,
                      const std::vector<int>& input,
                      std::size_t rounds) {
    program.validate();
    if (input.empty())
        throw std::runtime_error("program test tape must not be empty");

    RunResult out{initial_state, 0, input};
    for (std::size_t round = 0; round < rounds; ++round) {
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
    return run_program(program, initial_state, input, rounds).state;
}

std::vector<int> run_base_tape(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t rounds) {
    return run_program(program, initial_state, input, rounds).tape;
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

SeriesSeed private_root_a() {
    SeriesSeed root{};
    for (std::size_t i = 0; i < root.size(); ++i)
        root[i] = static_cast<unsigned char>(0x31u + i);
    return root;
}

SeriesSeed private_root_b() {
    auto root = private_root_a();
    root[11] ^= 0xa7u;
    return root;
}

SeriesFirstStackContext combined_stack_context() {
    SeriesFirstStackContext c;
    for (std::size_t i = 0; i < c.session_id.size(); ++i)
        c.session_id[i] = static_cast<std::uint8_t>(i + 1);
    c.job_id = "combined-integrity-morph-test";
    c.epoch = 73;
    c.machine_protocol = "v0id-remote-machine-v3";
    c.fhe_parameter_set = "STD128Q";
    for (std::size_t i = 0; i < c.semantic_binding.size(); ++i) {
        c.semantic_binding[i] = static_cast<std::uint8_t>((i * 5 + 1) & 0xffu);
        c.generator_binding[i] = static_cast<std::uint8_t>((i * 9 + 7) & 0xffu);
    }
    return c;
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

    // ---------------------------------------------------------------------
    // Intended embedded-integrity ordering gate.
    //
    // This tiny one-state fragment is deliberately NOT a cryptographic hash.
    // It toggles the current tape bit so the test can prove that an auxiliary
    // integrity fragment is composed into the same Program *before* the private
    // ProgramMorpher pass. A real self-hash TM/circuit plugs into the same
    // compiler boundary; the architectural ordering must not change.
    // ---------------------------------------------------------------------
    const Program integrity_marker{1, {
        {0, 0, 0, 1, 0},
        {0, 1, 0, 0, 0},
    }};
    integrity_marker.validate();

    const auto combined = compose_bounded_with_integrity(
        increment, 0, rounds, integrity_marker, 0);

    pass(combined.semantic_state_count == rounds * increment.states &&
             combined.integrity_state_offset == rounds * increment.states &&
             combined.program.states == rounds * increment.states + integrity_marker.states,
         "semantic and integrity fragments compile into one bounded program image");

    const auto combined_after_semantic =
        run_program(combined.program, combined.initial_state, input, rounds);
    pass(combined_after_semantic.tape == base_full_tape &&
             combined_after_semantic.state == combined.integrity_state_offset,
         "combined program enters integrity code only after the requested semantic rounds");

    const auto combined_after_integrity =
        run_program(combined.program, combined.initial_state, input, rounds + 1);
    pass(combined_after_integrity.tape != base_full_tape,
         "embedded integrity fragment executes as part of the same program");

    std::vector<std::uint8_t> series_input;
    series_input.reserve(input.size());
    for (const int bit : input)
        series_input.push_back(static_cast<std::uint8_t>(bit & 1));

    KmacSeriesGenerator generator(64);
    const auto root_a = private_root_a();
    const auto root_b = private_root_b();
    const auto derived_a = generator.derive(series_input, root_a, combined_stack_context().epoch);
    const auto derived_a_again = generator.derive(series_input, root_a, combined_stack_context().epoch);
    const auto derived_b = generator.derive(series_input, root_b, combined_stack_context().epoch);

    const auto stack_seed_a = v0id::crypto::derive_program_morph_seed_from_stack(
        root_a, combined_stack_context(), derived_a.series);
    const auto stack_seed_a_again = v0id::crypto::derive_program_morph_seed_from_stack(
        root_a, combined_stack_context(), derived_a_again.series);
    const auto stack_seed_b = v0id::crypto::derive_program_morph_seed_from_stack(
        root_b, combined_stack_context(), derived_b.series);

    pass(stack_seed_a == stack_seed_a_again,
         "private PQR/stack polymorphism series deterministically derives the morph seed");
    pass(stack_seed_a != stack_seed_b,
         "changing the issuer-private root changes the combined-machine morph seed");

    constexpr std::size_t combined_public_states = 16;
    const auto combined_morph = ProgramMorpher::morph(
        combined.program, combined.initial_state,
        combined_public_states, stack_seed_a, 4);
    const auto combined_morph_other = ProgramMorpher::morph(
        combined.program, combined.initial_state,
        combined_public_states, stack_seed_b, 4);

    pass(combined_morph.manifest.base_to_morphed.size() == combined.program.states,
         "one ProgramMorpher pass covers every semantic AND integrity state");

    const auto hidden_integrity_state =
        combined_morph.manifest.base_to_morphed.at(combined.integrity_state_offset);
    const auto& hidden_integrity_zero =
        combined_morph.program.rule(hidden_integrity_state, 0);
    const auto& hidden_integrity_one =
        combined_morph.program.rule(hidden_integrity_state, 1);
    pass(hidden_integrity_zero.next_state == hidden_integrity_state &&
             hidden_integrity_zero.write == 1 &&
             hidden_integrity_one.next_state == hidden_integrity_state &&
             hidden_integrity_one.write == 0,
         "integrity logic survives the same secret state permutation as useful logic");

    const auto morphed_after_semantic =
        run_program(combined_morph.program, combined_morph.initial_state, input, rounds);
    const auto morphed_after_integrity =
        run_program(combined_morph.program, combined_morph.initial_state, input, rounds + 1);
    pass(morphed_after_semantic.tape == base_full_tape &&
             morphed_after_integrity.tape == combined_after_integrity.tape,
         "combined useful+integrity semantics survive one shared polymorphic transform");

    pass(combined_morph.manifest.base_to_morphed !=
             combined_morph_other.manifest.base_to_morphed,
         "private PQR/stack series remixes the whole useful+integrity machine together");

    std::cout << "V0ID round-polymorphic + combine-before-morph tests: "
              << passed << " passed, 0 failed\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "[FAIL] " << e.what() << '\n';
    return 1;
}
