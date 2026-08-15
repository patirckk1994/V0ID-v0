#include "integrity_program.hpp"

#include "stack_integrity_bridge.hpp"
#include "stack_polymorph_bridge.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::crypto::SeriesFirstStackContext;
using v0id::integrity::CanonicalSelfImageContext;
using v0id::integrity::IntegrityHashBackend;
using v0id::integrity::IntegrityHashProfile;
using v0id::integrity::IntegrityProgramArtifact;
using v0id::integrity::IntegrityProgramBuildRequest;
using v0id::integrity::PrivateLocalIntegrityProgramHook;
using v0id::integrity::Sha3_512IntegrityHashBackend;
using v0id::polymorph::SeriesSeed;

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

std::string hex(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto b : bytes)
        out << std::setw(2) << static_cast<unsigned>(b);
    return out.str();
}

Program increment_program() {
    return Program{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
}

SeriesSeed private_root() {
    SeriesSeed root{};
    for (std::size_t i = 0; i < root.size(); ++i)
        root[i] = static_cast<unsigned char>(0x51u + i);
    return root;
}

SeriesFirstStackContext stack_context() {
    SeriesFirstStackContext c;
    for (std::size_t i = 0; i < c.session_id.size(); ++i)
        c.session_id[i] = static_cast<std::uint8_t>(i + 1);
    c.job_id = "integrity-program-test";
    c.epoch = 91;
    c.machine_protocol = "v0id-remote-machine-v3";
    c.fhe_parameter_set = "STD128Q";
    for (std::size_t i = 0; i < c.semantic_binding.size(); ++i) {
        c.semantic_binding[i] = static_cast<std::uint8_t>((i * 5 + 3) & 0xffu);
        c.generator_binding[i] = static_cast<std::uint8_t>((i * 11 + 7) & 0xffu);
    }
    return c;
}

CanonicalSelfImageContext self_context() {
    const auto sc = stack_context();
    CanonicalSelfImageContext c;
    c.session_id = sc.session_id;
    c.job_id = sc.job_id;
    c.epoch = sc.epoch;
    c.machine_protocol = sc.machine_protocol;
    c.fhe_parameter_set = sc.fhe_parameter_set;
    c.initial_state = 0;
    c.initial_head = 0;
    c.initial_tape = {1,0,1,1,0,0,0,0};
    c.semantic_rounds = 4;
    c.integrity_rounds = 1;
    c.total_execution_rounds = 5;
    c.semantic_binding = sc.semantic_binding;
    c.generator_binding = sc.generator_binding;
    c.private_integrity_challenge.resize(32);
    for (std::size_t i = 0; i < c.private_integrity_challenge.size(); ++i)
        c.private_integrity_challenge[i] = static_cast<std::uint8_t>(0xc0u + i);
    c.digest_slot_bytes = 64;
    return c;
}

class ToyHashBackend final : public IntegrityHashBackend {
public:
    IntegrityHashProfile profile() const override {
        return {"toy-integrity-test", 1, 1};
    }

    std::vector<std::uint8_t> digest(
        const std::vector<std::uint8_t>& subject) const override {
        std::uint8_t x = 0;
        for (const auto b : subject) x ^= b;
        return {x};
    }
};

PrivateLocalIntegrityProgramHook make_toy_hook(std::vector<std::uint8_t> module_bytes) {
    return PrivateLocalIntegrityProgramHook(
        "private-test-integrity-module",
        1,
        IntegrityHashProfile{"toy-integrity-test", 1, 1},
        std::move(module_bytes),
        [](const IntegrityProgramBuildRequest& request,
           const std::vector<std::uint8_t>& module) {
            // Deliberately only a plumbing marker, NOT a cryptographic hash. The
            // test verifies hook privacy, series material, combine-before-morph,
            // masked self-image semantics and one shared ProgramMorpher pass.
            const bool invert =
                ((request.private_algorithm_material.front() ^ module.front()) & 1u) != 0;
            Program p{1, {
                {0, 0, 0, invert ? 0 : 1, 0},
                {0, 1, 0, invert ? 1 : 0, 0},
            }};
            return IntegrityProgramArtifact{std::move(p), 0, 1, {0x50,0x52,0x49,0x56}};
        });
}

bool contains(const std::vector<std::size_t>& values, std::size_t value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    Sha3_512IntegrityHashBackend sha3;
    const auto empty_digest = sha3.digest({});
    pass(hex(empty_digest) ==
             "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
             "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
         "default SHA3-512 backend matches the empty-message known answer");
    pass(sha3.profile() == IntegrityHashProfile{"sha3-512", 1, 64},
         "default integrity hash profile is explicit SHA3-512/v1");

    const auto root = private_root();
    const auto sc = stack_context();
    const auto execution_series =
        v0id::crypto::derive_execution_integrity_series(root, sc);
    const auto execution_series_again =
        v0id::crypto::derive_execution_integrity_series(root, sc);
    const auto context_hash = v0id::crypto::hash_series_first_stack_context(sc);
    const auto polymorphism_series = v0id::crypto::derive_private_stack_series(
        root, context_hash, v0id::crypto::StackPurpose::polymorphism);

    pass(execution_series == execution_series_again,
         "execution_integrity purpose series is deterministic");
    pass(execution_series != polymorphism_series,
         "execution_integrity and polymorphism purpose series remain separated");

    auto hook_a = make_toy_hook({0x00,0x61,0x73,0x6d,0x01});
    auto hook_b = make_toy_hook({0x00,0x61,0x73,0x6d,0x02});
    pass(hook_a.private_binding() != hook_b.private_binding(),
         "private-local implementation bytes change the private hook binding");

    const auto material_a = v0id::crypto::expand_execution_integrity_algorithm_later(
        execution_series, "toy-integrity-test", 1,
        hook_a.private_binding(), 4096, 1, 64);
    const auto material_b = v0id::crypto::expand_execution_integrity_algorithm_later(
        execution_series, "toy-integrity-test", 1,
        hook_b.private_binding(), 4096, 1, 64);
    pass(material_a != material_b,
         "algorithm-later integrity material binds the private implementation");

    const std::vector<std::uint8_t> generator_series{9,8,7,6,5,4,3,2,1};
    const auto morph_seed = v0id::crypto::derive_program_morph_seed_from_stack(
        root, sc, generator_series);

    ToyHashBackend toy_hash;
    const auto built = v0id::integrity::build_combined_integrity_executable(
        increment_program(), 0, 4, 16, 4,
        execution_series, morph_seed, self_context(), toy_hash, hook_a);

    pass(built.combined.semantic_rounds == 4 &&
             built.combined.integrity_rounds == 1 &&
             built.total_execution_rounds == 5,
         "combined executable carries explicit semantic+integrity round accounting");
    pass(built.morphed.manifest.base_to_morphed.size() == built.combined.program.states,
         "one ProgramMorpher pass covers the complete useful+integrity program");
    pass(built.morphed_integrity_states.size() == 1,
         "client retains the final hidden integrity-state location privately");
    pass(!built.canonical_subject.empty() &&
             built.canonical_subject_bits.size() == built.canonical_subject.size() * 8,
         "final masked polymorphic self-image has matching byte/bit views");
    pass(built.expected_digest == toy_hash.digest(built.canonical_subject),
         "client expected digest is computed from the exact final masked self-image");

    auto final_context = self_context();
    final_context.initial_state = built.morphed.initial_state;
    final_context.integrity_rounds = built.combined.integrity_rounds;
    final_context.total_execution_rounds = built.total_execution_rounds;

    auto integrity_mutated = built.morphed.program;
    bool mutated_integrity = false;
    for (auto& r : integrity_mutated.rules) {
        if (contains(built.morphed_integrity_states, r.state)) {
            r.write ^= 1;
            mutated_integrity = true;
            break;
        }
    }
    require(mutated_integrity, "test could not locate integrity state");
    integrity_mutated.validate();
    pass(v0id::integrity::canonical_self_image_v1_masked(
             integrity_mutated, built.morphed_integrity_states, final_context) ==
             built.canonical_subject,
         "mutating excluded hash implementation rows does not recursively change its subject");

    auto useful_mutated = built.morphed.program;
    bool mutated_useful = false;
    for (auto& r : useful_mutated.rules) {
        if (!contains(built.morphed_integrity_states, r.state)) {
            r.write ^= 1;
            mutated_useful = true;
            break;
        }
    }
    require(mutated_useful, "test could not locate non-integrity state");
    useful_mutated.validate();
    pass(v0id::integrity::canonical_self_image_v1_masked(
             useful_mutated, built.morphed_integrity_states, final_context) !=
             built.canonical_subject,
         "mutating the rest of the final polymorphic TM changes the self-hash subject");

    const auto built_other_hook = v0id::integrity::build_combined_integrity_executable(
        increment_program(), 0, 4, 16, 4,
        execution_series, morph_seed, self_context(), toy_hash, hook_b);
    pass(built.private_algorithm_material != built_other_hook.private_algorithm_material,
         "private hook/module choice mutates execution-integrity algorithm material");

    bool fake_sha3_rejected = false;
    try {
        (void)v0id::integrity::build_combined_integrity_executable(
            increment_program(), 0, 4, 16, 4,
            execution_series, morph_seed, self_context(), sha3, hook_a);
    } catch (const std::runtime_error&) {
        fake_sha3_rejected = true;
    }
    pass(fake_sha3_rejected,
         "SHA3 reference backend fails closed without a matching real runtime SHA3 hook");

    std::cout << "V0ID private execution-integrity program tests: "
              << passed << " passed, 0 failed\n"
              << "NOTE: SHA3-512 reference hashing is real; the test hook is intentionally "
                 "non-cryptographic and only exercises private synthesis + common polymorphism.\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "[FAIL] " << e.what() << '\n';
    return 1;
}
