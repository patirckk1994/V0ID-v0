#include "series_first_stack.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::crypto::SeriesFirstStackContext;
using v0id::crypto::SharedSeriesRoot;
using v0id::crypto::StackPurpose;
using v0id::polymorph::SeriesSeed;

struct Runner {
    int passed{};
    int failed{};

    void check(bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    }
};

SeriesFirstStackContext base_context() {
    SeriesFirstStackContext c;
    for (std::size_t i = 0; i < c.session_id.size(); ++i)
        c.session_id[i] = static_cast<std::uint8_t>(i + 1);
    c.job_id = "job-stack-audit";
    c.epoch = 41;
    c.machine_protocol = "v0id-remote-machine-v3";
    c.fhe_parameter_set = "STD128Q";
    for (std::size_t i = 0; i < c.semantic_binding.size(); ++i) {
        c.semantic_binding[i] = static_cast<std::uint8_t>((i * 7 + 1) & 0xffu);
        c.generator_binding[i] = static_cast<std::uint8_t>((i * 11 + 3) & 0xffu);
        c.kex_transcript_binding[i] = static_cast<std::uint8_t>((i * 13 + 5) & 0xffu);
        c.shared_modules_binding[i] = static_cast<std::uint8_t>((i * 17 + 9) & 0xffu);
    }
    return c;
}

SeriesSeed issuer_root() {
    SeriesSeed root{};
    for (std::size_t i = 0; i < root.size(); ++i)
        root[i] = static_cast<unsigned char>(0x40u + i);
    return root;
}

SharedSeriesRoot shared_root() {
    SharedSeriesRoot root{};
    for (std::size_t i = 0; i < root.size(); ++i)
        root[i] = static_cast<unsigned char>(0x90u + i);
    return root;
}

bool throws_invalid_context(SeriesFirstStackContext c) {
    try {
        (void)v0id::crypto::hash_series_first_stack_context(c);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

} // namespace

int main() try {
    Runner r;

    const auto base = base_context();
    const auto h = v0id::crypto::hash_series_first_stack_context(base);
    const auto h_again = v0id::crypto::hash_series_first_stack_context(base);
    r.check(h == h_again, "whole-stack canonical context is deterministic");

    auto changed = base;
    changed.session_id[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "session substitution changes whole-stack context");

    changed = base;
    changed.job_id += "-other";
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "job substitution changes whole-stack context");

    changed = base;
    ++changed.epoch;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "epoch substitution changes whole-stack context");

    changed = base;
    changed.semantic_binding[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "semantic substitution changes whole-stack context");

    changed = base;
    changed.generator_binding[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "generator substitution changes whole-stack context");

    changed = base;
    changed.kex_transcript_binding[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "KEX transcript substitution changes whole-stack context");

    changed = base;
    changed.shared_modules_binding[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "shared module-set substitution changes whole-stack context");

    changed = base;
    changed.outer_channel_binding = {0x54, 0x4c, 0x53, 0x2d, 0x45, 0x58, 0x50};
    r.check(v0id::crypto::hash_series_first_stack_context(changed) != h,
            "optional outer channel binding changes whole-stack context");

    const auto private_morph = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::polymorphism);
    const auto private_morph_again = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::polymorphism);
    r.check(private_morph == private_morph_again,
            "private purpose series is deterministic");

    const auto private_layout = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::machine_layout);
    const auto private_quine = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::quine_challenge);
    const auto private_integrity = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::execution_integrity);
    const auto private_plugin = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::strategy_plugin);
    r.check(private_morph != private_layout &&
            private_morph != private_quine &&
            private_morph != private_integrity &&
            private_morph != private_plugin,
            "private stack purposes are domain-separated before algorithm choice");

    const auto shared_auth = v0id::crypto::derive_shared_stack_series(
        shared_root(), h, StackPurpose::application_auth);
    const auto shared_receipt = v0id::crypto::derive_shared_stack_series(
        shared_root(), h, StackPurpose::job_receipt);
    r.check(shared_auth != shared_receipt,
            "shared post-KEM stack purposes are domain-separated");

    const auto private_auth = v0id::crypto::derive_private_stack_series(
        issuer_root(), h, StackPurpose::application_auth);
    r.check(private_auth != shared_auth,
            "issuer-private and post-KEM shared stack domains remain separate");

    const std::vector<std::uint8_t> alg_context{1,2,3,4,5,6};
    const auto alg_a = v0id::crypto::expand_stack_algorithm_later(
        private_morph, "program-morpher-v1", 1, alg_context, 32);
    const auto alg_a_again = v0id::crypto::expand_stack_algorithm_later(
        private_morph, "program-morpher-v1", 1, alg_context, 32);
    r.check(alg_a == alg_a_again,
            "algorithm-later expansion is deterministic after series exists");

    const auto alg_b = v0id::crypto::expand_stack_algorithm_later(
        private_morph, "program-morpher-v2", 1, alg_context, 32);
    r.check(alg_a != alg_b,
            "algorithm identity is bound only at algorithm-later stage");

    const auto alg_version = v0id::crypto::expand_stack_algorithm_later(
        private_morph, "program-morpher-v1", 2, alg_context, 32);
    r.check(alg_a != alg_version,
            "algorithm version substitution changes derived material");

    auto alg_context2 = alg_context;
    alg_context2[0] ^= 1u;
    const auto alg_ctx_changed = v0id::crypto::expand_stack_algorithm_later(
        private_morph, "program-morpher-v1", 1, alg_context2, 32);
    r.check(alg_a != alg_ctx_changed,
            "algorithm-specific context substitution changes derived material");

    changed = base;
    changed.session_id.fill(0);
    r.check(throws_invalid_context(changed),
            "zero session id fails closed");

    changed = base;
    changed.semantic_binding.fill(0);
    r.check(throws_invalid_context(changed),
            "missing semantic binding fails closed");

    changed = base;
    changed.generator_binding.fill(0);
    r.check(throws_invalid_context(changed),
            "missing generator binding fails closed");

    bool empty_algorithm_rejected = false;
    try {
        (void)v0id::crypto::expand_stack_algorithm_later(
            private_morph, "", 1, {}, 32);
    } catch (const std::runtime_error&) {
        empty_algorithm_rejected = true;
    }
    r.check(empty_algorithm_rejected,
            "algorithm-later adapter rejects missing algorithm identity");

    std::cout << "\nV0ID series-first whole-stack tests: "
              << r.passed << " passed, " << r.failed << " failed\n"
              << "NOTE: the stack schedule derives purpose series before algorithm IDs. "
                 "It does not replace TLS transport keys, KEM security, or execution proofs.\n";
    return r.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID series-first whole-stack test fatal error: "
              << e.what() << '\n';
    return 1;
}
