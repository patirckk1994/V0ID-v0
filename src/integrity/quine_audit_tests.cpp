#include "quine_hash.hpp"
#include "program_morpher.hpp"
#include "series_generator.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::integrity::AuditChallenge256;
using v0id::integrity::QuineDigest512;
using v0id::integrity::QuineHashContext;
using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::SeriesProfile;
using v0id::polymorph::SeriesSeed;

struct TestRunner {
    int passed{};
    int failed{};

    void expect(bool condition, const std::string& name,
                const std::string& reason) {
        if (condition) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << ": " << reason << '\n';
        }
    }
};

Program increment_program() {
    return Program{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
}

SeriesSeed deterministic_root(std::uint16_t reduced) {
    SeriesSeed root{};
    root[0] = static_cast<unsigned char>((reduced >> 8) & 0xffu);
    root[1] = static_cast<unsigned char>(reduced & 0xffu);
    // Domain-label the deliberately reduced test keys so they cannot be confused
    // with production roots should test material ever be logged or serialized.
    constexpr char marker[] = "V0ID-REDUCED-AUDIT";
    for (std::size_t i = 0; i < sizeof(marker) - 1 && i + 2 < root.size(); ++i)
        root[i + 2] = static_cast<unsigned char>(marker[i]);
    return root;
}

std::size_t hamming_distance(const QuineDigest512& a,
                             const QuineDigest512& b) {
    std::size_t bits = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        std::uint8_t x = static_cast<std::uint8_t>(a[i] ^ b[i]);
        for (; x != 0; x = static_cast<std::uint8_t>(x & (x - 1)))
            ++bits;
    }
    return bits;
}

bool same(const QuineDigest512& a, const QuineDigest512& b) {
    return a == b;
}

v0id::fhe::EvaluatorSessionId session_id(std::uint8_t bias = 0) {
    v0id::fhe::EvaluatorSessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(i + 1 + bias);
    return id;
}

QuineHashContext base_context(const Program& morphed,
                              const Program& semantic,
                              const SeriesProfile& profile,
                              const std::vector<int>& tape,
                              std::size_t initial_state,
                              const std::vector<std::uint8_t>& implementation = {}) {
    QuineHashContext context;
    context.shape = {morphed.states, tape.size(), 4, 4};
    context.profile = {
        "openfhe-binfhe",
        "STD128Q",
        "v0id-remote-machine-v3",
        "quine-sha3-512-client-v1+toy-fhe32",
        profile.generator_id,
        profile.version,
    };
    context.session_id = session_id();
    context.job_id = "quine-composition-audit";
    context.epoch = 7;
    context.initial_state = initial_state;
    context.initial_head = 0;
    context.initial_tape = tape;
    context.semantic_binding = v0id::integrity::semantic_job_hash512(
        semantic, 0, 0, tape, context.shape.rounds);
    context.generator_binding = v0id::integrity::generator_binding512(
        profile, implementation);
    return context;
}

} // namespace

int main() try {
    TestRunner tests;

    // Independent well-known SHA3-512 test vector for "abc".
    const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
    const auto abc_digest = v0id::integrity::hex_digest(
        v0id::integrity::sha3_512_bytes(abc));
    tests.expect(
        abc_digest ==
            "b751850b1a57168a5693cd924b6b096e080f621827444f70d884f5d0240d2712"
            "e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        "OpenSSL SHA3-512 matches abc known answer",
        "unexpected SHA3-512 digest");

    const Program semantic = increment_program();
    const std::vector<int> tape{1,0,1,1,0,0,0,0};
    KmacSeriesGenerator generator(64);
    const auto profile = generator.profile();
    const auto private_root = deterministic_root(0x1234);
    std::vector<std::uint8_t> input;
    for (int bit : tape)
        input.push_back(static_cast<std::uint8_t>(bit));
    const auto derived = generator.derive(input, private_root, 7);
    const auto morph = ProgramMorpher::morph(
        semantic, 0, 4, derived.morph_seed, 4);

    auto context = base_context(
        morph.program, semantic, profile, tape, morph.initial_state);
    const auto challenge = v0id::integrity::derive_audit_challenge256(
        private_root, context.session_id, context.job_id, context.epoch);
    const auto q = v0id::integrity::quine_hash512(
        morph.program, context, challenge);
    const auto q_again = v0id::integrity::quine_hash512(
        morph.program, context, challenge);
    tests.expect(q == q_again,
                 "canonical quine commitment is deterministic",
                 "same canonical object produced different digest");

    auto changed = context;
    changed.profile.parameter_set = "STD128";
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "FHE parameter downgrade changes quine commitment",
                 "STD128Q -> STD128 was not bound");

    changed = context;
    changed.session_id = session_id(9);
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "session substitution changes quine commitment",
                 "session id was not bound");

    changed = context;
    changed.job_id += "-other";
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "job substitution changes quine commitment",
                 "job id was not bound");

    changed = context;
    ++changed.epoch;
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "epoch substitution changes quine commitment",
                 "epoch was not bound");

    changed = context;
    changed.semantic_binding[0] ^= 1u;
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "semantic-job substitution changes quine commitment",
                 "issuer semantic binding was not bound");

    changed = context;
    changed.generator_binding[0] ^= 1u;
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, changed, challenge)),
                 "generator implementation substitution changes quine commitment",
                 "generator binding was not bound");

    auto challenge2 = challenge;
    challenge2[0] ^= 1u;
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           morph.program, context, challenge2)),
                 "audit-challenge substitution changes quine commitment",
                 "private challenge was not bound");

    auto altered_program = morph.program;
    altered_program.rules[0].write ^= 1;
    tests.expect(!same(q, v0id::integrity::quine_hash512(
                           altered_program, context, challenge)),
                 "morphed executable substitution changes quine commitment",
                 "morphed machine was not bound");

    const auto changed_root = deterministic_root(0x1235);
    const auto changed_challenge = v0id::integrity::derive_audit_challenge256(
        changed_root, context.session_id, context.job_id, context.epoch);
    tests.expect(challenge != changed_challenge,
                 "private series root changes audit challenge",
                 "challenge did not depend on private series root");

    // Reduced-domain structural screen. This does NOT prove quantum security.
    // It is an exhaustive falsification test for an exact XOR period over a
    // 10-bit projection of the private series root, the structure Simon's
    // algorithm would exploit if it generalized to the full function.
    constexpr std::uint16_t REDUCED_BITS = 10;
    constexpr std::uint16_t DOMAIN = 1u << REDUCED_BITS;
    std::vector<QuineDigest512> series_images(DOMAIN);
    std::set<std::string> unique_images;
    for (std::uint16_t x = 0; x < DOMAIN; ++x) {
        const auto root = deterministic_root(x);
        const auto out = generator.derive(input, root, 7);
        series_images[x] = v0id::integrity::sha3_512_bytes(out.series);
        unique_images.insert(v0id::integrity::hex_digest(series_images[x]));
    }
    tests.expect(unique_images.size() == DOMAIN,
                 "reduced 10-bit series roots have unique 512-bit images",
                 "collision found in reduced-domain series screen");

    bool exact_xor_period = false;
    std::uint16_t offending_period = 0;
    for (std::uint16_t s = 1; s < DOMAIN && !exact_xor_period; ++s) {
        bool period = true;
        for (std::uint16_t x = 0; x < DOMAIN; ++x) {
            if (series_images[x] != series_images[x ^ s]) {
                period = false;
                break;
            }
        }
        if (period) {
            exact_xor_period = true;
            offending_period = s;
        }
    }
    tests.expect(!exact_xor_period,
                 "no exact XOR period in exhaustive reduced-domain series screen",
                 "found reduced XOR period " + std::to_string(offending_period));

    std::size_t avalanche_sum = 0;
    std::size_t avalanche_samples = 0;
    std::size_t avalanche_min = 512;
    for (std::uint16_t x = 0; x < DOMAIN; ++x) {
        for (std::uint16_t bit = 0; bit < REDUCED_BITS; ++bit) {
            const auto y = static_cast<std::uint16_t>(x ^ (1u << bit));
            if (x < y) {
                const auto distance = hamming_distance(series_images[x], series_images[y]);
                avalanche_sum += distance;
                avalanche_min = std::min(avalanche_min, distance);
                ++avalanche_samples;
            }
        }
    }
    const double avalanche_average = avalanche_samples == 0
        ? 0.0
        : static_cast<double>(avalanche_sum) /
              static_cast<double>(avalanche_samples);
    std::cout << "[INFO] reduced-series SHA3 image avalanche avg="
              << avalanche_average << "/512 min=" << avalanche_min << "/512\n";
    tests.expect(avalanche_average > 220.0 && avalanche_average < 292.0,
                 "reduced series screen has no gross avalanche bias",
                 "average digest Hamming distance outside broad sanity band");

    std::cout << "\nV0ID PQR composition audit tests: "
              << tests.passed << " passed, " << tests.failed << " failed\n";
    std::cout << "NOTE: reduced-period/avalanche tests can falsify obvious structure; "
                 "they are not a proof against future quantum algorithms.\n";
    return tests.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID PQR composition audit fatal error: " << e.what() << '\n';
    return 1;
}
