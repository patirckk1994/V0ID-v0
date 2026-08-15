#include "canonical_self_image.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::integrity::CanonicalSelfImageContext;

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

CanonicalSelfImageContext base_context() {
    CanonicalSelfImageContext c;
    for (std::size_t i = 0; i < c.session_id.size(); ++i)
        c.session_id[i] = static_cast<std::uint8_t>(i + 1);
    c.job_id = "canonical-self-image-test";
    c.epoch = 17;
    c.machine_protocol = "v0id-remote-machine-v3";
    c.fhe_parameter_set = "STD128Q";
    c.initial_state = 0;
    c.initial_head = 0;
    c.initial_tape = {1,0,1,1,0,0,0,0};
    c.semantic_rounds = 4;
    c.integrity_rounds = 9;
    c.total_execution_rounds = 13;
    for (std::size_t i = 0; i < c.semantic_binding.size(); ++i) {
        c.semantic_binding[i] = static_cast<std::uint8_t>((i * 3 + 1) & 0xffu);
        c.generator_binding[i] = static_cast<std::uint8_t>((i * 7 + 5) & 0xffu);
    }
    c.private_integrity_challenge.resize(32);
    for (std::size_t i = 0; i < c.private_integrity_challenge.size(); ++i)
        c.private_integrity_challenge[i] = static_cast<std::uint8_t>(0xa0u + i);
    c.digest_slot_bytes = 64;
    return c;
}

Program increment_program() {
    return Program{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
}

bool throws_bad_round_accounting() {
    try {
        auto c = base_context();
        ++c.total_execution_rounds;
        (void)v0id::integrity::canonical_self_image_v1(increment_program(), c);
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    const auto program = increment_program();
    const auto context = base_context();
    const auto canonical =
        v0id::integrity::canonical_self_image_v1(program, context);
    const auto canonical_again =
        v0id::integrity::canonical_self_image_v1(program, context);

    pass(!canonical.empty(), "CanonicalSelfImageV1 is non-empty");
    pass(canonical == canonical_again,
         "CanonicalSelfImageV1 is deterministic for identical input");

    auto changed_program = program;
    changed_program.rules[0].write ^= 1;
    pass(v0id::integrity::canonical_self_image_v1(changed_program, context) != canonical,
         "semantic program mutation changes canonical self-image");

    auto changed = context;
    changed.job_id += "-other";
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "job substitution changes canonical self-image");

    changed = context;
    changed.session_id[0] ^= 1u;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "session substitution changes canonical self-image");

    changed = context;
    ++changed.epoch;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "epoch substitution changes canonical self-image");

    changed = context;
    ++changed.semantic_rounds;
    ++changed.total_execution_rounds;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "semantic round-budget substitution changes canonical self-image");

    changed = context;
    ++changed.integrity_rounds;
    ++changed.total_execution_rounds;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "integrity round-budget substitution changes canonical self-image");

    changed = context;
    changed.private_integrity_challenge[7] ^= 0x55u;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "private integrity challenge substitution changes canonical self-image");

    changed = context;
    changed.digest_slot_bytes = 32;
    pass(v0id::integrity::canonical_self_image_v1(program, changed) != canonical,
         "fixed digest-slot capacity is canonically bound");

    const auto bits =
        v0id::integrity::canonical_self_image_bits_v1(program, context);
    pass(bits.size() == canonical.size() * 8,
         "canonical bit image has exactly eight bits per byte");

    bool bits_match = true;
    for (std::size_t i = 0; i < canonical.size() && bits_match; ++i) {
        for (int shift = 7; shift >= 0; --shift) {
            const auto bit_index = i * 8 + static_cast<std::size_t>(7 - shift);
            if (bits[bit_index] != static_cast<int>((canonical[i] >> shift) & 1u)) {
                bits_match = false;
                break;
            }
        }
    }
    pass(bits_match,
         "client byte encoding and future encrypted bit consumer are bit-identical");

    pass(throws_bad_round_accounting(),
         "canonical self-image rejects inconsistent total round accounting");

    std::cout << "V0ID CanonicalSelfImageV1 tests: "
              << passed << " passed, 0 failed\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "[FAIL] " << e.what() << '\n';
    return 1;
}
