#include "canonical_self_image.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace v0id::integrity {
namespace {

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

std::uint64_t checked_u64(std::size_t value, const char* what) {
    if constexpr (sizeof(std::size_t) > sizeof(std::uint64_t)) {
        if (value > std::numeric_limits<std::uint64_t>::max())
            throw std::runtime_error(std::string(what) + " exceeds canonical u64 range");
    }
    return static_cast<std::uint64_t>(value);
}

void append_blob(std::vector<std::uint8_t>& out,
                 const std::uint8_t* data,
                 std::size_t size) {
    append_u64(out, checked_u64(size, "canonical self-image blob length"));
    if (size != 0)
        out.insert(out.end(), data, data + size);
}

void append_string(std::vector<std::uint8_t>& out, std::string_view value) {
    append_u64(out, checked_u64(value.size(), "canonical self-image string length"));
    out.insert(out.end(), value.begin(), value.end());
}

template <std::size_t N>
bool all_zero(const std::array<std::uint8_t, N>& value) {
    return std::all_of(value.begin(), value.end(),
                       [](std::uint8_t b) { return b == 0; });
}

std::vector<bool> excluded_mask(const v0id::core::Program& program,
                                const std::vector<std::size_t>& excluded) {
    std::vector<bool> mask(program.states, false);
    for (const auto state : excluded) {
        if (state >= program.states)
            throw std::runtime_error("canonical self-image excluded state out of range");
        if (mask[state])
            throw std::runtime_error("canonical self-image duplicate excluded state");
        mask[state] = true;
    }
    return mask;
}

void append_program(std::vector<std::uint8_t>& out,
                    const v0id::core::Program& program,
                    const std::vector<std::size_t>& excluded) {
    program.validate();
    const auto mask = excluded_mask(program, excluded);

    append_u64(out, checked_u64(program.states, "canonical self-image state count"));
    append_u64(out, checked_u64(program.states * 2,
                                "canonical self-image transition count"));

    // Canonical semantic order, independent of vector storage order. Excluded
    // integrity rows retain their location in the final public state image but
    // their transition payload is replaced by one canonical zero representation.
    for (std::size_t state = 0; state < program.states; ++state) {
        for (int read = 0; read <= 1; ++read) {
            append_u64(out, checked_u64(state, "canonical self-image state id"));
            out.push_back(static_cast<std::uint8_t>(read));
            out.push_back(mask[state] ? std::uint8_t{1} : std::uint8_t{0});

            if (mask[state]) {
                append_u64(out, 0);
                out.push_back(0); // write
                out.push_back(1); // canonical move=stay encoding: move+1
            } else {
                const auto& rule = program.rule(state, read);
                append_u64(out, checked_u64(rule.next_state,
                                            "canonical self-image next-state id"));
                out.push_back(static_cast<std::uint8_t>(rule.write));
                out.push_back(static_cast<std::uint8_t>(rule.move + 1));
            }
        }
    }
}

void validate_context(const v0id::core::Program& program,
                      const CanonicalSelfImageContext& context) {
    program.validate();

    if (all_zero(context.session_id))
        throw std::runtime_error("canonical self-image requires a nonzero session id");
    if (context.job_id.empty())
        throw std::runtime_error("canonical self-image requires a job id");
    if (context.machine_protocol.empty() || context.fhe_parameter_set.empty())
        throw std::runtime_error("canonical self-image requires machine/FHE profile ids");
    if (context.initial_state >= program.states)
        throw std::runtime_error("canonical self-image initial state out of range");
    if (context.initial_tape.empty() || context.initial_head >= context.initial_tape.size())
        throw std::runtime_error("canonical self-image initial tape/head invalid");
    for (const int bit : context.initial_tape)
        if (bit != 0 && bit != 1)
            throw std::runtime_error("canonical self-image tape must be binary");

    if (context.semantic_rounds == 0 || context.integrity_rounds == 0)
        throw std::runtime_error("canonical self-image requires semantic and integrity rounds");
    if (context.integrity_rounds >
        std::numeric_limits<std::size_t>::max() - context.semantic_rounds ||
        context.total_execution_rounds !=
            context.semantic_rounds + context.integrity_rounds)
        throw std::runtime_error("canonical self-image total round accounting mismatch");

    if (all_zero(context.semantic_binding) || all_zero(context.generator_binding))
        throw std::runtime_error("canonical self-image requires semantic/generator bindings");
    if (context.private_integrity_challenge.empty() ||
        context.private_integrity_challenge.size() > 4096)
        throw std::runtime_error("canonical self-image private integrity challenge invalid");
    if (context.digest_slot_bytes == 0 || context.digest_slot_bytes > 4096)
        throw std::runtime_error("canonical self-image digest slot size invalid");
}

std::vector<std::uint8_t> encode(
    const v0id::core::Program& program,
    const std::vector<std::size_t>& excluded_integrity_states,
    const CanonicalSelfImageContext& context) {

    validate_context(program, context);

    std::vector<std::uint8_t> out;
    append_string(out, "V0ID-CANONICAL-SELF-IMAGE-v1");
    append_u64(out, 1);

    append_blob(out, context.session_id.data(), context.session_id.size());
    append_string(out, context.job_id);
    append_u64(out, context.epoch);
    append_string(out, context.machine_protocol);
    append_string(out, context.fhe_parameter_set);

    append_u64(out, checked_u64(context.initial_state,
                                "canonical self-image initial state"));
    append_u64(out, checked_u64(context.initial_head,
                                "canonical self-image initial head"));
    append_u64(out, checked_u64(context.initial_tape.size(),
                                "canonical self-image tape length"));
    for (const int bit : context.initial_tape)
        out.push_back(static_cast<std::uint8_t>(bit));

    append_u64(out, checked_u64(context.semantic_rounds,
                                "canonical self-image semantic rounds"));
    append_u64(out, checked_u64(context.integrity_rounds,
                                "canonical self-image integrity rounds"));
    append_u64(out, checked_u64(context.total_execution_rounds,
                                "canonical self-image total rounds"));

    append_blob(out, context.semantic_binding.data(), context.semantic_binding.size());
    append_blob(out, context.generator_binding.data(), context.generator_binding.size());
    append_blob(out,
                context.private_integrity_challenge.data(),
                context.private_integrity_challenge.size());

    append_string(out, "V0ID-FINAL-PROGRAM-MASKED-INTEGRITY-v1");
    append_program(out, program, excluded_integrity_states);

    // Canonical self-reference/output rule. Result storage is represented as a
    // fixed-size all-zero field, so no digest fixed point is required.
    append_string(out, "V0ID-INTEGRITY-DIGEST-SLOT-v1");
    append_u64(out, checked_u64(context.digest_slot_bytes,
                                "canonical self-image digest slot bytes"));
    out.insert(out.end(), context.digest_slot_bytes, std::uint8_t{0});

    return out;
}

std::vector<int> to_bits(const std::vector<std::uint8_t>& bytes) {
    std::vector<int> bits;
    bits.reserve(bytes.size() * 8);
    for (const auto byte : bytes) {
        for (int shift = 7; shift >= 0; --shift)
            bits.push_back(static_cast<int>((byte >> shift) & 1u));
    }
    return bits;
}

} // namespace

std::vector<std::uint8_t> canonical_self_image_v1(
    const v0id::core::Program& program,
    const CanonicalSelfImageContext& context) {
    return encode(program, {}, context);
}

std::vector<std::uint8_t> canonical_self_image_v1_masked(
    const v0id::core::Program& final_morphed_program,
    const std::vector<std::size_t>& excluded_integrity_states,
    const CanonicalSelfImageContext& context) {
    if (excluded_integrity_states.empty())
        throw std::runtime_error("masked canonical self-image requires integrity states");
    return encode(final_morphed_program, excluded_integrity_states, context);
}

std::vector<int> canonical_self_image_bits_v1(
    const v0id::core::Program& program,
    const CanonicalSelfImageContext& context) {
    return to_bits(canonical_self_image_v1(program, context));
}

std::vector<int> canonical_self_image_bits_v1_masked(
    const v0id::core::Program& final_morphed_program,
    const std::vector<std::size_t>& excluded_integrity_states,
    const CanonicalSelfImageContext& context) {
    return to_bits(canonical_self_image_v1_masked(
        final_morphed_program, excluded_integrity_states, context));
}

} // namespace v0id::integrity
