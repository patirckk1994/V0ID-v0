#pragma once

#include "series_first_schedule.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::crypto {

using StackContextHash512 = std::array<std::uint8_t, 64>;
using StackSeriesKey = std::array<unsigned char, 32>;

// Purpose is selected before any concrete algorithm. This is the central
// "series first, algorithm later" boundary for the V0ID semantic/security
// stack. Transport encryption itself intentionally is not one of these domains.
enum class StackPurpose : std::uint8_t {
    machine_layout = 1,
    polymorphism = 2,
    quine_challenge = 3,
    strategy_plugin = 4,
    execution_integrity = 5,
    application_auth = 6,
    job_receipt = 7,
};

// Canonical context shared by the stack schedule. The KEX transcript binding is
// optional: all-zero means the job is not attached to the application-level KEM
// schedule. outer_channel_binding is also optional and is where a future TLS
// exporter/channel-binding value may be committed. V0ID does not derive or
// replace TLS traffic keys here.
struct SeriesFirstStackContext {
    std::string protocol_id{"v0id-series-first-stack-v1"};
    std::array<std::uint8_t, 32> session_id{};
    std::string job_id;
    std::uint64_t epoch{};
    std::string machine_protocol;
    std::string fhe_parameter_set;
    std::array<std::uint8_t, 64> semantic_binding{};
    std::array<std::uint8_t, 64> generator_binding{};
    TranscriptHash512 kex_transcript_binding{};
    std::vector<std::uint8_t> outer_channel_binding;
};

StackContextHash512 hash_series_first_stack_context(
    const SeriesFirstStackContext& context);

const char* stack_purpose_name(StackPurpose purpose);

// Stage 1: derive a purpose-specific pseudorandom series key without naming a
// concrete downstream algorithm. Private and post-KEM shared schedules use
// distinct KMAC domains even when all public context is identical.
StackSeriesKey derive_private_stack_series(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const StackContextHash512& context_hash,
    StackPurpose purpose);

StackSeriesKey derive_shared_stack_series(
    const SharedSeriesRoot& post_kem_shared_root,
    const StackContextHash512& context_hash,
    StackPurpose purpose);

// Stage 2: only after the purpose series exists do we bind/select an algorithm.
// algorithm_context should carry algorithm-specific public parameters and, for
// post-quine execution-integrity material, the QuineHash512 digest. The function
// is a KDF/series adapter, not an implementation of the selected algorithm.
std::vector<std::uint8_t> expand_stack_algorithm_later(
    const StackSeriesKey& purpose_series,
    const std::string& algorithm_id,
    std::uint64_t algorithm_version,
    const std::vector<std::uint8_t>& algorithm_context,
    std::size_t output_bytes);

} // namespace v0id::crypto
