#pragma once

#include "series_first_stack.hpp"

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace v0id::crypto {

// Stage 1 for the embedded integrity path: derive issuer-private material for
// the *purpose* of execution integrity without naming a hash algorithm or local
// implementation. This is the series-first half of the boundary.
inline StackSeriesKey derive_execution_integrity_series(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const SeriesFirstStackContext& stack_context) {

    const auto context_hash = hash_series_first_stack_context(stack_context);
    return derive_private_stack_series(
        issuer_private_root, context_hash, StackPurpose::execution_integrity);
}

namespace detail {
inline void append_u64_be(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}
} // namespace detail

// Stage 2: only after execution_integrity_series already exists do we name the
// chosen hash/profile and bind private implementation material. The private hook
// binding may be a local module digest or another issuer-only implementation
// commitment; it is KDF context and is not transmitted by this API.
inline std::vector<std::uint8_t> expand_execution_integrity_algorithm_later(
    const StackSeriesKey& execution_integrity_series,
    const std::string& algorithm_id,
    std::uint64_t algorithm_version,
    const std::vector<std::uint8_t>& private_hook_binding,
    std::size_t canonical_subject_bits,
    std::size_t digest_bytes,
    std::size_t output_bytes = 64) {

    if (algorithm_id.empty() || algorithm_version == 0)
        throw std::runtime_error("execution-integrity algorithm id/version missing");
    if (canonical_subject_bits == 0 || digest_bytes == 0)
        throw std::runtime_error("execution-integrity shape must be nonzero");
    if (private_hook_binding.size() > 4096)
        throw std::runtime_error("execution-integrity private hook binding too large");

    std::vector<std::uint8_t> context;
    static constexpr char DOMAIN[] = "V0ID-EXECUTION-INTEGRITY-ALGCTX-v1";
    context.insert(context.end(), DOMAIN, DOMAIN + sizeof(DOMAIN) - 1);
    detail::append_u64_be(context,
                          static_cast<std::uint64_t>(canonical_subject_bits));
    detail::append_u64_be(context, static_cast<std::uint64_t>(digest_bytes));
    detail::append_u64_be(context,
                          static_cast<std::uint64_t>(private_hook_binding.size()));
    context.insert(context.end(),
                   private_hook_binding.begin(), private_hook_binding.end());

    return expand_stack_algorithm_later(
        execution_integrity_series,
        algorithm_id,
        algorithm_version,
        context,
        output_bytes);
}

} // namespace v0id::crypto
