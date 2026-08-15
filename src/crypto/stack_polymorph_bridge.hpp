#pragma once

#include "series_first_stack.hpp"
#include "program_morpher.hpp"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace v0id::crypto {

// Convert the issuer-private whole-stack polymorphism purpose series into the
// concrete ProgramMorpher seed only at the algorithm-later stage.
//
// generator_series is the already-derived client-local unpredictable series
// produced before the concrete morpher algorithm is selected. Keeping it in the
// algorithm context preserves the pluggable series-generator influence while
// the independent StackPurpose::polymorphism domain prevents that generator
// output from becoming the sole security-sensitive root.
inline v0id::polymorph::MorphSeed derive_program_morph_seed_from_stack(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const SeriesFirstStackContext& stack_context,
    const std::vector<std::uint8_t>& generator_series) {

    if (generator_series.empty())
        throw std::runtime_error("program morph seed requires a non-empty private series");

    const auto context_hash = hash_series_first_stack_context(stack_context);
    const auto polymorphism_series = derive_private_stack_series(
        issuer_private_root, context_hash, StackPurpose::polymorphism);

    const auto material = expand_stack_algorithm_later(
        polymorphism_series,
        "program-morpher-v1",
        1,
        generator_series,
        v0id::polymorph::MorphSeed{}.size());

    if (material.size() != v0id::polymorph::MorphSeed{}.size())
        throw std::runtime_error("program morph seed expansion returned wrong length");

    v0id::polymorph::MorphSeed out{};
    std::copy(material.begin(), material.end(), out.begin());
    return out;
}

} // namespace v0id::crypto
