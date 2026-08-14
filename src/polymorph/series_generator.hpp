#pragma once

#include "program_morpher.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace v0id::polymorph {

using SeriesSeed = std::array<unsigned char, 32>;

struct SeriesProfile {
    std::string generator_id;
    std::uint32_t version{};
    std::vector<std::uint8_t> parameters;
};

// Client-side result of the series-first derivation stage. The series and the
// private manifest are not evaluator inputs. morph_seed is the bridge into the
// existing ProgramMorpher and is deliberately derived client-side.
struct DerivedSeries {
    std::vector<std::uint8_t> series;
    MorphSeed morph_seed{};
    std::vector<std::uint8_t> private_manifest;
};

class PolymorphicSeriesGenerator {
public:
    virtual ~PolymorphicSeriesGenerator() = default;

    virtual SeriesProfile profile() const = 0;
    virtual DerivedSeries derive(const std::vector<std::uint8_t>& input,
                                 const SeriesSeed& seed,
                                 std::uint64_t epoch) const = 0;
};

SeriesSeed random_series_seed();

// Built-in deterministic research generator. It expands a private 256-bit seed,
// epoch and input through KMAC-256 into a private byte series, then derives the
// ProgramMorpher seed from that series under a distinct KMAC domain. This is a
// concrete series-first plumbing experiment, NOT a claim that arbitrary series
// are intrinsically post-quantum hard or that a new cryptographic primitive has
// been proven.
class KmacSeriesGenerator final : public PolymorphicSeriesGenerator {
public:
    explicit KmacSeriesGenerator(std::size_t series_bytes = 64);

    SeriesProfile profile() const override;
    DerivedSeries derive(const std::vector<std::uint8_t>& input,
                         const SeriesSeed& seed,
                         std::uint64_t epoch) const override;

private:
    std::size_t series_bytes_{};
};

// Safe extension seam for user-injected polymorphic patterns inside the local
// process. This intentionally is not a network plugin loader: the application
// supplies trusted code and an explicit public identifier/version.
using SeriesDeriveFunction = std::function<DerivedSeries(
    const std::vector<std::uint8_t>&,
    const SeriesSeed&,
    std::uint64_t)>;

class FunctionalSeriesGenerator final : public PolymorphicSeriesGenerator {
public:
    FunctionalSeriesGenerator(SeriesProfile profile,
                              SeriesDeriveFunction derive_function);

    SeriesProfile profile() const override;
    DerivedSeries derive(const std::vector<std::uint8_t>& input,
                         const SeriesSeed& seed,
                         std::uint64_t epoch) const override;

private:
    SeriesProfile profile_;
    SeriesDeriveFunction derive_function_;
};

} // namespace v0id::polymorph
