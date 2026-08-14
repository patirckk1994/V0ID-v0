#pragma once

#include "program_morpher.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace v0id::polymorph {

// Issuer-only 256-bit root for the private series-first schedule. The built-in
// generator obtains fresh roots from OpenSSL RAND_priv_bytes(). A peer must not
// learn this value merely because it participates in a transport/key-exchange
// session; otherwise it could reproduce the issuer's polymorphism.
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

// Built-in series-first generator. Version 2 uses OpenSSL KMAC-256 in XOF mode
// (the KMACXOF256 construction) to expand an issuer-only 256-bit root, semantic
// input and epoch into arbitrary-length private series bytes. Separate KMACXOF
// customization strings derive ProgramMorpher material and private provenance,
// preventing those outputs from being treated as interchangeable key material.
//
// This gives the polymorphism schedule a standardized symmetric PRF/XOF base. It
// does NOT turn arbitrary series into a new hardness assumption and does not
// replace a standardized KEM for key exchange. A later key-exchange layer may
// absorb a standardized KEM shared secret into its own domain-separated shared
// series schedule while this issuer-only root remains private.
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
// supplies trusted code and an explicit public identifier/version. Security-
// critical challenges must not be keyed solely by plugin-controlled output.
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
