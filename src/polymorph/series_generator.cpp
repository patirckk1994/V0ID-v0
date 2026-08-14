#include "series_generator.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace v0id::polymorph {
namespace {

constexpr std::size_t MAX_SERIES_BYTES = 1024 * 1024;

void append_u64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<unsigned char>((value >> shift) & 0xffu));
}

void append_blob(std::vector<unsigned char>& out,
                 const std::uint8_t* data,
                 std::size_t size) {
    append_u64(out, static_cast<std::uint64_t>(size));
    if (size != 0)
        out.insert(out.end(), data, data + size);
}

std::vector<std::uint8_t> kmacxof256(
    const SeriesSeed& key,
    const std::vector<std::uint8_t>& message,
    std::string_view customization,
    std::size_t output_bytes) {
    if (output_bytes == 0 || output_bytes > MAX_SERIES_BYTES)
        throw std::runtime_error("KMACXOF256 output length outside local limit");

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
    if (!mac)
        throw std::runtime_error("OpenSSL KMAC-256 unavailable");

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx)
        throw std::runtime_error("EVP_MAC_CTX_new failed");

    int xof = 1;
    std::size_t requested = output_bytes;
    auto* custom_ptr = const_cast<char*>(customization.data());
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM, custom_ptr, customization.size()),
        OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof),
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &requested),
        OSSL_PARAM_construct_end(),
    };

    std::vector<std::uint8_t> out(output_bytes);
    std::size_t written = 0;
    const bool ok =
        EVP_MAC_init(ctx, key.data(), key.size(), params) == 1 &&
        EVP_MAC_update(ctx, message.data(), message.size()) == 1 &&
        EVP_MAC_final(ctx, out.data(), &written, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);

    if (!ok || written != output_bytes)
        throw std::runtime_error("OpenSSL KMACXOF256 derivation failed");
    return out;
}

std::vector<std::uint8_t> series_message(
    const std::vector<std::uint8_t>& input,
    std::uint64_t epoch) {
    std::vector<std::uint8_t> message;
    message.reserve(32 + input.size());
    append_u64(message, 2); // schedule version
    append_u64(message, epoch);
    append_blob(message, input.data(), input.size());
    return message;
}

std::vector<std::uint8_t> expand_series(const SeriesSeed& seed,
                                        const std::vector<std::uint8_t>& input,
                                        std::uint64_t epoch,
                                        std::size_t bytes) {
    return kmacxof256(seed, series_message(input, epoch),
                      "V0ID private polymorphic series v2", bytes);
}

MorphSeed derive_morph_seed(const SeriesSeed& seed,
                            const std::vector<std::uint8_t>& series,
                            std::uint64_t epoch) {
    std::vector<std::uint8_t> message;
    message.reserve(24 + series.size());
    append_u64(message, 2);
    append_u64(message, epoch);
    append_blob(message, series.data(), series.size());

    const auto block = kmacxof256(
        seed, message, "V0ID trusted ProgramMorpher seed v2", MorphSeed{}.size());
    MorphSeed out{};
    std::copy(block.begin(), block.end(), out.begin());
    return out;
}

void validate_profile(const SeriesProfile& profile) {
    if (profile.generator_id.empty())
        throw std::runtime_error("series generator id must not be empty");
    if (profile.generator_id.size() > 96)
        throw std::runtime_error("series generator id too long");
    if (profile.version == 0)
        throw std::runtime_error("series generator version must be positive");
    if (profile.parameters.size() > 4096)
        throw std::runtime_error("series generator parameter blob too large");
}

void validate_derived(const DerivedSeries& derived) {
    if (derived.series.empty())
        throw std::runtime_error("series generator returned an empty series");
    if (derived.series.size() > MAX_SERIES_BYTES)
        throw std::runtime_error("series generator output exceeds local limit");
    if (derived.private_manifest.size() > MAX_SERIES_BYTES)
        throw std::runtime_error("series generator private manifest exceeds local limit");
}

} // namespace

SeriesSeed random_series_seed() {
    SeriesSeed seed{};
    // This root is intended never to become evaluator-visible. OpenSSL's private
    // RAND instance separates private values from public random outputs while
    // retaining the platform-seeded CSPRNG and explicit failure handling.
    if (RAND_priv_bytes(seed.data(), static_cast<int>(seed.size())) != 1)
        throw std::runtime_error("RAND_priv_bytes failed while generating private series root");
    return seed;
}

KmacSeriesGenerator::KmacSeriesGenerator(std::size_t series_bytes)
    : series_bytes_(series_bytes) {
    if (series_bytes_ == 0 || series_bytes_ > MAX_SERIES_BYTES)
        throw std::runtime_error("KMACXOF series length outside local limit");
}

SeriesProfile KmacSeriesGenerator::profile() const {
    SeriesProfile out;
    out.generator_id = "v0id-series-kmacxof256-v2";
    out.version = 2;
    out.parameters.resize(8);
    const auto n = static_cast<std::uint64_t>(series_bytes_);
    for (int i = 0; i < 8; ++i)
        out.parameters[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((n >> ((7 - i) * 8)) & 0xffu);
    return out;
}

DerivedSeries KmacSeriesGenerator::derive(const std::vector<std::uint8_t>& input,
                                          const SeriesSeed& seed,
                                          std::uint64_t epoch) const {
    DerivedSeries out;
    out.series = expand_series(seed, input, epoch, series_bytes_);
    out.morph_seed = derive_morph_seed(seed, out.series, epoch);

    // Client-only provenance token under a third customization string. Distinct
    // domains ensure series bytes, morph material and provenance never reuse the
    // same KMACXOF output stream as interchangeable key material.
    std::vector<std::uint8_t> manifest_message;
    manifest_message.reserve(24 + out.series.size());
    append_u64(manifest_message, 2);
    append_u64(manifest_message, epoch);
    append_blob(manifest_message, out.series.data(), out.series.size());
    out.private_manifest = kmacxof256(
        seed, manifest_message, "V0ID private series provenance v2", 16);

    validate_derived(out);
    return out;
}

FunctionalSeriesGenerator::FunctionalSeriesGenerator(
    SeriesProfile profile,
    SeriesDeriveFunction derive_function)
    : profile_(std::move(profile)),
      derive_function_(std::move(derive_function)) {
    validate_profile(profile_);
    if (!derive_function_)
        throw std::runtime_error("user series derive function must not be empty");
}

SeriesProfile FunctionalSeriesGenerator::profile() const {
    return profile_;
}

DerivedSeries FunctionalSeriesGenerator::derive(
    const std::vector<std::uint8_t>& input,
    const SeriesSeed& seed,
    std::uint64_t epoch) const {
    auto out = derive_function_(input, seed, epoch);
    validate_derived(out);
    return out;
}

} // namespace v0id::polymorph
