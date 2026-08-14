#include "series_generator.hpp"

#include <openssl/evp.h>
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

void append_domain(std::vector<unsigned char>& out, std::string_view domain) {
    out.insert(out.end(), domain.begin(), domain.end());
    out.push_back(0);
}

std::vector<unsigned char> kmac_once(const SeriesSeed& key,
                                     const std::vector<unsigned char>& message) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
    if (!mac)
        throw std::runtime_error("OpenSSL KMAC-256 unavailable");

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx)
        throw std::runtime_error("EVP_MAC_CTX_new failed");

    std::array<unsigned char, 64> buffer{};
    std::size_t out_len = 0;
    const bool ok = EVP_MAC_init(ctx, key.data(), key.size(), nullptr) == 1 &&
                    EVP_MAC_update(ctx, message.data(), message.size()) == 1 &&
                    EVP_MAC_final(ctx, buffer.data(), &out_len, buffer.size()) == 1;
    EVP_MAC_CTX_free(ctx);

    if (!ok || out_len == 0 || out_len > buffer.size())
        throw std::runtime_error("KMAC-256 series derivation failed");

    return {buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(out_len)};
}

std::vector<std::uint8_t> expand_series(const SeriesSeed& seed,
                                        const std::vector<std::uint8_t>& input,
                                        std::uint64_t epoch,
                                        std::size_t bytes) {
    std::vector<std::uint8_t> out;
    out.reserve(bytes);

    std::uint64_t counter = 0;
    while (out.size() < bytes) {
        std::vector<unsigned char> message;
        message.reserve(64 + input.size());
        append_domain(message, "V0ID-SERIES-v1");
        append_u64(message, epoch);
        append_u64(message, counter++);
        append_u64(message, static_cast<std::uint64_t>(input.size()));
        message.insert(message.end(), input.begin(), input.end());

        const auto block = kmac_once(seed, message);
        const auto remaining = bytes - out.size();
        const auto take = std::min(remaining, block.size());
        out.insert(out.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
    }
    return out;
}

MorphSeed derive_morph_seed(const SeriesSeed& seed,
                            const std::vector<std::uint8_t>& series,
                            std::uint64_t epoch) {
    std::vector<unsigned char> message;
    message.reserve(64 + series.size());
    append_domain(message, "V0ID-SERIES-MORPH-v1");
    append_u64(message, epoch);
    append_u64(message, static_cast<std::uint64_t>(series.size()));
    message.insert(message.end(), series.begin(), series.end());

    const auto block = kmac_once(seed, message);
    if (block.size() < MorphSeed{}.size())
        throw std::runtime_error("KMAC series output too short for morph seed");

    MorphSeed out{};
    std::copy_n(block.begin(), out.size(), out.begin());
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
    if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1)
        throw std::runtime_error("RAND_bytes failed while generating series seed");
    return seed;
}

KmacSeriesGenerator::KmacSeriesGenerator(std::size_t series_bytes)
    : series_bytes_(series_bytes) {
    if (series_bytes_ == 0 || series_bytes_ > MAX_SERIES_BYTES)
        throw std::runtime_error("KMAC series length outside local limit");
}

SeriesProfile KmacSeriesGenerator::profile() const {
    SeriesProfile out;
    out.generator_id = "v0id-series-kmac-v1";
    out.version = 1;
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

    // Keep a small client-only provenance token so later experiments can bind
    // trace measurements to a derivation without exposing the series itself.
    std::vector<unsigned char> manifest_message;
    manifest_message.reserve(64 + out.series.size());
    append_domain(manifest_message, "V0ID-SERIES-MANIFEST-v1");
    append_u64(manifest_message, epoch);
    manifest_message.insert(manifest_message.end(), out.series.begin(), out.series.end());
    const auto manifest_block = kmac_once(seed, manifest_message);
    const auto manifest_size = std::min<std::size_t>(16, manifest_block.size());
    out.private_manifest.assign(manifest_block.begin(),
                                manifest_block.begin() + static_cast<std::ptrdiff_t>(manifest_size));

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
