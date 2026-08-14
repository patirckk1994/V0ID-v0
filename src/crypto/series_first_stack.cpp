#include "series_first_stack.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace v0id::crypto {
namespace {

constexpr std::size_t MAX_DERIVED_BYTES = 1024 * 1024;

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

void append_blob(std::vector<std::uint8_t>& out,
                 const std::uint8_t* data,
                 std::size_t size) {
    append_u64(out, static_cast<std::uint64_t>(size));
    if (size != 0)
        out.insert(out.end(), data, data + size);
}

void append_string(std::vector<std::uint8_t>& out, std::string_view value) {
    append_u64(out, static_cast<std::uint64_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

bool all_zero(const std::uint8_t* data, std::size_t size) {
    return std::all_of(data, data + size,
                       [](std::uint8_t b) { return b == 0; });
}

StackContextHash512 sha3_512(const std::vector<std::uint8_t>& bytes) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-512 unavailable for stack context");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    StackContextHash512 out{};
    unsigned int written = 0;
    const bool ok =
        EVP_DigestInit_ex2(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &written) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (!ok || written != out.size())
        throw std::runtime_error("OpenSSL SHA3-512 stack context hash failed");
    return out;
}

std::vector<std::uint8_t> kmacxof256(
    const unsigned char* key,
    std::size_t key_size,
    const std::vector<std::uint8_t>& message,
    std::string_view customization,
    std::size_t output_bytes) {
    if (key_size < 16)
        throw std::runtime_error("stack series KMAC key is too short");
    if (output_bytes == 0 || output_bytes > MAX_DERIVED_BYTES)
        throw std::runtime_error("stack series derived length outside limit");

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
    if (!mac)
        throw std::runtime_error("OpenSSL KMAC-256 unavailable for stack schedule");
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
        EVP_MAC_init(ctx, key, key_size, params) == 1 &&
        EVP_MAC_update(ctx, message.data(), message.size()) == 1 &&
        EVP_MAC_final(ctx, out.data(), &written, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);
    if (!ok || written != output_bytes)
        throw std::runtime_error("OpenSSL KMACXOF256 stack derivation failed");
    return out;
}

void validate_stack_context(const SeriesFirstStackContext& c) {
    if (c.protocol_id != "v0id-series-first-stack-v1")
        throw std::runtime_error("unsupported series-first stack protocol");
    if (all_zero(c.session_id.data(), c.session_id.size()))
        throw std::runtime_error("series-first stack requires non-zero session id");
    if (c.job_id.empty())
        throw std::runtime_error("series-first stack requires job id");
    if (c.machine_protocol.empty() || c.fhe_parameter_set.empty())
        throw std::runtime_error("series-first stack requires compute profile");
    if (all_zero(c.semantic_binding.data(), c.semantic_binding.size()))
        throw std::runtime_error("series-first stack requires semantic binding");
    if (all_zero(c.generator_binding.data(), c.generator_binding.size()))
        throw std::runtime_error("series-first stack requires generator binding");
}

StackSeriesKey derive_stack_series(
    const unsigned char* root,
    std::size_t root_size,
    const StackContextHash512& context_hash,
    StackPurpose purpose,
    std::string_view privacy_domain) {
    const char* purpose_text = stack_purpose_name(purpose);

    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-STACK-PURPOSE-SERIES-v1");
    append_string(message, privacy_domain);
    append_string(message, purpose_text);
    append_blob(message, context_hash.data(), context_hash.size());

    const auto material = kmacxof256(
        root, root_size, message, "V0ID stack purpose series v1",
        StackSeriesKey{}.size());
    StackSeriesKey out{};
    std::copy(material.begin(), material.end(), out.begin());
    return out;
}

} // namespace

StackContextHash512 hash_series_first_stack_context(
    const SeriesFirstStackContext& context) {
    validate_stack_context(context);

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-SERIES-FIRST-STACK-CONTEXT-v1");
    append_string(canonical, context.protocol_id);
    append_blob(canonical, context.session_id.data(), context.session_id.size());
    append_string(canonical, context.job_id);
    append_u64(canonical, context.epoch);
    append_string(canonical, context.machine_protocol);
    append_string(canonical, context.fhe_parameter_set);
    append_blob(canonical, context.semantic_binding.data(),
                context.semantic_binding.size());
    append_blob(canonical, context.generator_binding.data(),
                context.generator_binding.size());
    append_blob(canonical, context.kex_transcript_binding.data(),
                context.kex_transcript_binding.size());
    append_blob(canonical, context.shared_modules_binding.data(),
                context.shared_modules_binding.size());
    append_blob(canonical, context.outer_channel_binding.data(),
                context.outer_channel_binding.size());
    return sha3_512(canonical);
}

const char* stack_purpose_name(StackPurpose purpose) {
    switch (purpose) {
        case StackPurpose::machine_layout: return "machine-layout";
        case StackPurpose::polymorphism: return "polymorphism";
        case StackPurpose::quine_challenge: return "quine-challenge";
        case StackPurpose::strategy_plugin: return "strategy-plugin";
        case StackPurpose::execution_integrity: return "execution-integrity";
        case StackPurpose::application_auth: return "application-auth";
        case StackPurpose::job_receipt: return "job-receipt";
    }
    throw std::runtime_error("unknown series-first stack purpose");
}

StackSeriesKey derive_private_stack_series(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const StackContextHash512& context_hash,
    StackPurpose purpose) {
    return derive_stack_series(
        issuer_private_root.data(), issuer_private_root.size(), context_hash,
        purpose, "issuer-private");
}

StackSeriesKey derive_shared_stack_series(
    const SharedSeriesRoot& post_kem_shared_root,
    const StackContextHash512& context_hash,
    StackPurpose purpose) {
    return derive_stack_series(
        post_kem_shared_root.data(), post_kem_shared_root.size(), context_hash,
        purpose, "post-kem-shared");
}

std::vector<std::uint8_t> expand_stack_algorithm_later(
    const StackSeriesKey& purpose_series,
    const std::string& algorithm_id,
    std::uint64_t algorithm_version,
    const std::vector<std::uint8_t>& algorithm_context,
    std::size_t output_bytes) {
    if (algorithm_id.empty() || algorithm_version == 0)
        throw std::runtime_error("algorithm-later adapter requires id/version");

    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-STACK-ALGORITHM-LATER-v1");
    append_string(message, algorithm_id);
    append_u64(message, algorithm_version);
    append_blob(message, algorithm_context.data(), algorithm_context.size());

    return kmacxof256(
        purpose_series.data(), purpose_series.size(), message,
        "V0ID stack algorithm-later adapter v1", output_bytes);
}

} // namespace v0id::crypto
