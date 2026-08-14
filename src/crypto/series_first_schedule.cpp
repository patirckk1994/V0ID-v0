#include "series_first_schedule.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
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

std::vector<std::uint8_t> sha3_512(const std::vector<std::uint8_t>& bytes) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-512 unavailable");
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    std::vector<std::uint8_t> out(64);
    unsigned int written = 0;
    const bool ok =
        EVP_DigestInit_ex2(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &written) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (!ok || written != out.size())
        throw std::runtime_error("OpenSSL SHA3-512 transcript hash failed");
    return out;
}

std::vector<std::uint8_t> kmacxof256(
    const std::uint8_t* key,
    std::size_t key_size,
    const std::vector<std::uint8_t>& message,
    std::string_view customization,
    std::size_t output_bytes) {
    if (key_size < 16)
        throw std::runtime_error("series-first KMAC root key is too short");
    if (output_bytes == 0 || output_bytes > MAX_DERIVED_BYTES)
        throw std::runtime_error("series-first derived length outside limit");

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
        EVP_MAC_init(ctx, key, key_size, params) == 1 &&
        EVP_MAC_update(ctx, message.data(), message.size()) == 1 &&
        EVP_MAC_final(ctx, out.data(), &written, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);
    if (!ok || written != output_bytes)
        throw std::runtime_error("OpenSSL KMACXOF256 series-first derivation failed");
    return out;
}

bool session_id_all_zero(const std::array<std::uint8_t, 32>& id) {
    return std::all_of(id.begin(), id.end(),
                       [](std::uint8_t b) { return b == 0; });
}

void validate_transcript(const SeriesFirstKexTranscript& t) {
    if (t.protocol_id != "v0id-series-first-kex-v1")
        throw std::runtime_error("unsupported series-first KEX transcript protocol");
    if (t.kem_id.empty() || t.kem_version == 0)
        throw std::runtime_error("series-first KEX transcript missing KEM profile");
    if (t.machine_protocol.empty() || t.fhe_parameter_set.empty())
        throw std::runtime_error("series-first KEX transcript missing compute profile");
    if (session_id_all_zero(t.session_id))
        throw std::runtime_error("series-first KEX transcript has zero session id");
    if (t.initiator_peer_id.empty() || t.responder_peer_id.empty())
        throw std::runtime_error("series-first KEX transcript missing peer roles");
    if (t.kem_public_material.empty() || t.kem_ciphertext.empty())
        throw std::runtime_error("series-first KEX transcript missing KEM material");
}

} // namespace

TranscriptHash512 hash_series_first_kex_transcript(
    const SeriesFirstKexTranscript& transcript) {
    validate_transcript(transcript);

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-SERIES-FIRST-KEX-TRANSCRIPT-v1");
    append_string(canonical, transcript.protocol_id);
    append_string(canonical, transcript.kem_id);
    append_u64(canonical, transcript.kem_version);
    append_string(canonical, transcript.machine_protocol);
    append_string(canonical, transcript.fhe_parameter_set);
    append_blob(canonical, transcript.session_id.data(), transcript.session_id.size());
    append_string(canonical, transcript.initiator_peer_id);
    append_string(canonical, transcript.responder_peer_id);
    append_blob(canonical, transcript.kem_public_material.data(),
                transcript.kem_public_material.size());
    append_blob(canonical, transcript.kem_ciphertext.data(),
                transcript.kem_ciphertext.size());

    const auto digest = sha3_512(canonical);
    TranscriptHash512 out{};
    std::copy(digest.begin(), digest.end(), out.begin());
    return out;
}

SharedSeriesRoot derive_shared_series_root(
    const std::vector<std::uint8_t>& kem_shared_secret,
    const TranscriptHash512& transcript_hash) {
    if (kem_shared_secret.size() < 16)
        throw std::runtime_error("KEM shared secret too short for series-first root");

    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-SHARED-SERIES-ROOT-v1");
    append_blob(message, transcript_hash.data(), transcript_hash.size());
    const auto material = kmacxof256(
        kem_shared_secret.data(), kem_shared_secret.size(), message,
        "V0ID shared post-KEM series root v1", SharedSeriesRoot{}.size());

    SharedSeriesRoot out{};
    std::copy(material.begin(), material.end(), out.begin());
    return out;
}

v0id::polymorph::SeriesSeed derive_private_job_series_root(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const TranscriptHash512& transcript_hash,
    const std::string& job_id,
    std::uint64_t epoch) {
    if (job_id.empty())
        throw std::runtime_error("private job series root requires a job id");

    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-PRIVATE-JOB-SERIES-ROOT-v1");
    append_blob(message, transcript_hash.data(), transcript_hash.size());
    append_string(message, job_id);
    append_u64(message, epoch);
    const auto material = kmacxof256(
        issuer_private_root.data(), issuer_private_root.size(), message,
        "V0ID issuer-only job series root v1",
        v0id::polymorph::SeriesSeed{}.size());

    v0id::polymorph::SeriesSeed out{};
    std::copy(material.begin(), material.end(), out.begin());
    return out;
}

std::vector<std::uint8_t> expand_series_labeled(
    const SharedSeriesRoot& root,
    const std::string& label,
    const std::vector<std::uint8_t>& context,
    std::size_t output_bytes) {
    if (label.empty())
        throw std::runtime_error("shared series expansion label must not be empty");
    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-SHARED-SERIES-LABEL-v1");
    append_string(message, label);
    append_blob(message, context.data(), context.size());
    return kmacxof256(root.data(), root.size(), message,
                      "V0ID shared series algorithm-later v1", output_bytes);
}

std::vector<std::uint8_t> expand_private_series_labeled(
    const v0id::polymorph::SeriesSeed& root,
    const std::string& label,
    const std::vector<std::uint8_t>& context,
    std::size_t output_bytes) {
    if (label.empty())
        throw std::runtime_error("private series expansion label must not be empty");
    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-PRIVATE-SERIES-LABEL-v1");
    append_string(message, label);
    append_blob(message, context.data(), context.size());
    return kmacxof256(root.data(), root.size(), message,
                      "V0ID private series algorithm-later v1", output_bytes);
}

} // namespace v0id::crypto
