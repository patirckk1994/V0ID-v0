#include "series_first_schedule.hpp"
#include "series_first_stack.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

bool has_ml_kem_768() {
    ERR_clear_error();
    CtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "ML-KEM-768", nullptr),
               EVP_PKEY_CTX_free);
    const bool ok = static_cast<bool>(ctx);
    ERR_clear_error();
    return ok;
}

std::vector<std::uint8_t> raw_public(EVP_PKEY* key) {
    std::size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &len) != 1 || len == 0)
        throw std::runtime_error("ML-KEM-768 public key size query failed");
    std::vector<std::uint8_t> out(len);
    if (EVP_PKEY_get_raw_public_key(key, out.data(), &len) != 1)
        throw std::runtime_error("ML-KEM-768 public key export failed");
    out.resize(len);
    return out;
}

struct Encapsulation {
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> secret;
};

Encapsulation encapsulate(const std::vector<std::uint8_t>& public_bytes) {
    KeyPtr public_key(
        EVP_PKEY_new_raw_public_key_ex(
            nullptr, "ML-KEM-768", nullptr,
            public_bytes.data(), public_bytes.size()),
        EVP_PKEY_free);
    if (!public_key)
        throw std::runtime_error("ML-KEM-768 public-only import failed");

    CtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, public_key.get(), nullptr),
               EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0)
        throw std::runtime_error("ML-KEM-768 encapsulation init failed");

    std::size_t ct_len = 0;
    std::size_t secret_len = 0;
    if (EVP_PKEY_encapsulate(
            ctx.get(), nullptr, &ct_len, nullptr, &secret_len) <= 0 ||
        ct_len == 0 || secret_len == 0)
        throw std::runtime_error("ML-KEM-768 encapsulation size query failed");

    Encapsulation out;
    out.ciphertext.resize(ct_len);
    out.secret.resize(secret_len);
    if (EVP_PKEY_encapsulate(
            ctx.get(), out.ciphertext.data(), &ct_len,
            out.secret.data(), &secret_len) <= 0)
        throw std::runtime_error("ML-KEM-768 encapsulation failed");
    out.ciphertext.resize(ct_len);
    out.secret.resize(secret_len);
    return out;
}

std::vector<std::uint8_t> decapsulate(
    EVP_PKEY* private_key,
    const std::vector<std::uint8_t>& ciphertext) {
    CtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, private_key, nullptr),
               EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0)
        throw std::runtime_error("ML-KEM-768 decapsulation init failed");

    std::size_t secret_len = 0;
    if (EVP_PKEY_decapsulate(
            ctx.get(), nullptr, &secret_len,
            ciphertext.data(), ciphertext.size()) <= 0 || secret_len == 0)
        throw std::runtime_error("ML-KEM-768 decapsulation size query failed");

    std::vector<std::uint8_t> secret(secret_len);
    if (EVP_PKEY_decapsulate(
            ctx.get(), secret.data(), &secret_len,
            ciphertext.data(), ciphertext.size()) <= 0)
        throw std::runtime_error("ML-KEM-768 decapsulation failed");
    secret.resize(secret_len);
    return secret;
}

v0id::crypto::SeriesFirstKexTranscript transcript(
    const std::vector<std::uint8_t>& public_key,
    const std::vector<std::uint8_t>& ciphertext) {
    v0id::crypto::SeriesFirstKexTranscript t;
    t.kem_id = "ML-KEM-768";
    t.kem_version = 1;
    t.machine_protocol = "v0id-remote-machine-v3";
    t.fhe_parameter_set = "STD128Q";
    for (std::size_t i = 0; i < t.session_id.size(); ++i)
        t.session_id[i] = static_cast<std::uint8_t>(0x21u + i);
    t.initiator_peer_id = "CLIENT";
    t.responder_peer_id = "EVAL";
    t.kem_public_material = public_key;
    t.kem_ciphertext = ciphertext;
    return t;
}

v0id::crypto::SeriesFirstStackContext stack_context(
    const v0id::crypto::TranscriptHash512& transcript_hash) {
    v0id::crypto::SeriesFirstStackContext c;
    for (std::size_t i = 0; i < c.session_id.size(); ++i)
        c.session_id[i] = static_cast<std::uint8_t>(0x21u + i);
    c.job_id = "mlkem-stack-composition";
    c.epoch = 7;
    c.machine_protocol = "v0id-remote-machine-v3";
    c.fhe_parameter_set = "STD128Q";
    c.kex_transcript_binding = transcript_hash;
    for (std::size_t i = 0; i < c.semantic_binding.size(); ++i) {
        c.semantic_binding[i] = static_cast<std::uint8_t>((i * 5 + 1) & 0xffu);
        c.generator_binding[i] = static_cast<std::uint8_t>((i * 9 + 3) & 0xffu);
    }
    return c;
}

} // namespace

int main() try {
    if (!has_ml_kem_768()) {
        std::cout << "SKIP: OpenSSL provider has no ML-KEM-768; "
                     "series-first ML-KEM runtime gate not executed.\n";
        return 0;
    }

    KeyPtr private_key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768"),
                       EVP_PKEY_free);
    if (!private_key)
        throw std::runtime_error("OpenSSL ML-KEM-768 key generation failed");

    const auto public_key = raw_public(private_key.get());
    const auto encapsulated = encapsulate(public_key);
    const auto responder_secret = decapsulate(
        private_key.get(), encapsulated.ciphertext);

    int passed = 0;
    int failed = 0;
    auto check = [&](bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    };

    check(encapsulated.secret == responder_secret,
          "OpenSSL ML-KEM-768 encapsulation/decapsulation secrets match");

    const auto t = transcript(public_key, encapsulated.ciphertext);
    const auto th = v0id::crypto::hash_series_first_kex_transcript(t);
    const auto initiator_root = v0id::crypto::derive_shared_series_root(
        encapsulated.secret, th);
    const auto responder_root = v0id::crypto::derive_shared_series_root(
        responder_secret, th);
    check(initiator_root == responder_root,
          "both KEM peers derive the same post-KEM shared series root");

    const auto sc = stack_context(th);
    const auto sh = v0id::crypto::hash_series_first_stack_context(sc);
    const auto initiator_auth_series = v0id::crypto::derive_shared_stack_series(
        initiator_root, sh, v0id::crypto::StackPurpose::application_auth);
    const auto responder_auth_series = v0id::crypto::derive_shared_stack_series(
        responder_root, sh, v0id::crypto::StackPurpose::application_auth);
    check(initiator_auth_series == responder_auth_series,
          "both peers derive the same application-auth purpose series");

    const std::vector<std::uint8_t> algorithm_context{0x52,0x4d,0x4a,0x33};
    const auto initiator_key = v0id::crypto::expand_stack_algorithm_later(
        initiator_auth_series, "KMAC256-APPLICATION-AUTH", 1,
        algorithm_context, 32);
    const auto responder_key = v0id::crypto::expand_stack_algorithm_later(
        responder_auth_series, "KMAC256-APPLICATION-AUTH", 1,
        algorithm_context, 32);
    check(initiator_key == responder_key,
          "algorithm-later application material agrees after real ML-KEM");

    auto changed_t = t;
    changed_t.fhe_parameter_set = "STD128";
    const auto changed_th = v0id::crypto::hash_series_first_kex_transcript(changed_t);
    check(v0id::crypto::derive_shared_series_root(
              encapsulated.secret, changed_th) != initiator_root,
          "post-KEM series root changes on FHE-profile downgrade transcript");

    auto wrong_secret = responder_secret;
    wrong_secret[0] ^= 1u;
    check(v0id::crypto::derive_shared_series_root(wrong_secret, th) != initiator_root,
          "wrong KEM secret cannot reproduce the shared series root");

    std::cout << "\nV0ID ML-KEM series-first composition tests: "
              << passed << " passed, " << failed << " failed\n"
              << "NOTE: ML-KEM supplies shared-secret hardness. The series schedule is "
                 "a transcript-bound application KDF layer, not peer authentication or TLS.\n";
    return failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID ML-KEM series-first composition fatal error: "
              << e.what() << '\n';
    return 1;
}
