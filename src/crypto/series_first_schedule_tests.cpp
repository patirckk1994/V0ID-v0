#include "series_first_schedule.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::crypto::SeriesFirstKexTranscript;
using v0id::crypto::SharedSeriesRoot;
using v0id::crypto::TranscriptHash512;
using v0id::polymorph::SeriesSeed;

struct Runner {
    int passed{};
    int failed{};
    void check(bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    }
};

SeriesFirstKexTranscript transcript() {
    SeriesFirstKexTranscript t;
    t.kem_id = "ML-KEM-768";
    t.kem_version = 1;
    t.machine_protocol = "v0id-remote-machine-v3";
    t.fhe_parameter_set = "STD128Q";
    for (std::size_t i = 0; i < t.session_id.size(); ++i)
        t.session_id[i] = static_cast<std::uint8_t>(i + 1);
    t.initiator_peer_id = "CLIENT";
    t.responder_peer_id = "EVAL";
    t.kem_public_material.resize(1184);
    t.kem_ciphertext.resize(1088);
    for (std::size_t i = 0; i < t.kem_public_material.size(); ++i)
        t.kem_public_material[i] = static_cast<std::uint8_t>((i * 13 + 7) & 0xffu);
    for (std::size_t i = 0; i < t.kem_ciphertext.size(); ++i)
        t.kem_ciphertext[i] = static_cast<std::uint8_t>((i * 29 + 3) & 0xffu);
    return t;
}

std::vector<std::uint8_t> kem_secret(std::uint8_t bias = 0) {
    std::vector<std::uint8_t> secret(32);
    for (std::size_t i = 0; i < secret.size(); ++i)
        secret[i] = static_cast<std::uint8_t>(0xa0u + i + bias);
    return secret;
}

SeriesSeed issuer_root() {
    SeriesSeed root{};
    for (std::size_t i = 0; i < root.size(); ++i)
        root[i] = static_cast<unsigned char>(0x31u + i);
    return root;
}

} // namespace

int main() try {
    Runner r;
    const auto base = transcript();
    const auto h = v0id::crypto::hash_series_first_kex_transcript(base);
    const auto h2 = v0id::crypto::hash_series_first_kex_transcript(base);
    r.check(h == h2, "KEX transcript encoding is deterministic");

    auto changed = base;
    changed.kem_id = "ML-KEM-1024";
    r.check(v0id::crypto::hash_series_first_kex_transcript(changed) != h,
            "KEM algorithm substitution changes transcript hash");

    changed = base;
    changed.fhe_parameter_set = "STD128";
    r.check(v0id::crypto::hash_series_first_kex_transcript(changed) != h,
            "FHE parameter downgrade changes transcript hash");

    changed = base;
    std::swap(changed.initiator_peer_id, changed.responder_peer_id);
    r.check(v0id::crypto::hash_series_first_kex_transcript(changed) != h,
            "peer-role reflection changes transcript hash");

    changed = base;
    changed.session_id[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_kex_transcript(changed) != h,
            "session substitution changes transcript hash");

    changed = base;
    changed.kem_ciphertext[0] ^= 1u;
    r.check(v0id::crypto::hash_series_first_kex_transcript(changed) != h,
            "KEM ciphertext substitution changes transcript hash");

    const auto shared = v0id::crypto::derive_shared_series_root(kem_secret(), h);
    const auto shared_again = v0id::crypto::derive_shared_series_root(kem_secret(), h);
    r.check(shared == shared_again,
            "post-KEM shared series root is deterministic for one transcript");

    r.check(v0id::crypto::derive_shared_series_root(kem_secret(1), h) != shared,
            "different KEM secret changes shared series root");

    auto changed_h = h;
    changed_h[0] ^= 1u;
    r.check(v0id::crypto::derive_shared_series_root(kem_secret(), changed_h) != shared,
            "different transcript changes shared series root");

    const std::vector<std::uint8_t> context{1,2,3,4};
    const auto transport = v0id::crypto::expand_series_labeled(
        shared, "transport-key", context, 32);
    const auto auth = v0id::crypto::expand_series_labeled(
        shared, "auth-key", context, 32);
    r.check(transport != auth,
            "algorithm-later labels separate downstream shared material");

    const auto private_job = v0id::crypto::derive_private_job_series_root(
        issuer_root(), h, "job-A", 9);
    const auto private_job2 = v0id::crypto::derive_private_job_series_root(
        issuer_root(), h, "job-B", 9);
    r.check(private_job != private_job2,
            "issuer-only polymorphism root is job-separated");

    const auto private_morph = v0id::crypto::expand_private_series_labeled(
        private_job, "polymorphism", context, 32);
    const auto private_audit = v0id::crypto::expand_private_series_labeled(
        private_job, "audit", context, 32);
    r.check(private_morph != private_audit,
            "private polymorphism and audit streams are domain-separated");

    r.check(!std::equal(shared.begin(), shared.end(), private_job.begin()),
            "shared KEM root is not reused as issuer-private morph root");

    std::cout << "\nV0ID series-first KEX schedule tests: "
              << r.passed << " passed, " << r.failed << " failed\n"
              << "NOTE: these tests validate composition/key scheduling only; "
                 "they do not replace ML-KEM security or peer authentication.\n";
    return r.failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID series-first KEX test fatal error: " << e.what() << '\n';
    return 1;
}
