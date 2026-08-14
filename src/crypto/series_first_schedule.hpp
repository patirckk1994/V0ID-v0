#pragma once

#include "series_generator.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::crypto {

using TranscriptHash512 = std::array<std::uint8_t, 64>;
using SharedSeriesRoot = std::array<unsigned char, 32>;

// Canonical public handshake fields that must be bound before a KEM shared
// secret is turned into reusable session material. Authentication of peer_id
// values is a separate protocol question; this structure prevents accidental
// omission/downgrade of fields from the key schedule itself.
struct SeriesFirstKexTranscript {
    std::string protocol_id{"v0id-series-first-kex-v1"};
    std::string kem_id;                  // e.g. ML-KEM-768
    std::uint64_t kem_version{1};
    std::string machine_protocol;
    std::string fhe_parameter_set;
    std::array<std::uint8_t, 32> session_id{};
    std::string initiator_peer_id;
    std::string responder_peer_id;
    std::vector<std::uint8_t> kem_public_material;
    std::vector<std::uint8_t> kem_ciphertext;
};

TranscriptHash512 hash_series_first_kex_transcript(
    const SeriesFirstKexTranscript& transcript);

// Post-KEM series-first schedule. The KEM supplies the hardness and a shared
// secret; KMACXOF256 turns that secret plus the complete transcript into a
// generic shared series root. This does NOT invent a new KEM.
SharedSeriesRoot derive_shared_series_root(
    const std::vector<std::uint8_t>& kem_shared_secret,
    const TranscriptHash512& transcript_hash);

// Bind an issuer-only private root to a particular authenticated/negotiated
// session and job. This value, rather than SharedSeriesRoot, should drive private
// polymorphism when the evaluator is one of the KEM peers.
v0id::polymorph::SeriesSeed derive_private_job_series_root(
    const v0id::polymorph::SeriesSeed& issuer_private_root,
    const TranscriptHash512& transcript_hash,
    const std::string& job_id,
    std::uint64_t epoch);

// "Algorithm later": derive labeled bytes only after the series root exists.
// Every downstream algorithm gets a distinct label/context, so transport keys,
// audit material and polymorphism cannot accidentally reuse one byte stream.
std::vector<std::uint8_t> expand_series_labeled(
    const SharedSeriesRoot& root,
    const std::string& label,
    const std::vector<std::uint8_t>& context,
    std::size_t output_bytes);

std::vector<std::uint8_t> expand_private_series_labeled(
    const v0id::polymorph::SeriesSeed& root,
    const std::string& label,
    const std::vector<std::uint8_t>& context,
    std::size_t output_bytes);

} // namespace v0id::crypto
