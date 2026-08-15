#include "integrity_program.hpp"

#include "stack_integrity_bridge.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace v0id::integrity {
namespace {

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
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
        throw std::runtime_error("EVP_MD_CTX_new failed for SHA3-512");
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
        throw std::runtime_error("OpenSSL SHA3-512 integrity digest failed");
    return out;
}

v0id::core::Program fixed_shape_identity_program(std::size_t states) {
    if (states == 0)
        throw std::runtime_error("integrity public state count must be positive");

    v0id::core::Program out;
    out.states = states;
    out.rules.reserve(states * 2);
    for (std::size_t state = 0; state < states; ++state) {
        out.rules.push_back({state, 0, state, 0, 0});
        out.rules.push_back({state, 1, state, 1, 0});
    }
    out.validate();
    return out;
}

void validate_hash_profile(const IntegrityHashProfile& profile) {
    if (profile.algorithm_id.empty() || profile.algorithm_version == 0 ||
        profile.digest_bytes == 0 || profile.digest_bytes > 4096)
        throw std::runtime_error("invalid integrity hash profile");
}

void validate_artifact(const IntegrityProgramArtifact& artifact) {
    artifact.program.validate();
    if (artifact.initial_state >= artifact.program.states)
        throw std::runtime_error("integrity program initial state out of range");
    if (artifact.rounds == 0)
        throw std::runtime_error("integrity program must execute at least one round");
    if (artifact.private_manifest.size() > 1024 * 1024)
        throw std::runtime_error("integrity private manifest exceeds local limit");
}

} // namespace

IntegrityHashProfile Sha3_512IntegrityHashBackend::profile() const {
    return {"sha3-512", 1, 64};
}

std::vector<std::uint8_t> Sha3_512IntegrityHashBackend::digest(
    const std::vector<std::uint8_t>& canonical_subject) const {
    return sha3_512(canonical_subject);
}

PrivateLocalIntegrityProgramHook::PrivateLocalIntegrityProgramHook(
    std::string local_id,
    std::uint64_t local_version,
    IntegrityHashProfile supported_hash,
    std::vector<std::uint8_t> module_bytes,
    Runner runner)
    : local_id_(std::move(local_id)),
      local_version_(local_version),
      supported_hash_(std::move(supported_hash)),
      module_bytes_(std::move(module_bytes)),
      runner_(std::move(runner)) {

    validate_hash_profile(supported_hash_);
    if (local_id_.empty() || local_id_.size() > 256 || local_version_ == 0)
        throw std::runtime_error("private integrity hook requires local id/version");
    if (module_bytes_.empty() || module_bytes_.size() > 1024 * 1024)
        throw std::runtime_error("private integrity module bytes outside local limit");
    if (!runner_)
        throw std::runtime_error("private integrity hook requires a local runner");
}

std::string PrivateLocalIntegrityProgramHook::local_id() const {
    return local_id_;
}

std::uint64_t PrivateLocalIntegrityProgramHook::local_version() const {
    return local_version_;
}

IntegrityHashProfile PrivateLocalIntegrityProgramHook::supported_hash() const {
    return supported_hash_;
}

std::vector<std::uint8_t> PrivateLocalIntegrityProgramHook::private_binding() const {
    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-PRIVATE-INTEGRITY-HOOK-v1");
    append_string(canonical, local_id_);
    append_u64(canonical, local_version_);
    append_u64(canonical, static_cast<std::uint64_t>(module_bytes_.size()));
    canonical.insert(canonical.end(), module_bytes_.begin(), module_bytes_.end());
    return sha3_512(canonical);
}

IntegrityProgramArtifact PrivateLocalIntegrityProgramHook::build(
    const IntegrityProgramBuildRequest& request) const {
    if (!(request.hash_profile == supported_hash_))
        throw std::runtime_error("private integrity hook/hash profile mismatch");
    if (request.canonical_subject_bits == 0 || request.digest_bits == 0 ||
        request.private_algorithm_material.empty())
        throw std::runtime_error("private integrity hook received incomplete build request");

    auto artifact = runner_(request, module_bytes_);
    validate_artifact(artifact);
    return artifact;
}

CombinedIntegrityExecutable build_combined_integrity_executable(
    const v0id::core::Program& semantic_program,
    std::size_t semantic_initial_state,
    std::size_t semantic_rounds,
    std::size_t public_state_count,
    std::size_t integrity_candidate_count,
    const v0id::crypto::StackSeriesKey& execution_integrity_series,
    const v0id::polymorph::MorphSeed& whole_machine_morph_seed,
    CanonicalSelfImageContext self_image_context,
    const IntegrityHashBackend& hash_backend,
    const IntegrityProgramHook& program_hook) {

    semantic_program.validate();
    if (semantic_initial_state >= semantic_program.states || semantic_rounds == 0)
        throw std::runtime_error("invalid semantic program/rounds for integrity build");
    if (public_state_count == 0 || integrity_candidate_count == 0)
        throw std::runtime_error("invalid public shape for integrity build");

    const auto hash_profile = hash_backend.profile();
    validate_hash_profile(hash_profile);
    if (!(program_hook.supported_hash() == hash_profile))
        throw std::runtime_error("runtime integrity hook does not implement selected hash profile");
    if (self_image_context.digest_slot_bytes < hash_profile.digest_bytes)
        throw std::runtime_error("canonical digest slot is smaller than selected hash output");

    // CanonicalSelfImageV1 uses fixed-width fields and a fixed public program
    // shape. Therefore its bit length is known before the private hook chooses
    // concrete integrity states. Use a harmless fixed-shape program only to size
    // the hook input; its contents are not the eventual hash subject.
    auto shape_context = self_image_context;
    shape_context.initial_state = 0;
    shape_context.semantic_rounds = semantic_rounds;
    shape_context.integrity_rounds = 1;
    shape_context.total_execution_rounds = semantic_rounds + 1;
    const auto shape_program = fixed_shape_identity_program(public_state_count);
    const auto canonical_subject_bits_hint =
        canonical_self_image_bits_v1(shape_program, shape_context).size();

    const auto private_binding = program_hook.private_binding();
    auto algorithm_material =
        v0id::crypto::expand_execution_integrity_algorithm_later(
            execution_integrity_series,
            hash_profile.algorithm_id,
            hash_profile.algorithm_version,
            private_binding,
            canonical_subject_bits_hint,
            hash_profile.digest_bytes,
            64);

    IntegrityProgramBuildRequest request;
    request.hash_profile = hash_profile;
    request.canonical_subject_bits = canonical_subject_bits_hint;
    request.digest_bits = hash_profile.digest_bytes * 8;
    request.private_algorithm_material = algorithm_material;

    auto integrity = program_hook.build(request);
    validate_artifact(integrity);

    auto combined = v0id::core::compose_bounded_with_integrity(
        semantic_program,
        semantic_initial_state,
        semantic_rounds,
        integrity.program,
        integrity.initial_state,
        integrity.rounds);

    if (combined.program.states > public_state_count)
        throw std::runtime_error(
            "combined useful+integrity program exceeds fixed public state count");

    auto morphed = v0id::polymorph::ProgramMorpher::morph(
        combined.program,
        combined.initial_state,
        public_state_count,
        whole_machine_morph_seed,
        integrity_candidate_count);

    std::vector<std::size_t> morphed_integrity_states;
    morphed_integrity_states.reserve(integrity.program.states);
    for (std::size_t q = 0; q < integrity.program.states; ++q) {
        const auto base_state = combined.integrity_state_offset + q;
        morphed_integrity_states.push_back(
            morphed.manifest.base_to_morphed.at(base_state));
    }
    std::sort(morphed_integrity_states.begin(), morphed_integrity_states.end());

    self_image_context.initial_state = morphed.initial_state;
    self_image_context.semantic_rounds = semantic_rounds;
    self_image_context.integrity_rounds = integrity.rounds;
    self_image_context.total_execution_rounds = combined.total_execution_rounds;

    auto canonical_subject = canonical_self_image_v1_masked(
        morphed.program, morphed_integrity_states, self_image_context);
    auto canonical_subject_bits = canonical_self_image_bits_v1_masked(
        morphed.program, morphed_integrity_states, self_image_context);

    if (canonical_subject_bits.size() != canonical_subject_bits_hint)
        throw std::runtime_error(
            "canonical self-image bit length changed after integrity synthesis");

    auto expected_digest = hash_backend.digest(canonical_subject);
    if (expected_digest.size() != hash_profile.digest_bytes)
        throw std::runtime_error("integrity hash backend returned wrong digest size");

    CombinedIntegrityExecutable out;
    out.combined = std::move(combined);
    out.morphed = std::move(morphed);
    out.morphed_integrity_states = std::move(morphed_integrity_states);
    out.canonical_subject = std::move(canonical_subject);
    out.canonical_subject_bits = std::move(canonical_subject_bits);
    out.expected_digest = std::move(expected_digest);
    out.private_algorithm_material = std::move(algorithm_material);
    out.total_execution_rounds = out.combined.total_execution_rounds;
    return out;
}

} // namespace v0id::integrity
