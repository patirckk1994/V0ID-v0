#include "quine_hash.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace v0id::integrity {
namespace {

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

void append_program(std::vector<std::uint8_t>& out,
                    const v0id::core::Program& program) {
    program.validate();
    append_u64(out, static_cast<std::uint64_t>(program.states));
    append_u64(out, static_cast<std::uint64_t>(program.states * 2));

    // Canonicalize by semantic index rather than vector storage order.
    for (std::size_t state = 0; state < program.states; ++state) {
        for (int read = 0; read <= 1; ++read) {
            const auto& rule = program.rule(state, read);
            append_u64(out, static_cast<std::uint64_t>(state));
            out.push_back(static_cast<std::uint8_t>(read));
            append_u64(out, static_cast<std::uint64_t>(rule.next_state));
            out.push_back(static_cast<std::uint8_t>(rule.write));
            out.push_back(static_cast<std::uint8_t>(rule.move + 1)); // -1,0,+1 -> 0,1,2
        }
    }
}

void append_tape(std::vector<std::uint8_t>& out,
                 const std::vector<int>& tape) {
    if (tape.empty())
        throw std::runtime_error("quine hash tape must not be empty");
    append_u64(out, static_cast<std::uint64_t>(tape.size()));
    for (const int bit : tape) {
        if (bit != 0 && bit != 1)
            throw std::runtime_error("quine hash tape must be binary");
        out.push_back(static_cast<std::uint8_t>(bit));
    }
}

void append_profile(std::vector<std::uint8_t>& out,
                    const v0id::fhe::CryptoProfileId& profile) {
    if (profile.primitive_id.empty() || profile.parameter_set.empty() ||
        profile.machine_protocol.empty() || profile.integrity_profile.empty() ||
        profile.series_generator_id.empty() || profile.series_generator_version == 0)
        throw std::runtime_error("quine hash requires a complete crypto profile");

    append_string(out, profile.primitive_id);
    append_string(out, profile.parameter_set);
    append_string(out, profile.machine_protocol);
    append_string(out, profile.integrity_profile);
    append_string(out, profile.series_generator_id);
    append_u64(out, profile.series_generator_version);
}

std::vector<std::uint8_t> kmac256(
    const v0id::polymorph::SeriesSeed& key,
    const std::vector<std::uint8_t>& message,
    std::string_view customization,
    std::size_t output_bytes) {
    if (output_bytes == 0)
        throw std::runtime_error("KMAC output length must be positive");

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
    if (!mac)
        throw std::runtime_error("OpenSSL KMAC-256 unavailable");

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (!ctx)
        throw std::runtime_error("EVP_MAC_CTX_new failed");

    auto* custom_ptr = const_cast<char*>(customization.data());
    OSSL_PARAM init_params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM, custom_ptr, customization.size()),
        OSSL_PARAM_construct_end(),
    };

    std::vector<std::uint8_t> out(output_bytes);
    std::size_t written = 0;
    std::size_t requested = output_bytes;
    OSSL_PARAM final_params[] = {
        OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &requested),
        OSSL_PARAM_construct_end(),
    };

    const bool ok =
        EVP_MAC_init(ctx, key.data(), key.size(), init_params) == 1 &&
        EVP_MAC_update(ctx, message.data(), message.size()) == 1 &&
        EVP_MAC_CTX_set_params(ctx, final_params) == 1 &&
        EVP_MAC_final(ctx, out.data(), &written, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);

    if (!ok || written != output_bytes)
        throw std::runtime_error("OpenSSL KMAC-256 derivation failed");
    return out;
}

bool all_zero(const v0id::fhe::EvaluatorSessionId& id) {
    return std::all_of(id.begin(), id.end(),
                       [](std::uint8_t b) { return b == 0; });
}

} // namespace

QuineDigest512 sha3_512_bytes(const std::vector<std::uint8_t>& bytes) {
    EVP_MD* md = EVP_MD_fetch(nullptr, "SHA3-512", nullptr);
    if (!md)
        throw std::runtime_error("OpenSSL SHA3-512 unavailable");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_MD_free(md);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    QuineDigest512 out{};
    unsigned int written = 0;
    const bool ok =
        EVP_DigestInit_ex2(ctx, md, nullptr) == 1 &&
        EVP_DigestUpdate(ctx, bytes.data(), bytes.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, out.data(), &written) == 1;

    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (!ok || written != out.size())
        throw std::runtime_error("OpenSSL SHA3-512 failed");
    return out;
}

AuditChallenge256 derive_audit_challenge256(
    const v0id::polymorph::SeriesSeed& private_root,
    const v0id::fhe::EvaluatorSessionId& session_id,
    const std::string& job_id,
    std::uint64_t epoch) {
    if (all_zero(session_id))
        throw std::runtime_error("audit challenge requires a nonzero session id");
    if (job_id.empty())
        throw std::runtime_error("audit challenge requires a job id");

    std::vector<std::uint8_t> message;
    append_string(message, "V0ID-AUDIT-CHALLENGE-v1");
    append_blob(message, session_id.data(), session_id.size());
    append_string(message, job_id);
    append_u64(message, epoch);

    const auto material = kmac256(
        private_root, message, "V0ID audit challenge v1", AuditChallenge256{}.size());
    AuditChallenge256 out{};
    std::copy(material.begin(), material.end(), out.begin());
    return out;
}

QuineDigest512 semantic_job_hash512(const v0id::core::Program& base_program,
                                    std::size_t initial_state,
                                    std::size_t initial_head,
                                    const std::vector<int>& initial_tape,
                                    std::uint64_t rounds) {
    base_program.validate();
    if (initial_state >= base_program.states)
        throw std::runtime_error("semantic binding initial state out of range");
    if (initial_tape.empty() || initial_head >= initial_tape.size())
        throw std::runtime_error("semantic binding initial tape/head invalid");

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-SEMANTIC-JOB-v1");
    append_u64(canonical, rounds);
    append_u64(canonical, static_cast<std::uint64_t>(initial_state));
    append_u64(canonical, static_cast<std::uint64_t>(initial_head));
    append_tape(canonical, initial_tape);
    append_program(canonical, base_program);
    return sha3_512_bytes(canonical);
}

QuineDigest512 generator_binding512(
    const v0id::polymorph::SeriesProfile& profile,
    const std::vector<std::uint8_t>& implementation_bytes) {
    if (profile.generator_id.empty() || profile.version == 0)
        throw std::runtime_error("generator binding requires a versioned profile");

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-GENERATOR-BINDING-v1");
    append_string(canonical, profile.generator_id);
    append_u64(canonical, profile.version);
    append_blob(canonical, profile.parameters.data(), profile.parameters.size());
    append_blob(canonical, implementation_bytes.data(), implementation_bytes.size());
    return sha3_512_bytes(canonical);
}

QuineDigest512 quine_hash512(const v0id::core::Program& morphed_program,
                             const QuineHashContext& context,
                             const AuditChallenge256& challenge) {
    morphed_program.validate();
    if (context.job_id.empty())
        throw std::runtime_error("quine hash job id must not be empty");
    if (context.initial_state >= morphed_program.states)
        throw std::runtime_error("quine hash initial state out of range");
    if (context.initial_tape.empty() ||
        context.initial_head >= context.initial_tape.size())
        throw std::runtime_error("quine hash initial tape/head invalid");
    if (context.shape.states != morphed_program.states)
        throw std::runtime_error("quine hash state shape does not match program");
    if (context.shape.tape_cells != context.initial_tape.size())
        throw std::runtime_error("quine hash tape shape does not match input");
    if (all_zero(context.session_id))
        throw std::runtime_error("quine hash requires a nonzero session id");

    std::vector<std::uint8_t> canonical;
    append_string(canonical, "V0ID-QUINE-HASH-v1");
    append_u64(canonical, 1); // encoding version
    append_profile(canonical, context.profile);

    append_u64(canonical, context.shape.states);
    append_u64(canonical, context.shape.tape_cells);
    append_u64(canonical, context.shape.rounds);
    append_u64(canonical, context.shape.integrity_slots);

    append_blob(canonical, context.session_id.data(), context.session_id.size());
    append_string(canonical, context.job_id);
    append_u64(canonical, context.epoch);
    append_u64(canonical, static_cast<std::uint64_t>(context.initial_state));
    append_u64(canonical, static_cast<std::uint64_t>(context.initial_head));
    append_tape(canonical, context.initial_tape);

    append_blob(canonical, context.semantic_binding.data(), context.semantic_binding.size());
    append_blob(canonical, context.generator_binding.data(), context.generator_binding.size());
    append_blob(canonical, challenge.data(), challenge.size());
    append_program(canonical, morphed_program);

    // Canonical quine/self-reference rule. The digest field exists in the
    // committed object but is represented as exactly 64 zero bytes while the
    // digest is calculated, avoiding a cryptographic fixed-point assumption.
    std::array<std::uint8_t, 64> zero_digest_slot{};
    append_string(canonical, "V0ID-QUINE-DIGEST-SLOT-v1");
    append_blob(canonical, zero_digest_slot.data(), zero_digest_slot.size());

    return sha3_512_bytes(canonical);
}

std::string hex_digest(const QuineDigest512& digest) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : digest)
        out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

std::string hex_challenge(const AuditChallenge256& challenge) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : challenge)
        out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

} // namespace v0id::integrity
