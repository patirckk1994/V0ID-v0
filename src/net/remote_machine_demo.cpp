#include "peer_transport.hpp"
#include "fhe_codec.hpp"
#include "remote_machine.hpp"
#include "remote_machine_codec.hpp"
#include "program.hpp"
#include "program_morpher.hpp"
#include "series_generator.hpp"
#include "toy_fingerprint.hpp"

#include "binfhecontext.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lbcrypto;
using namespace v0id::net;

namespace {

constexpr int REMOTE_MACHINE_TIMEOUT_MS = 3600000; // one hour
constexpr std::size_t PUBLIC_STATES = 4;
constexpr std::size_t TAPE_CELLS = 8;
constexpr std::size_t FIXED_ROUNDS = 4;
constexpr std::size_t INTEGRITY_SLOTS = 4;
constexpr std::uint64_t DEMO_EPOCH = 1;

using v0id::core::Program;
using v0id::fhe::ByteBlob;
using v0id::fhe::CryptoProfileId;
using v0id::fhe::DigestBlob32;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteEncryptedMachine;
using v0id::fhe::RemoteMachineBundle;
using v0id::fhe::RemoteMachineResult;
using v0id::integrity::EncryptedDigest32;
using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::MorphedProgram;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::SeriesProfile;

void usage(const char* argv0) {
    std::cerr
        << "usage:\n"
        << "  " << argv0 << " server <peer-id> <bind-endpoint> [count]\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint>\n\n"
        << "client privately derives a polymorphic series, uses it to morph and\n"
        << "encrypt an 8-cell increment machine, then sends the encrypted machine.\n"
        << "The server executes four fixed BinFHE rounds and returns encrypted\n"
        << "machine state plus four masked integrity candidates. The private series,\n"
        << "series seed, MorphManifest and LWE secret key never leave the client.\n";
}

PublicMachineShape demo_shape() {
    return PublicMachineShape{
        PUBLIC_STATES,
        TAPE_CELLS,
        FIXED_ROUNDS,
        INTEGRITY_SLOTS,
    };
}

CryptoProfileId demo_profile(const SeriesProfile& series) {
    return CryptoProfileId{
        "openfhe-binfhe",
        "STD128",
        "v0id-remote-machine-v2",
        "toy-fingerprint32-v1",
        series.generator_id,
        series.version,
    };
}

void require_supported_execution_profile(const CryptoProfileId& profile) {
    if (profile.primitive_id != "openfhe-binfhe")
        throw std::runtime_error("unsupported FHE primitive profile");
    if (profile.parameter_set != "STD128")
        throw std::runtime_error("unsupported BinFHE parameter profile");
    if (profile.machine_protocol != "v0id-remote-machine-v2")
        throw std::runtime_error("unsupported remote machine protocol profile");
    if (profile.integrity_profile != "toy-fingerprint32-v1")
        throw std::runtime_error("unsupported integrity profile");

    // The series itself is a client-side morph input, so the evaluator does not
    // need its implementation. Its bounded id/version is retained as public
    // provenance for future capability negotiation and correlation experiments.
}

bool same_shape(const PublicMachineShape& a, const PublicMachineShape& b) {
    return a.states == b.states &&
           a.tape_cells == b.tape_cells &&
           a.rounds == b.rounds &&
           a.integrity_slots == b.integrity_slots;
}

std::vector<int> run_plaintext(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t steps) {
    program.validate();
    if (input.empty() || initial_state >= program.states)
        throw std::runtime_error("invalid plaintext remote-machine input");

    auto tape = input;
    std::size_t state = initial_state;
    std::size_t head = 0;
    for (std::size_t s = 0; s < steps; ++s) {
        const auto& r = program.rule(state, tape.at(head));
        tape[head] = r.write;
        state = r.next_state;
        if (r.move < 0 && head > 0)
            --head;
        else if (r.move > 0 && head + 1 < tape.size())
            ++head;
    }
    return tape;
}

void print_msb_first(const std::vector<int>& bits) {
    for (auto it = bits.rbegin(); it != bits.rend(); ++it)
        std::cout << *it;
    std::cout << '\n';
}

void print_client_manifest(const MorphedProgram& morph) {
    std::cout << "client state map     : ";
    for (std::size_t q = 0; q < morph.manifest.base_to_morphed.size(); ++q) {
        if (q) std::cout << ", ";
        std::cout << q << "->" << morph.manifest.base_to_morphed[q];
    }
    std::cout << " | dummy=";
    for (std::size_t i = 0; i < morph.manifest.dummy_states.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << morph.manifest.dummy_states[i];
    }
    std::cout << " | private integrity slot="
              << morph.manifest.integrity_output_slot << '\n';
}

std::vector<ByteBlob> serialize_ciphertexts(
    const std::vector<LWECiphertext>& ciphertexts) {
    std::vector<ByteBlob> out;
    out.reserve(ciphertexts.size());
    for (const auto& ct : ciphertexts)
        out.push_back(v0id::fhe::serialize_binary(ct));
    return out;
}

std::vector<LWECiphertext> deserialize_ciphertexts(
    const std::vector<ByteBlob>& blobs) {
    std::vector<LWECiphertext> out(blobs.size());
    for (std::size_t i = 0; i < blobs.size(); ++i)
        v0id::fhe::deserialize_binary(blobs[i], out[i]);
    return out;
}

DigestBlob32 serialize_digest(const EncryptedDigest32& digest) {
    DigestBlob32 out;
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = v0id::fhe::serialize_binary(digest[i]);
    return out;
}

EncryptedDigest32 deserialize_digest(const DigestBlob32& blobs) {
    EncryptedDigest32 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        v0id::fhe::deserialize_binary(blobs[i], out[i]);
    return out;
}

std::vector<int> decrypt_bits(BinFHEContext& cc,
                              const LWEPrivateKey& sk,
                              const std::vector<LWECiphertext>& ciphertexts) {
    std::vector<int> out(ciphertexts.size());
    for (std::size_t i = 0; i < ciphertexts.size(); ++i) {
        LWEPlaintext p{};
        cc.Decrypt(sk, ciphertexts[i], &p);
        out[i] = static_cast<int>(p & 1);
    }
    return out;
}

int run_server(const std::string& peer_id,
               const std::string& endpoint,
               int count) {
    PeerServer server(endpoint, REMOTE_MACHINE_TIMEOUT_MS);
    std::cout << "V0ID remote-machine evaluator " << peer_id
              << " listening on " << endpoint << '\n';

    for (int request_index = 0; request_index < count; ++request_index) {
        const auto request = server.receive();
        Envelope reply;
        reply.peer_id = peer_id;
        reply.job_id = request.job_id;
        reply.epoch = request.epoch;

        try {
            if (request.type != MessageType::execute_job)
                throw std::runtime_error("expected EXECUTE_JOB");

            const auto bundle = v0id::fhe::unpack_remote_machine_bundle(request.payload);
            require_supported_execution_profile(bundle.profile);
            const auto& shape = bundle.shape;

            std::cout << "job=" << request.job_id
                      << " from=" << request.peer_id
                      << " states=" << shape.states
                      << " tape=" << shape.tape_cells
                      << " rounds=" << shape.rounds
                      << " integrity-slots=" << shape.integrity_slots << '\n';
            std::cout << "crypto profile       : "
                      << bundle.profile.primitive_id << '/'
                      << bundle.profile.parameter_set << " | "
                      << bundle.profile.machine_protocol << " | "
                      << bundle.profile.integrity_profile << '\n';
            std::cout << "series profile       : "
                      << bundle.profile.series_generator_id << "/v"
                      << bundle.profile.series_generator_version << '\n';
            std::cout << "private series recv  : NO\n"
                      << "series seed received : NO\n"
                      << "manifest received    : NO\n"
                      << "secret key received  : NO\n";

            BinFHEContext cc;
            RingGSWACCKey refresh_key;
            LWESwitchingKey switching_key;
            LWECiphertext encrypted_zero;

            v0id::fhe::deserialize_binary(bundle.context, cc);
            v0id::fhe::deserialize_binary(bundle.refresh_key, refresh_key);
            v0id::fhe::deserialize_binary(bundle.switching_key, switching_key);
            v0id::fhe::deserialize_binary(bundle.encrypted_zero, encrypted_zero);
            cc.BTKeyLoad({refresh_key, switching_key});

            auto program_bits = deserialize_ciphertexts(bundle.program_bits);
            auto state_bits = deserialize_ciphertexts(bundle.state_bits);
            auto head_bits = deserialize_ciphertexts(bundle.head_bits);
            auto tape_bits = deserialize_ciphertexts(bundle.tape_bits);

            // Preserve the received initial tape for the job-image fingerprint;
            // the machine evaluator replaces its own tape vector as it executes.
            const auto fingerprint_input = tape_bits;
            const auto nonce_bits = deserialize_digest(bundle.nonce_bits);
            const auto fingerprint_initial_state =
                deserialize_digest(bundle.fingerprint_initial_state_bits);

            std::vector<EncryptedDigest32> mask_bits;
            mask_bits.reserve(bundle.integrity_mask_bits.size());
            for (const auto& mask : bundle.integrity_mask_bits)
                mask_bits.push_back(deserialize_digest(mask));

            std::cout << "computing encrypted self-fingerprint...\n";
            const auto digest = v0id::integrity::toy_fingerprint32_fhe(
                cc, program_bits, fingerprint_input, nonce_bits,
                fingerprint_initial_state);

            std::vector<EncryptedDigest32> candidates;
            candidates.reserve(mask_bits.size());
            for (const auto& mask : mask_bits)
                candidates.push_back(v0id::integrity::mask_digest_fhe(cc, digest, mask));

            RemoteEncryptedMachine machine(
                cc, shape, std::move(program_bits), std::move(state_bits),
                std::move(head_bits), std::move(tape_bits),
                std::move(encrypted_zero));

            for (std::uint64_t round = 0; round < shape.rounds; ++round) {
                std::cout << "executing public round " << (round + 1)
                          << '/' << shape.rounds << "...\n" << std::flush;
                machine.step();
            }

            RemoteMachineResult result;
            result.shape = shape;
            result.profile = bundle.profile;
            result.state_bits = serialize_ciphertexts(machine.state_bits());
            result.head_bits = serialize_ciphertexts(machine.head_bits());
            result.tape_bits = serialize_ciphertexts(machine.tape_bits());
            result.integrity_candidates.reserve(candidates.size());
            for (const auto& candidate : candidates)
                result.integrity_candidates.push_back(serialize_digest(candidate));

            reply.type = MessageType::job_result;
            reply.payload = v0id::fhe::pack_remote_machine_result(result);

            std::cout << "remote encrypted machine complete; result bytes="
                      << reply.payload.size() << '\n';
        } catch (const std::exception& e) {
            reply.type = MessageType::error;
            reply.payload = bytes(e.what());
            std::cerr << "remote evaluator job failed: " << e.what() << '\n';
        }

        server.reply(reply);
    }

    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint) {
    const Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};

    const std::vector<int> input{1,0,1,1,0,0,0,0}; // 13, LSB first
    const std::vector<int> expected{0,1,1,1,0,0,0,0}; // 14

    std::vector<std::uint8_t> series_input;
    series_input.reserve(input.size());
    for (const int bit : input)
        series_input.push_back(static_cast<std::uint8_t>(bit & 1));

    KmacSeriesGenerator series_generator(64);
    const auto series_profile = series_generator.profile();
    const auto series_seed = v0id::polymorph::random_series_seed();
    const auto derived_series =
        series_generator.derive(series_input, series_seed, DEMO_EPOCH);

    auto morph = ProgramMorpher::morph(
        increment, 0, PUBLIC_STATES, derived_series.morph_seed, INTEGRITY_SLOTS);

    if (run_plaintext(morph.program, morph.initial_state, input, FIXED_ROUNDS) != expected)
        throw std::runtime_error("remote demo plaintext morph mismatch");

    std::cout << "input                : ";
    print_msb_first(input);
    std::cout << "series generator     : " << series_profile.generator_id
              << "/v" << series_profile.version << '\n'
              << "private series bytes : " << derived_series.series.size() << '\n'
              << "public state count   : " << PUBLIC_STATES << '\n'
              << "public tape cells    : " << TAPE_CELLS << '\n'
              << "public round budget  : " << FIXED_ROUNDS << '\n'
              << "public integrity bank: " << INTEGRITY_SLOTS << '\n';
    print_client_manifest(morph);

    const auto expected_digest = v0id::integrity::toy_fingerprint32_plain(
        morph.program, input, morph.manifest.integrity_nonce);

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    std::cout << "generating OpenFHE bootstrapping keys...\n" << std::flush;
    cc.BTKeyGen(sk);

    const auto plain_program_bits = v0id::integrity::canonical_program_bits(morph.program);
    const auto encrypted_program_bits =
        v0id::integrity::encrypt_plain_bits(cc, sk, plain_program_bits);

    std::vector<int> initial_state(PUBLIC_STATES, 0);
    initial_state.at(morph.initial_state) = 1;
    const auto encrypted_state =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_state);

    std::vector<int> initial_head(TAPE_CELLS, 0);
    initial_head[0] = 1;
    const auto encrypted_head =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_head);
    const auto encrypted_tape =
        v0id::integrity::encrypt_plain_bits(cc, sk, input);

    const auto encrypted_nonce = v0id::integrity::encrypt_u32_bits(
        cc, sk, morph.manifest.integrity_nonce);
    const auto encrypted_fingerprint_initial_state =
        v0id::integrity::encrypt_u32_bits(
            cc, sk, v0id::integrity::TOY_FINGERPRINT_INITIAL_STATE);

    std::vector<EncryptedDigest32> encrypted_masks;
    encrypted_masks.reserve(morph.manifest.integrity_output_masks.size());
    for (const auto mask : morph.manifest.integrity_output_masks)
        encrypted_masks.push_back(v0id::integrity::encrypt_u32_bits(cc, sk, mask));

    RemoteMachineBundle bundle;
    bundle.shape = demo_shape();
    bundle.profile = demo_profile(series_profile);
    bundle.context = v0id::fhe::serialize_binary(cc);
    bundle.refresh_key = v0id::fhe::serialize_binary(cc.GetRefreshKey());
    bundle.switching_key = v0id::fhe::serialize_binary(cc.GetSwitchKey());
    bundle.encrypted_zero = v0id::fhe::serialize_binary(cc.Encrypt(sk, 0));
    bundle.program_bits = serialize_ciphertexts(encrypted_program_bits);
    bundle.state_bits = serialize_ciphertexts(encrypted_state);
    bundle.head_bits = serialize_ciphertexts(encrypted_head);
    bundle.tape_bits = serialize_ciphertexts(encrypted_tape);
    bundle.nonce_bits = serialize_digest(encrypted_nonce);
    bundle.fingerprint_initial_state_bits =
        serialize_digest(encrypted_fingerprint_initial_state);
    bundle.integrity_mask_bits.reserve(encrypted_masks.size());
    for (const auto& mask : encrypted_masks)
        bundle.integrity_mask_bits.push_back(serialize_digest(mask));

    Envelope request;
    request.type = MessageType::execute_job;
    request.peer_id = peer_id;
    request.job_id = "v0id-v041-series-first-remote-increment";
    request.epoch = DEMO_EPOCH;
    request.payload = v0id::fhe::pack_remote_machine_bundle(bundle);

    std::cout << "remote job bytes     : " << request.payload.size() << '\n'
              << "sending private series: NO\n"
              << "sending series seed  : NO\n"
              << "sending MorphManifest: NO\n"
              << "sending secret key   : NO\n"
              << "waiting for remote fixed-path evaluation...\n" << std::flush;

    PeerClient client(endpoint, REMOTE_MACHINE_TIMEOUT_MS);
    const auto reply = client.round_trip(request);
    if (reply.type == MessageType::error)
        throw std::runtime_error("remote evaluator error: " + text(reply.payload));
    if (reply.type != MessageType::job_result)
        throw std::runtime_error("unexpected remote-machine reply type");

    const auto result = v0id::fhe::unpack_remote_machine_result(reply.payload);
    if (!same_shape(result.shape, bundle.shape))
        throw std::runtime_error("remote result public shape mismatch");
    if (!(result.profile == bundle.profile))
        throw std::runtime_error("remote result crypto profile mismatch");

    const auto final_tape_ct = deserialize_ciphertexts(result.tape_bits);
    const auto final_tape = decrypt_bits(cc, sk, final_tape_ct);

    std::cout << "remote output        : ";
    print_msb_first(final_tape);
    if (final_tape != expected)
        throw std::runtime_error("remote encrypted machine result mismatch");

    const auto slot = morph.manifest.integrity_output_slot;
    if (slot >= result.integrity_candidates.size())
        throw std::runtime_error("private integrity slot outside returned candidate bank");

    const auto selected_candidate = deserialize_digest(result.integrity_candidates[slot]);
    const auto masked_digest = v0id::integrity::decrypt_u32_bits(cc, sk, selected_candidate);
    const auto recovered_digest =
        masked_digest ^ morph.manifest.integrity_output_masks[slot];

    std::cout << "remote self-check    : 0x" << std::hex << recovered_digest
              << std::dec << " (private client slot " << slot << ")\n";
    if (recovered_digest != expected_digest)
        throw std::runtime_error("remote encrypted self-fingerprint mismatch");

    std::cout << "OK: series-derived morphed encrypted machine executed remotely\n"
                 "    + private series derived before ProgramMorpher\n"
                 "    + public crypto/profile identifiers round-tripped\n"
                 "    + encrypted program/state/head/tape crossed the network\n"
                 "    + fixed public round budget executed by server\n"
                 "    + all integrity candidates returned\n"
                 "    + private series/seed remained client-side\n"
                 "    + MorphManifest remained client-side\n"
                 "    + secret key remained client-side\n"
                 "    + client decrypted 00001110 and verified private self-check\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) try {
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }

    const std::string mode = argv[1];
    const std::string peer_id = argv[2];
    const std::string endpoint = argv[3];

    if (mode == "server") {
        const int count = argc >= 5 ? std::stoi(argv[4]) : 1;
        if (count <= 0)
            throw std::runtime_error("count must be positive");
        return run_server(peer_id, endpoint, count);
    }

    if (mode == "client")
        return run_client(peer_id, endpoint);

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "V0ID remote-machine error: " << e.what() << '\n';
    return 1;
}
