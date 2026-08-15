#include "peer_transport.hpp"
#include "fhe_codec.hpp"
#include "remote_machine.hpp"
#include "remote_machine_codec.hpp"
#include "program.hpp"
#include "program_morpher.hpp"
#include "series_generator.hpp"
#include "series_first_stack.hpp"
#include "stack_polymorph_bridge.hpp"
#include "quine_hash.hpp"

#ifdef V0ID_HAVE_WASM_POLYMORPH
#include "wasm_series_generator.hpp"
#endif

#include "binfhecontext.h"
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace lbcrypto;
using namespace v0id::net;

namespace {

constexpr int REMOTE_MACHINE_TIMEOUT_MS = 3600000; // one hour
constexpr std::size_t PUBLIC_STATES = 4;
constexpr std::size_t TAPE_CELLS = 8;
constexpr std::size_t FIXED_ROUNDS = 4;
constexpr std::size_t MAX_CACHED_EVALUATOR_SESSIONS = 4;
constexpr std::uint64_t DEMO_EPOCH = 1;

using v0id::core::Program;
using v0id::crypto::SeriesFirstStackContext;
using v0id::fhe::ByteBlob;
using v0id::fhe::CryptoProfileId;
using v0id::fhe::EvaluatorSessionBundle;
using v0id::fhe::EvaluatorSessionId;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteEncryptedMachine;
using v0id::fhe::RemoteMachineBundle;
using v0id::fhe::RemoteMachineResult;
using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::MorphedProgram;
using v0id::polymorph::PolymorphicSeriesGenerator;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::SeriesProfile;

struct CachedEvaluatorSession {
    std::string primitive_id;
    std::string parameter_set;
    BinFHEContext cc;
    RingGSWACCKey refresh_key;
    LWESwitchingKey switching_key;
};

void usage(const char* argv0) {
    std::cerr
        << "usage:\n"
        << "  " << argv0 << " server <peer-id> <bind-endpoint> [job-count]\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint>\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint> --series kmac\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint> --series-wasm <file.wasm>\n\n"
        << "The client installs expensive BinFHE evaluator material once, then\n"
        << "sends an RMJ4 encrypted-machine job that references that cached session.\n"
        << "KMACXOF256 is the default private series-first generator. When built\n"
        << "with WAMR, --series-wasm runs a zero-import polymorphism module locally\n"
        << "before ProgramMorpher. The Wasm, private series/root, quine commitment,\n"
        << "MorphManifest and LWE secret key never leave the client.\n";
}

std::vector<std::uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot open local polymorphism Wasm file: " + path);
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

std::unique_ptr<PolymorphicSeriesGenerator> make_series_generator(
    const std::vector<std::uint8_t>& wasm_bytes) {
    if (wasm_bytes.empty())
        return std::make_unique<KmacSeriesGenerator>(64);
#ifdef V0ID_HAVE_WASM_POLYMORPH
    SeriesProfile profile{"v0id-local-wasm-v1", 1, {}};
    return std::make_unique<v0id::polymorph::WasmSeriesGenerator>(
        wasm_bytes, std::move(profile));
#else
    (void)wasm_bytes;
    throw std::runtime_error("--series-wasm requires a build with V0ID_ENABLE_MATHVM=ON");
#endif
}

PublicMachineShape demo_shape() {
    return PublicMachineShape{PUBLIC_STATES, TAPE_CELLS, FIXED_ROUNDS, 0};
}

CryptoProfileId demo_profile(const SeriesProfile& series) {
    return CryptoProfileId{
        "openfhe-binfhe",
        "STD128Q",
        "v0id-remote-machine-v4",
        "quine-sha3-512-client-v1",
        series.generator_id,
        series.version,
    };
}

void require_supported_execution_profile(const CryptoProfileId& profile) {
    if (profile.primitive_id != "openfhe-binfhe")
        throw std::runtime_error("unsupported FHE primitive profile");
    if (profile.parameter_set != "STD128Q")
        throw std::runtime_error("unsupported BinFHE quantum-security parameter profile");
    if (profile.machine_protocol != "v0id-remote-machine-v4")
        throw std::runtime_error("unsupported remote machine protocol profile");
    if (profile.integrity_profile != "quine-sha3-512-client-v1")
        throw std::runtime_error("unsupported integrity profile");
}

void require_supported_session_profile(const EvaluatorSessionBundle& session) {
    if (session.primitive_id != "openfhe-binfhe")
        throw std::runtime_error("unsupported evaluator-session FHE primitive");
    if (session.parameter_set != "STD128Q")
        throw std::runtime_error("unsupported evaluator-session quantum parameter set");
}

bool same_shape(const PublicMachineShape& a, const PublicMachineShape& b) {
    return a.states == b.states && a.tape_cells == b.tape_cells &&
           a.rounds == b.rounds && a.integrity_slots == b.integrity_slots;
}

EvaluatorSessionId random_evaluator_session_id() {
    EvaluatorSessionId id{};
    do {
        if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1)
            throw std::runtime_error("RAND_bytes failed while generating evaluator session id");
    } while (std::all_of(id.begin(), id.end(), [](std::uint8_t b) { return b == 0; }));
    return id;
}

std::string session_key(const EvaluatorSessionId& id) {
    return std::string(reinterpret_cast<const char*>(id.data()), id.size());
}

std::string session_id_hex(const EvaluatorSessionId& id) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : id)
        out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

ByteBlob session_id_payload(const EvaluatorSessionId& id) {
    return ByteBlob(id.begin(), id.end());
}

void require_session_ready_reply(const Envelope& reply,
                                 const EvaluatorSessionId& expected) {
    if (reply.type == MessageType::error)
        throw std::runtime_error("evaluator session install failed: " + text(reply.payload));
    if (reply.type != MessageType::evaluator_session_ready)
        throw std::runtime_error("unexpected evaluator-session reply type");
    if (reply.payload != session_id_payload(expected))
        throw std::runtime_error("evaluator-session acknowledgement id mismatch");
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
        if (r.move < 0 && head > 0) --head;
        else if (r.move > 0 && head + 1 < tape.size()) ++head;
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
    std::cout << '\n';
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
    std::unordered_map<std::string, std::unique_ptr<CachedEvaluatorSession>> sessions;

    std::cout << "V0ID remote-machine evaluator " << peer_id
              << " listening on " << endpoint << '\n'
              << "evaluator cache slots : " << MAX_CACHED_EVALUATOR_SESSIONS << '\n';

    int job_requests = 0;
    while (job_requests < count) {
        const auto request = server.receive();
        const bool counts_as_job = request.type == MessageType::execute_job;
        Envelope reply;
        reply.peer_id = peer_id;
        reply.job_id = request.job_id;
        reply.epoch = request.epoch;

        try {
            if (request.type == MessageType::install_evaluator_session) {
                const auto setup = v0id::fhe::unpack_evaluator_session_bundle(request.payload);
                require_supported_session_profile(setup);
                const auto key = session_key(setup.session_id);
                if (sessions.contains(key))
                    throw std::runtime_error("evaluator session id already installed");
                if (sessions.size() >= MAX_CACHED_EVALUATOR_SESSIONS)
                    throw std::runtime_error("evaluator session cache is full");

                auto cached = std::make_unique<CachedEvaluatorSession>();
                cached->primitive_id = setup.primitive_id;
                cached->parameter_set = setup.parameter_set;
                v0id::fhe::deserialize_binary(setup.context, cached->cc);
                v0id::fhe::deserialize_binary(setup.refresh_key, cached->refresh_key);
                v0id::fhe::deserialize_binary(setup.switching_key, cached->switching_key);
                cached->cc.BTKeyLoad({cached->refresh_key, cached->switching_key});

                const auto short_id = session_id_hex(setup.session_id).substr(0, 16);
                sessions.emplace(key, std::move(cached));
                reply.type = MessageType::evaluator_session_ready;
                reply.payload = session_id_payload(setup.session_id);

                std::cout << "installed evaluator session=" << short_id
                          << " setup-bytes=" << request.payload.size()
                          << " cached-sessions=" << sessions.size() << '\n'
                          << "  primitive          : " << setup.primitive_id << '\n'
                          << "  parameter set      : " << setup.parameter_set << '\n'
                          << "  secret key received: NO\n";
            } else if (request.type == MessageType::execute_job) {
                const auto bundle = v0id::fhe::unpack_remote_machine_bundle(request.payload);
                require_supported_execution_profile(bundle.profile);

                const auto it = sessions.find(session_key(bundle.session_id));
                if (it == sessions.end())
                    throw std::runtime_error("RMJ4 references unknown evaluator session");
                auto& cached = *it->second;
                if (bundle.profile.primitive_id != cached.primitive_id ||
                    bundle.profile.parameter_set != cached.parameter_set)
                    throw std::runtime_error("RMJ4 crypto profile does not match cached evaluator session");

                const auto& shape = bundle.shape;
                std::cout << "job=" << request.job_id
                          << " from=" << request.peer_id
                          << " session=" << session_id_hex(bundle.session_id).substr(0, 16)
                          << " job-bytes=" << request.payload.size()
                          << " states=" << shape.states
                          << " tape=" << shape.tape_cells
                          << " rounds=" << shape.rounds << '\n';
                std::cout << "crypto profile       : "
                          << bundle.profile.primitive_id << '/'
                          << bundle.profile.parameter_set << " | "
                          << bundle.profile.machine_protocol << " | "
                          << bundle.profile.integrity_profile << '\n'
                          << "series profile       : "
                          << bundle.profile.series_generator_id << "/v"
                          << bundle.profile.series_generator_version << '\n'
                          << "cached evaluator keys: YES\n"
                          << "private series recv  : NO\n"
                          << "quine digest received: NO\n"
                          << "manifest received    : NO\n"
                          << "secret key received  : NO\n";

                auto& cc = cached.cc;
                LWECiphertext encrypted_zero;
                v0id::fhe::deserialize_binary(bundle.encrypted_zero, encrypted_zero);
                auto program_bits = deserialize_ciphertexts(bundle.program_bits);
                auto state_bits = deserialize_ciphertexts(bundle.state_bits);
                auto head_bits = deserialize_ciphertexts(bundle.head_bits);
                auto tape_bits = deserialize_ciphertexts(bundle.tape_bits);

                RemoteEncryptedMachine machine(
                    cc, shape, std::move(program_bits), std::move(state_bits),
                    std::move(head_bits), std::move(tape_bits), std::move(encrypted_zero));

                for (std::uint64_t round = 0; round < shape.rounds; ++round) {
                    std::cout << "executing public round " << (round + 1)
                              << '/' << shape.rounds << "...\n" << std::flush;
                    machine.step();
                }

                RemoteMachineResult result;
                result.session_id = bundle.session_id;
                result.shape = shape;
                result.profile = bundle.profile;
                result.state_bits = serialize_ciphertexts(machine.state_bits());
                result.head_bits = serialize_ciphertexts(machine.head_bits());
                result.tape_bits = serialize_ciphertexts(machine.tape_bits());

                reply.type = MessageType::job_result;
                reply.payload = v0id::fhe::pack_remote_machine_result(result);
                std::cout << "remote encrypted machine complete; result bytes="
                          << reply.payload.size() << '\n';
            } else {
                throw std::runtime_error("expected INSTALL_EVALUATOR_SESSION or EXECUTE_JOB");
            }
        } catch (const std::exception& e) {
            reply.type = MessageType::error;
            reply.payload = bytes(e.what());
            std::cerr << "remote evaluator request failed: " << e.what() << '\n';
        }

        server.reply(reply);
        if (counts_as_job) ++job_requests;
    }
    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint,
               const std::string& wasm_path) {
    const Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
    const std::vector<int> input{1,0,1,1,0,0,0,0};
    const std::vector<int> expected{0,1,1,1,0,0,0,0};

    std::vector<std::uint8_t> series_input;
    series_input.reserve(input.size());
    for (const int bit : input)
        series_input.push_back(static_cast<std::uint8_t>(bit & 1));

    std::vector<std::uint8_t> wasm_bytes;
    if (!wasm_path.empty()) {
        wasm_bytes = read_binary_file(wasm_path);
        if (wasm_bytes.empty())
            throw std::runtime_error("local polymorphism Wasm file is empty");
    }

    auto series_generator = make_series_generator(wasm_bytes);
    const auto series_profile = series_generator->profile();
    const auto series_seed = v0id::polymorph::random_series_seed();
    const auto derived_series = series_generator->derive(series_input, series_seed, DEMO_EPOCH);

    const auto evaluator_session_id = random_evaluator_session_id();
    const std::string request_job_id = wasm_path.empty()
        ? "v0id-v047-pq-series-first-remote-increment"
        : "v0id-v047-pq-wasm-morphed-rmj4-remote-increment";

    const auto semantic_binding = v0id::integrity::semantic_job_hash512(
        increment, 0, 0, input, FIXED_ROUNDS);
    const auto generator_binding = v0id::integrity::generator_binding512(
        series_profile, wasm_bytes);

    SeriesFirstStackContext stack_context;
    stack_context.session_id = evaluator_session_id;
    stack_context.job_id = request_job_id;
    stack_context.epoch = DEMO_EPOCH;
    stack_context.machine_protocol = "v0id-remote-machine-v4";
    stack_context.fhe_parameter_set = "STD128Q";
    stack_context.semantic_binding = semantic_binding;
    stack_context.generator_binding = generator_binding;

    const auto job_bound_morph_seed = v0id::crypto::derive_program_morph_seed_from_stack(
        series_seed, stack_context, derived_series.series);
    auto morph = ProgramMorpher::morph(increment, 0, PUBLIC_STATES, job_bound_morph_seed);

    if (run_plaintext(morph.program, morph.initial_state, input, FIXED_ROUNDS) != expected)
        throw std::runtime_error("remote demo plaintext morph mismatch");

    std::cout << "input                : ";
    print_msb_first(input);
    std::cout << "series generator     : " << series_profile.generator_id
              << "/v" << series_profile.version << '\n'
              << "series source        : "
              << (wasm_path.empty() ? "OpenSSL KMACXOF256" : "local Wasm") << '\n';
    if (!wasm_path.empty())
        std::cout << "local Wasm file      : " << wasm_path << '\n';
    std::cout << "private series bytes : " << derived_series.series.size() << '\n'
              << "morph derivation     : StackPurpose::polymorphism -> program-morpher-v1\n"
              << "morph job-bound      : session + job + epoch + semantic + generator\n"
              << "public state count   : " << PUBLIC_STATES << '\n'
              << "public tape cells    : " << TAPE_CELLS << '\n'
              << "public round budget  : " << FIXED_ROUNDS << '\n';
    print_client_manifest(morph);

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128Q);
    auto sk = cc.KeyGen();
    std::cout << "BinFHE parameter set : STD128Q\n"
              << "generating OpenFHE bootstrapping keys...\n" << std::flush;
    cc.BTKeyGen(sk);

    EvaluatorSessionBundle setup;
    setup.session_id = evaluator_session_id;
    setup.primitive_id = "openfhe-binfhe";
    setup.parameter_set = "STD128Q";
    setup.context = v0id::fhe::serialize_binary(cc);
    setup.refresh_key = v0id::fhe::serialize_binary(cc.GetRefreshKey());
    setup.switching_key = v0id::fhe::serialize_binary(cc.GetSwitchKey());

    Envelope setup_request;
    setup_request.type = MessageType::install_evaluator_session;
    setup_request.peer_id = peer_id;
    setup_request.job_id = "v0id-v047-pq-evaluator-session";
    setup_request.epoch = DEMO_EPOCH;
    setup_request.payload = v0id::fhe::pack_evaluator_session_bundle(setup);

    std::cout << "evaluator session id : "
              << session_id_hex(evaluator_session_id).substr(0, 16) << "...\n"
              << "session setup bytes  : " << setup_request.payload.size() << '\n'
              << "  context bytes      : " << setup.context.size() << '\n'
              << "  refresh key bytes  : " << setup.refresh_key.size() << '\n'
              << "  switching key bytes: " << setup.switching_key.size() << '\n'
              << "installing evaluator material once...\n" << std::flush;

    PeerClient client(endpoint, REMOTE_MACHINE_TIMEOUT_MS);
    const auto setup_reply = client.round_trip(setup_request);
    require_session_ready_reply(setup_reply, evaluator_session_id);
    std::cout << "evaluator session    : READY / cached remotely\n";

    auto quine_context = v0id::integrity::QuineHashContext{};
    quine_context.shape = demo_shape();
    quine_context.profile = demo_profile(series_profile);
    quine_context.session_id = evaluator_session_id;
    quine_context.job_id = request_job_id;
    quine_context.epoch = DEMO_EPOCH;
    quine_context.initial_state = morph.initial_state;
    quine_context.initial_head = 0;
    quine_context.initial_tape = input;
    quine_context.semantic_binding = semantic_binding;
    quine_context.generator_binding = generator_binding;
    const auto audit_challenge = v0id::integrity::derive_audit_challenge256(
        series_seed, evaluator_session_id, request_job_id, DEMO_EPOCH);
    const auto quine_digest = v0id::integrity::quine_hash512(
        morph.program, quine_context, audit_challenge);

    std::cout << "client quine SHA3-512: "
              << v0id::integrity::hex_digest(quine_digest) << '\n'
              << "quine commitment sent: NO (issuer-private in current protocol)\n"
              << "audit challenge sent  : NO\n";

    const auto encrypted_program_bits = v0id::fhe::encrypt_remote_bits(
        cc, sk, v0id::fhe::canonical_remote_program_bits(morph.program));

    std::vector<int> initial_state(PUBLIC_STATES, 0);
    initial_state.at(morph.initial_state) = 1;
    const auto encrypted_state = v0id::fhe::encrypt_remote_bits(cc, sk, initial_state);

    std::vector<int> initial_head(TAPE_CELLS, 0);
    initial_head[0] = 1;
    const auto encrypted_head = v0id::fhe::encrypt_remote_bits(cc, sk, initial_head);
    const auto encrypted_tape = v0id::fhe::encrypt_remote_bits(cc, sk, input);

    RemoteMachineBundle bundle;
    bundle.session_id = evaluator_session_id;
    bundle.shape = demo_shape();
    bundle.profile = demo_profile(series_profile);
    bundle.encrypted_zero = v0id::fhe::serialize_binary(cc.Encrypt(sk, 0));
    bundle.program_bits = serialize_ciphertexts(encrypted_program_bits);
    bundle.state_bits = serialize_ciphertexts(encrypted_state);
    bundle.head_bits = serialize_ciphertexts(encrypted_head);
    bundle.tape_bits = serialize_ciphertexts(encrypted_tape);

    Envelope request;
    request.type = MessageType::execute_job;
    request.peer_id = peer_id;
    request.job_id = request_job_id;
    request.epoch = DEMO_EPOCH;
    request.payload = v0id::fhe::pack_remote_machine_bundle(bundle);

    std::cout << "RMJ4 per-job bytes    : " << request.payload.size() << '\n'
              << "cached setup resent  : NO\n"
              << "sending polymorph Wasm: NO\n"
              << "sending private series: NO\n"
              << "sending series root  : NO\n"
              << "sending quine digest : NO\n"
              << "sending MorphManifest: NO\n"
              << "sending secret key   : NO\n"
              << "waiting for remote fixed-path evaluation...\n" << std::flush;

    const auto reply = client.round_trip(request);
    if (reply.type == MessageType::error)
        throw std::runtime_error("remote evaluator error: " + text(reply.payload));
    if (reply.type != MessageType::job_result)
        throw std::runtime_error("unexpected remote-machine reply type");

    const auto result = v0id::fhe::unpack_remote_machine_result(reply.payload);
    if (result.session_id != evaluator_session_id)
        throw std::runtime_error("remote result evaluator session mismatch");
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

    const auto quine_after = v0id::integrity::quine_hash512(
        morph.program, quine_context, audit_challenge);
    if (quine_after != quine_digest)
        throw std::runtime_error("client quine commitment changed across remote job");

    std::cout << "client quine recheck : MATCH\n"
              << "OK: PQ-profile series-derived morphed encrypted machine executed remotely\n"
                 "    + OpenFHE STD128Q selected for the remote BinFHE profile\n"
                 "    + private series root generated from OpenSSL private DRBG\n"
                 "    + public evaluator session id generated before morph derivation\n"
                 "    + full job context bound before ProgramMorpher algorithm-later stage\n"
                 "    + local generator series remains private and influences morph material\n"
                 "    + SHA3-512 quine binds semantic job + exact generator + morph + profile\n"
                 "    + expensive BinFHE evaluator material installed once\n"
                 "    + RMJ4 carries only encrypted machine state; ToyFingerprint baggage removed\n"
                 "    + encrypted program/state/head/tape crossed the network\n"
                 "    + fixed public round budget executed by server\n"
                 "    + NO CLAIM yet that client-side SHA3 quine proves honest execution\n"
                 "    + client decrypted 00001110\n";
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
        if (argc > 5) {
            usage(argv[0]);
            return 2;
        }
        const int count = argc >= 5 ? std::stoi(argv[4]) : 1;
        if (count <= 0)
            throw std::runtime_error("job-count must be positive");
        return run_server(peer_id, endpoint, count);
    }

    if (mode == "client") {
        std::string wasm_path;
        if (argc == 4) {
        } else if (argc == 6 && std::string(argv[4]) == "--series" &&
                   std::string(argv[5]) == "kmac") {
        } else if (argc == 6 && std::string(argv[4]) == "--series-wasm") {
            wasm_path = argv[5];
            if (wasm_path.empty())
                throw std::runtime_error("--series-wasm path must not be empty");
        } else {
            usage(argv[0]);
            return 2;
        }
        return run_client(peer_id, endpoint, wasm_path);
    }

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "V0ID remote-machine error: " << e.what() << '\n';
    return 1;
}
