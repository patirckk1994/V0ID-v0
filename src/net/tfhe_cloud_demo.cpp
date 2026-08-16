#include "boolean_program_image.hpp"
#include "curve_peer_transport.hpp"
#include "gpu_fhe_backend.hpp"
#include "peer_transport.hpp"
#include "tfhe_cloud_codec.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using v0id::fhe::TfheCudaServerSession;
using v0id::integrity::BooleanProgramImage;
using v0id::integrity::BooleanProgramInstruction;
using v0id::integrity::BooleanProgramOpcode;
using v0id::net::CurveAuthorizedClient;
using v0id::net::CurveKeyPair;
using v0id::net::CurvePeerClient;
using v0id::net::CurvePeerServer;
using v0id::net::Envelope;
using v0id::net::MessageType;
using v0id::net::MultipartEnvelope;
using v0id::net::TfheCloudAck;
using v0id::net::TfheCloudChunk;
using v0id::net::TfheCloudFinish;
using v0id::net::TfheCloudInstall;
using v0id::net::TfheCloudResult;
using v0id::net::TfheCloudSessionId;

constexpr int CLOUD_TIMEOUT_MS = 3600000;
constexpr std::size_t MAX_CACHED_TFHE_SESSIONS = 4;
constexpr auto TFHE_SESSION_TTL = std::chrono::minutes(30);
constexpr std::uint64_t DEMO_EPOCH = 1;

struct CachedTfheSession {
    std::string authenticated_user_id;
    std::string job_id;
    std::uint64_t epoch{};
    std::size_t expected_instruction_count{};
    std::size_t expected_output_word_count{};
    std::size_t completed_instruction_count{};
    std::chrono::steady_clock::time_point last_activity;
    std::unique_ptr<TfheCudaServerSession> evaluator;
};

void usage(const char* argv0) {
    std::cerr
        << "usage:\n"
        << "  " << argv0 << " keygen <output-prefix>\n"
        << "  " << argv0 << " server <server-peer-id> <bind-endpoint>"
           " <server-secret-file> <allowed-client-public-file>"
           " <allowed-client-peer-id> [finished-job-count]\n"
        << "  " << argv0 << " client <client-peer-id> <connect-endpoint>"
           " <client-public-file> <client-secret-file>"
           " <server-public-file> <expected-server-peer-id>\n\n"
        << "Example:\n"
        << "  " << argv0 << " keygen server\n"
        << "  " << argv0 << " keygen client-a\n"
        << "  " << argv0 << " server gpu-node tcp://*:7788"
           " server.secret client-a.public client-a 1\n"
        << "  " << argv0 << " client client-a tcp://127.0.0.1:7788"
           " client-a.public client-a.secret server.public gpu-node\n\n"
        << "TFHE cloud transport requires ZeroMQ CURVE. The server pins authorized\n"
        << "client public keys through an in-process ZAP allowlist; the client pins\n"
        << "the evaluator public key. Secret CURVE keys are read from files instead\n"
        << "of command-line arguments. The TFHE ClientKey remains client-local.\n";
}

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

const char* message_type_name(MessageType type) {
    switch (type) {
        case MessageType::install_tfhe_session:
            return "INSTALL_TFHE_SESSION";
        case MessageType::tfhe_session_ready:
            return "TFHE_SESSION_READY";
        case MessageType::tfhe_instruction_chunk:
            return "TFHE_INSTRUCTION_CHUNK";
        case MessageType::tfhe_chunk_ready:
            return "TFHE_CHUNK_READY";
        case MessageType::tfhe_job_finish:
            return "TFHE_JOB_FINISH";
        case MessageType::tfhe_job_result:
            return "TFHE_JOB_RESULT";
        case MessageType::error:
            return "ERROR";
        default:
            return "OTHER";
    }
}

const char* progress_stage_name(v0id::fhe::GpuFheProgressStage stage) {
    switch (stage) {
        case v0id::fhe::GpuFheProgressStage::KeyGeneration:
            return "key-generation";
        case v0id::fhe::GpuFheProgressStage::ClientEncryption:
            return "client-encryption";
        case v0id::fhe::GpuFheProgressStage::Execution:
            return "execution";
        case v0id::fhe::GpuFheProgressStage::OutputSelection:
            return "output-selection";
    }
    return "unknown";
}

long long elapsed_ms(std::chrono::steady_clock::time_point started) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - started)
        .count();
}

void write_all(int fd, const char* data, std::size_t size) {
    while (size != 0) {
        const auto n = ::write(fd, data, size);
        if (n < 0)
            throw std::runtime_error("failed writing CURVE key file");
        data += n;
        size -= static_cast<std::size_t>(n);
    }
}

void write_key_file_exclusive(const std::string& path,
                              const std::string& key,
                              mode_t mode) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0)
        throw std::runtime_error("refusing to overwrite CURVE key file: " + path);
    try {
        const std::string line = key + "\n";
        write_all(fd, line.data(), line.size());
        if (::close(fd) != 0)
            throw std::runtime_error("failed closing CURVE key file: " + path);
    } catch (...) {
        ::close(fd);
        ::unlink(path.c_str());
        throw;
    }
}

std::string read_key_file(const std::string& path) {
    std::ifstream in(path);
    if (!in)
        throw std::runtime_error("cannot open CURVE key file: " + path);
    std::string key;
    std::string extra;
    if (!(in >> key))
        throw std::runtime_error("CURVE key file is empty: " + path);
    if (in >> extra)
        throw std::runtime_error("CURVE key file contains extra tokens: " + path);
    if (key.size() != 40)
        throw std::runtime_error("CURVE key file must contain one 40-character Z85 key: " + path);
    return key;
}

CurveKeyPair load_keypair(const std::string& public_path,
                          const std::string& secret_path) {
    return CurveKeyPair{read_key_file(public_path), read_key_file(secret_path)};
}

int run_keygen(const std::string& prefix) {
    if (prefix.empty())
        throw std::runtime_error("key output prefix must not be empty");
    const auto keys = v0id::net::generate_curve_keypair();
    const auto public_path = prefix + ".public";
    const auto secret_path = prefix + ".secret";
    write_key_file_exclusive(public_path, keys.public_key_z85, 0644);
    try {
        write_key_file_exclusive(secret_path, keys.secret_key_z85, 0600);
    } catch (...) {
        ::unlink(public_path.c_str());
        throw;
    }
    std::cout << "generated CURVE keypair\n"
              << "  public: " << public_path << " (0644)\n"
              << "  secret: " << secret_path << " (0600)\n";
    return 0;
}

TfheCloudSessionId random_session_id() {
    TfheCloudSessionId id{};
    do {
        if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1)
            throw std::runtime_error("RAND_bytes failed while generating TFHE cloud session id");
    } while (!v0id::net::valid_tfhe_cloud_session_id(id));
    return id;
}

std::string session_key(const TfheCloudSessionId& id) {
    return std::string(reinterpret_cast<const char*>(id.data()), id.size());
}

Envelope base_envelope(const std::string& peer_id,
                       const std::string& job_id,
                       std::uint64_t epoch) {
    Envelope out;
    out.peer_id = peer_id;
    out.job_id = job_id;
    out.epoch = epoch;
    return out;
}

MultipartEnvelope error_reply(const std::string& server_peer_id,
                              const std::string& job_id,
                              std::uint64_t epoch,
                              const std::string& error) {
    Envelope out = base_envelope(server_peer_id, job_id, epoch);
    out.type = MessageType::error;
    out.payload = v0id::net::bytes(error);
    return MultipartEnvelope{std::move(out), {}, {}};
}

void require_server_reply_binding(const MultipartEnvelope& reply,
                                  const std::string& expected_server_peer_id,
                                  const std::string& job_id,
                                  std::uint64_t epoch) {
    if (reply.envelope.peer_id != expected_server_peer_id)
        throw std::runtime_error("TFHE cloud reply server peer-id mismatch");
    if (reply.envelope.job_id != job_id)
        throw std::runtime_error("TFHE cloud reply job binding mismatch");
    if (reply.envelope.epoch != epoch)
        throw std::runtime_error("TFHE cloud reply epoch binding mismatch");
}

void throw_if_error(const MultipartEnvelope& reply, const char* operation) {
    if (reply.envelope.type == MessageType::error)
        throw std::runtime_error(std::string(operation) + " failed: " +
                                 v0id::net::text(reply.envelope.payload));
}

void require_same_binding(const CachedTfheSession& session,
                          const std::string& authenticated_user_id,
                          const std::string& job_id,
                          std::uint64_t epoch) {
    if (session.authenticated_user_id != authenticated_user_id)
        throw std::runtime_error("TFHE cloud authenticated transport identity mismatch");
    if (session.job_id != job_id)
        throw std::runtime_error("TFHE cloud job binding mismatch");
    if (session.epoch != epoch)
        throw std::runtime_error("TFHE cloud epoch binding mismatch");
}

void expire_sessions(
    std::unordered_map<std::string, std::unique_ptr<CachedTfheSession>>& sessions) {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = sessions.begin(); it != sessions.end();) {
        if (now - it->second->last_activity > TFHE_SESSION_TTL) {
            std::cout << "[cloud] expiring stale TFHE session\n" << std::flush;
            it = sessions.erase(it);
        } else {
            ++it;
        }
    }
}

BooleanProgramImage smoke_image() {
    BooleanProgramImage image;
    image.register_count = 1;
    image.input_word_count = 1;

    BooleanProgramInstruction load;
    load.op = BooleanProgramOpcode::XorInput;
    load.dst = 0;
    load.a = 0;
    load.input_index = 0;
    image.instructions.push_back(load);
    image.output_registers = {0};
    image.validate();
    return image;
}

int run_server(const std::string& peer_id,
               const std::string& endpoint,
               const std::string& server_secret_key,
               const std::string& allowed_client_public_key,
               const std::string& allowed_client_peer_id,
               int finished_job_limit) {
    CurvePeerServer server(
        endpoint,
        server_secret_key,
        {CurveAuthorizedClient{allowed_client_public_key, allowed_client_peer_id}},
        CLOUD_TIMEOUT_MS);
    std::unordered_map<std::string, std::unique_ptr<CachedTfheSession>> sessions;

    std::cout << "V0ID TFHE CUDA evaluator " << peer_id
              << " listening on " << server.last_endpoint() << '\n'
              << "session cache cap      : " << MAX_CACHED_TFHE_SESSIONS << '\n'
              << "session TTL            : 30 minutes\n"
              << "transport              : ZeroMQ CURVE + ZAP / multipart\n"
              << "authorized client      : " << allowed_client_peer_id << '\n'
              << "client secret key recv : NO\n"
              << "status                 : waiting for authenticated request...\n"
              << std::flush;

    int finish_requests = 0;
    while (finish_requests < finished_job_limit) {
        auto request = server.receive_multipart();
        expire_sessions(sessions);

        const auto request_type = request.envelope.type;
        const auto request_peer_id = request.envelope.peer_id;
        const auto request_authenticated_user_id = request.authenticated_user_id;
        const auto request_job_id = request.envelope.job_id;
        const auto request_epoch = request.envelope.epoch;
        const bool counts_as_finish = request_type == MessageType::tfhe_job_finish;

        std::cout << "[cloud] request type=" << message_type_name(request_type)
                  << " auth-user="
                  << (request_authenticated_user_id.empty()
                          ? std::string("<missing>")
                          : request_authenticated_user_id)
                  << " claimed-peer=" << request_peer_id
                  << " job=" << request_job_id
                  << " epoch=" << request_epoch << '\n'
                  << std::flush;

        MultipartEnvelope reply;
        try {
            if (request_authenticated_user_id.empty())
                throw std::runtime_error("TFHE cloud request lacks authenticated transport identity");
            if (request_peer_id != request_authenticated_user_id)
                throw std::runtime_error("TFHE cloud claimed peer-id differs from CURVE/ZAP identity");
            if (request_job_id.empty())
                throw std::runtime_error("TFHE cloud job id must not be empty");

            if (request_type == MessageType::install_tfhe_session) {
                auto install = v0id::net::unpack_tfhe_cloud_install(std::move(request));
                const auto key = session_key(install.session_id);
                if (sessions.contains(key))
                    throw std::runtime_error("TFHE cloud session id already installed");
                if (sessions.size() >= MAX_CACHED_TFHE_SESSIONS)
                    throw std::runtime_error("TFHE cloud evaluator session cache is full");

                const auto short_id =
                    v0id::net::tfhe_cloud_session_id_hex(install.session_id).substr(0, 16);
                const auto session_id = install.session_id;
                const auto install_started = std::chrono::steady_clock::now();

                std::cout << "[cloud] session=" << short_id
                          << " installing GPU evaluator"
                          << " server-key-bytes=" << install.server_key_blob.size()
                          << " encrypted-init-bytes=" << install.encrypted_init_blob.size()
                          << " instructions=" << install.total_instruction_count
                          << " outputs=" << install.output_word_count << '\n'
                          << std::flush;

                auto cached = std::make_unique<CachedTfheSession>();
                cached->authenticated_user_id = request_authenticated_user_id;
                cached->job_id = request_job_id;
                cached->epoch = request_epoch;
                cached->expected_instruction_count =
                    static_cast<std::size_t>(install.total_instruction_count);
                cached->expected_output_word_count = install.output_word_count;
                cached->last_activity = std::chrono::steady_clock::now();
                cached->evaluator = std::make_unique<TfheCudaServerSession>(
                    install.server_key_blob, install.encrypted_init_blob);

                std::cout << "[cloud] session=" << short_id
                          << " GPU evaluator ready elapsed-ms="
                          << elapsed_ms(install_started) << '\n'
                          << std::flush;

                sessions.emplace(key, std::move(cached));

                reply = v0id::net::pack_tfhe_cloud_ack(
                    base_envelope(peer_id, request_job_id, request_epoch),
                    TfheCloudAck{session_id, 0},
                    MessageType::tfhe_session_ready);

                std::cout << "installed TFHE session=" << short_id
                          << " auth-user=" << request_authenticated_user_id
                          << " instructions=" << install.total_instruction_count
                          << " outputs=" << install.output_word_count
                          << " cached=" << sessions.size() << '\n'
                          << "  CURVE authenticated  : YES\n"
                          << "  server key received  : YES\n"
                          << "  encrypted init recv  : YES\n"
                          << "  plaintext program    : NO\n"
                          << "  plaintext inputs     : NO\n"
                          << "  ClientKey received   : NO\n"
                          << std::flush;
            } else if (request_type == MessageType::tfhe_instruction_chunk) {
                auto chunk = v0id::net::unpack_tfhe_cloud_chunk(std::move(request));
                const auto it = sessions.find(session_key(chunk.session_id));
                if (it == sessions.end())
                    throw std::runtime_error("TFHE instruction chunk references unknown session");
                auto& cached = *it->second;
                require_same_binding(cached, request_authenticated_user_id,
                                     request_job_id, request_epoch);

                if (chunk.total_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE chunk total differs from installed session total");
                if (chunk.start_instruction != cached.completed_instruction_count)
                    throw std::runtime_error("TFHE chunk replay/reorder/gap rejected");
                if (chunk.instruction_count >
                    cached.expected_instruction_count - cached.completed_instruction_count)
                    throw std::runtime_error("TFHE chunk exceeds remaining instruction budget");

                const auto short_id =
                    v0id::net::tfhe_cloud_session_id_hex(chunk.session_id).substr(0, 16);
                const auto chunk_started = std::chrono::steady_clock::now();
                std::cout << "[cloud] session=" << short_id
                          << " executing encrypted chunk start=" << chunk.start_instruction
                          << " count=" << chunk.instruction_count
                          << " bytes=" << chunk.encrypted_chunk_blob.size() << '\n'
                          << std::flush;

                v0id::fhe::GpuFheProgressStage last_stage =
                    static_cast<v0id::fhe::GpuFheProgressStage>(0);
                std::size_t last_current = static_cast<std::size_t>(-1);
                std::size_t last_total = static_cast<std::size_t>(-1);
                auto server_progress = [&](v0id::fhe::GpuFheProgressStage stage,
                                           std::size_t current,
                                           std::size_t total) {
                    if (stage == last_stage && current == last_current && total == last_total)
                        return;
                    last_stage = stage;
                    last_current = current;
                    last_total = total;
                    std::cout << "[CUDA/server] session=" << short_id << ' '
                              << progress_stage_name(stage) << ' '
                              << current << '/' << total << '\n'
                              << std::flush;
                };

                cached.evaluator->evaluate_chunk(
                    chunk.encrypted_chunk_blob, server_progress);
                cached.completed_instruction_count += chunk.instruction_count;
                cached.last_activity = std::chrono::steady_clock::now();

                reply = v0id::net::pack_tfhe_cloud_ack(
                    base_envelope(peer_id, request_job_id, request_epoch),
                    TfheCloudAck{chunk.session_id, cached.completed_instruction_count},
                    MessageType::tfhe_chunk_ready);

                std::cout << "[cloud] session=" << short_id
                          << " chunk complete elapsed-ms=" << elapsed_ms(chunk_started)
                          << " completed=" << cached.completed_instruction_count
                          << '/' << cached.expected_instruction_count << '\n'
                          << std::flush;
            } else if (request_type == MessageType::tfhe_job_finish) {
                const auto finish = v0id::net::unpack_tfhe_cloud_finish(request);
                const auto key = session_key(finish.session_id);
                const auto it = sessions.find(key);
                if (it == sessions.end())
                    throw std::runtime_error("TFHE finish references unknown session");
                auto& cached = *it->second;
                require_same_binding(cached, request_authenticated_user_id,
                                     request_job_id, request_epoch);

                if (finish.expected_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE finish instruction count mismatch");
                if (finish.expected_output_word_count != cached.expected_output_word_count)
                    throw std::runtime_error("TFHE finish output count mismatch");
                if (cached.completed_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE finish rejected before all instructions completed");

                const auto short_id =
                    v0id::net::tfhe_cloud_session_id_hex(finish.session_id).substr(0, 16);
                const auto finish_started = std::chrono::steady_clock::now();
                std::cout << "[cloud] session=" << short_id
                          << " selecting encrypted outputs...\n"
                          << std::flush;

                v0id::fhe::GpuFheProgressStage last_stage =
                    static_cast<v0id::fhe::GpuFheProgressStage>(0);
                std::size_t last_current = static_cast<std::size_t>(-1);
                std::size_t last_total = static_cast<std::size_t>(-1);
                auto server_progress = [&](v0id::fhe::GpuFheProgressStage stage,
                                           std::size_t current,
                                           std::size_t total) {
                    if (stage == last_stage && current == last_current && total == last_total)
                        return;
                    last_stage = stage;
                    last_current = current;
                    last_total = total;
                    std::cout << "[CUDA/server] session=" << short_id << ' '
                              << progress_stage_name(stage) << ' '
                              << current << '/' << total << '\n'
                              << std::flush;
                };

                auto encrypted_result = cached.evaluator->finish(server_progress);
                const auto completed = cached.completed_instruction_count;
                const auto session_id = finish.session_id;
                sessions.erase(it);

                TfheCloudResult result;
                result.session_id = session_id;
                result.completed_instruction_count = completed;
                result.encrypted_result_blob = std::move(encrypted_result);
                reply = v0id::net::pack_tfhe_cloud_result(
                    base_envelope(peer_id, request_job_id, request_epoch),
                    std::move(result));

                std::cout << "finished TFHE session=" << short_id
                          << " auth-user=" << request_authenticated_user_id
                          << " completed=" << completed
                          << " result-build-ms=" << elapsed_ms(finish_started)
                          << " session released=YES\n"
                          << std::flush;
            } else {
                throw std::runtime_error("expected TFHE session install/chunk/finish message");
            }
        } catch (const std::exception& e) {
            reply = error_reply(peer_id, request_job_id, request_epoch, e.what());
            std::cerr << "TFHE cloud request failed: " << e.what() << '\n' << std::flush;
        }

        server.reply_multipart(reply);
        if (counts_as_finish)
            ++finish_requests;
        if (finish_requests < finished_job_limit)
            std::cout << "[cloud] waiting for next authenticated request...\n"
                      << std::flush;
    }
    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint,
               const CurveKeyPair& client_keys,
               const std::string& server_public_key,
               const std::string& expected_server_peer_id) {
    const auto image = smoke_image();
    constexpr std::uint64_t input_word = 0x0123456789abcdefULL;
    const std::vector<std::uint64_t> inputs{input_word};
    const auto plain = v0id::integrity::evaluate_boolean_program_image(image, inputs);
    require(plain.output_words == inputs,
            "TFHE cloud smoke plaintext oracle did not preserve input word");

    v0id::fhe::GpuFheProgressStage last_stage =
        static_cast<v0id::fhe::GpuFheProgressStage>(0);
    std::size_t last_current = static_cast<std::size_t>(-1);
    std::size_t last_total = static_cast<std::size_t>(-1);
    auto progress = [&](v0id::fhe::GpuFheProgressStage stage,
                        std::size_t current,
                        std::size_t total) {
        if (stage == last_stage && current == last_current && total == last_total)
            return;
        last_stage = stage;
        last_current = current;
        last_total = total;
        std::cout << "[CUDA/client] " << progress_stage_name(stage)
                  << ' ' << current << '/' << total << '\n'
                  << std::flush;
    };

    std::cout << "preparing TFHE client session...\n" << std::flush;
    auto prepared = v0id::fhe::prepare_boolean_program_image_tfhe_cuda_client(
        image, inputs, progress);
    require(prepared.instruction_count == image.instructions.size(),
            "prepared TFHE cloud instruction count mismatch");
    require(prepared.output_word_count == image.output_registers.size(),
            "prepared TFHE cloud output count mismatch");

    const auto session_id = random_session_id();
    const std::string job_id = "v0id-tfhe-cloud-smoke-v1";
    const auto server_key_bytes = prepared.server_key_blob.size();
    const auto init_bytes = prepared.encrypted_init_blob.size();

    CurvePeerClient client(endpoint, client_keys, server_public_key, CLOUD_TIMEOUT_MS);

    TfheCloudInstall install;
    install.session_id = session_id;
    install.total_instruction_count = prepared.instruction_count;
    install.output_word_count = static_cast<std::uint32_t>(prepared.output_word_count);
    install.server_key_blob = std::move(prepared.server_key_blob);
    install.encrypted_init_blob = std::move(prepared.encrypted_init_blob);

    std::cout << "session id             : "
              << v0id::net::tfhe_cloud_session_id_hex(session_id).substr(0, 16) << "...\n"
              << "transport              : ZeroMQ CURVE + pinned server key\n"
              << "client key bytes       : " << prepared.client_key_blob.size() << '\n'
              << "server key frame bytes : " << server_key_bytes << '\n'
              << "encrypted init bytes   : " << init_bytes << '\n'
              << "evaluator receives SK  : NO\n"
              << "installing authenticated remote GPU session...\n" << std::flush;

    auto install_reply = client.round_trip_multipart(
        v0id::net::pack_tfhe_cloud_install(
            base_envelope(peer_id, job_id, DEMO_EPOCH), std::move(install)));
    require_server_reply_binding(install_reply, expected_server_peer_id, job_id, DEMO_EPOCH);
    throw_if_error(install_reply, "TFHE session install");
    const auto install_ack = v0id::net::unpack_tfhe_cloud_ack(
        install_reply, MessageType::tfhe_session_ready);
    require(install_ack.session_id == session_id,
            "TFHE session acknowledgement id mismatch");
    require(install_ack.completed_instruction_count == 0,
            "new TFHE session acknowledgement must start at instruction zero");

    std::cout << "remote evaluator       : AUTHENTICATED / SESSION READY\n";

    for (std::size_t first = 0; first < image.instructions.size();
         first += v0id::fhe::kTfheCudaInstructionChunkSize) {
        const auto count = std::min(
            v0id::fhe::kTfheCudaInstructionChunkSize,
            image.instructions.size() - first);
        const auto instruction_span = std::span<const BooleanProgramInstruction>(
            image.instructions.data() + first, count);

        auto encrypted_chunk =
            v0id::fhe::encrypt_boolean_program_chunk_tfhe_cuda_client(
                prepared.client_key_blob,
                instruction_span,
                first,
                image.instructions.size(),
                progress);
        const auto chunk_bytes = encrypted_chunk.size();

        TfheCloudChunk chunk;
        chunk.session_id = session_id;
        chunk.start_instruction = first;
        chunk.instruction_count = static_cast<std::uint32_t>(count);
        chunk.total_instruction_count = image.instructions.size();
        chunk.encrypted_chunk_blob = std::move(encrypted_chunk);

        std::cout << "sending encrypted chunk : start=" << first
                  << " count=" << count
                  << " bytes=" << chunk_bytes << '\n' << std::flush;

        auto chunk_reply = client.round_trip_multipart(
            v0id::net::pack_tfhe_cloud_chunk(
                base_envelope(peer_id, job_id, DEMO_EPOCH), std::move(chunk)));
        require_server_reply_binding(chunk_reply, expected_server_peer_id, job_id, DEMO_EPOCH);
        throw_if_error(chunk_reply, "TFHE chunk execution");
        const auto ack = v0id::net::unpack_tfhe_cloud_ack(
            chunk_reply, MessageType::tfhe_chunk_ready);
        require(ack.session_id == session_id,
                "TFHE chunk acknowledgement id mismatch");
        require(ack.completed_instruction_count == first + count,
                "TFHE chunk acknowledgement progress mismatch");
    }

    TfheCloudFinish finish;
    finish.session_id = session_id;
    finish.expected_instruction_count = prepared.instruction_count;
    finish.expected_output_word_count =
        static_cast<std::uint32_t>(prepared.output_word_count);

    std::cout << "requesting encrypted result...\n" << std::flush;
    auto finish_reply = client.round_trip_multipart(
        v0id::net::pack_tfhe_cloud_finish(
            base_envelope(peer_id, job_id, DEMO_EPOCH), finish));
    require_server_reply_binding(finish_reply, expected_server_peer_id, job_id, DEMO_EPOCH);
    throw_if_error(finish_reply, "TFHE job finish");
    auto result = v0id::net::unpack_tfhe_cloud_result(std::move(finish_reply));
    require(result.session_id == session_id,
            "TFHE result session id mismatch");
    require(result.completed_instruction_count == prepared.instruction_count,
            "TFHE result completed-instruction count mismatch");

    const auto decrypted =
        v0id::fhe::decrypt_boolean_program_image_tfhe_cuda_client(
            prepared.client_key_blob,
            result.encrypted_result_blob,
            prepared.instruction_count,
            prepared.output_word_count);
    require(decrypted == plain.output_words,
            "remote TFHE cloud result differs from plaintext oracle");

    std::cout << "[PASS] CURVE authenticated/encrypted the cloud channel\n"
              << "[PASS] ZAP bound the session to the authorized client public key\n"
              << "[PASS] TFHE server key installed once over ZeroMQ multipart\n"
              << "[PASS] encrypted instruction chunks executed in bound order\n"
              << "[PASS] evaluator never received ClientKey or plaintext program/input\n"
              << "[PASS] encrypted remote result decrypted to the plaintext oracle\n";
    return 0;
}

} // namespace

int main(int argc, char** argv) try {
    if (argc >= 2 && std::string(argv[1]) == "keygen") {
        if (argc != 3) {
            usage(argv[0]);
            return 2;
        }
        return run_keygen(argv[2]);
    }

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const std::string mode = argv[1];
    if (mode == "server") {
        if (argc != 7 && argc != 8) {
            usage(argv[0]);
            return 2;
        }
        const std::string peer_id = argv[2];
        const std::string endpoint = argv[3];
        const auto server_secret_key = read_key_file(argv[4]);
        const auto allowed_client_public_key = read_key_file(argv[5]);
        const std::string allowed_client_peer_id = argv[6];
        int count = 1;
        if (argc == 8) {
            count = std::stoi(argv[7]);
            if (count <= 0)
                throw std::runtime_error("finished-job-count must be positive");
        }
        return run_server(peer_id, endpoint, server_secret_key,
                          allowed_client_public_key, allowed_client_peer_id, count);
    }

    if (mode == "client") {
        if (argc != 8) {
            usage(argv[0]);
            return 2;
        }
        const std::string peer_id = argv[2];
        const std::string endpoint = argv[3];
        const auto client_keys = load_keypair(argv[4], argv[5]);
        const auto server_public_key = read_key_file(argv[6]);
        const std::string expected_server_peer_id = argv[7];
        return run_client(peer_id, endpoint, client_keys,
                          server_public_key, expected_server_peer_id);
    }

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "TFHE cloud demo FAILED: " << e.what() << '\n';
    return 1;
}
