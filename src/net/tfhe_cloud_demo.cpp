#include "boolean_program_image.hpp"
#include "gpu_fhe_backend.hpp"
#include "peer_transport.hpp"
#include "tfhe_cloud_codec.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using v0id::fhe::TfheCudaServerSession;
using v0id::integrity::BooleanProgramImage;
using v0id::integrity::BooleanProgramInstruction;
using v0id::integrity::BooleanProgramOpcode;
using v0id::net::Envelope;
using v0id::net::MessageType;
using v0id::net::MultipartEnvelope;
using v0id::net::PeerClient;
using v0id::net::PeerServer;
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
    std::string peer_id;
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
        << "  " << argv0 << " server <peer-id> <bind-endpoint> [finished-job-count]\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint>\n\n"
        << "Example:\n"
        << "  " << argv0 << " server gpu-node tcp://*:7788 1\n"
        << "  " << argv0 << " client client-a tcp://127.0.0.1:7788\n\n"
        << "The client keeps ClientKey locally. The evaluator receives a compressed\n"
        << "server key once, encrypted init once, then bounded encrypted instruction\n"
        << "chunks over ZeroMQ multipart frames. This demo is not an authenticated\n"
        << "public service; peer_id/job_id binding is protocol state, not identity proof.\n";
}

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
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
    return MultipartEnvelope{std::move(out), {}};
}

void throw_if_error(const MultipartEnvelope& reply, const char* operation) {
    if (reply.envelope.type == MessageType::error)
        throw std::runtime_error(std::string(operation) + " failed: " +
                                 v0id::net::text(reply.envelope.payload));
}

void require_same_binding(const CachedTfheSession& session,
                          const std::string& peer_id,
                          const std::string& job_id,
                          std::uint64_t epoch) {
    if (session.peer_id != peer_id)
        throw std::runtime_error("TFHE cloud peer binding mismatch");
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
            std::cout << "expiring stale TFHE session\n";
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
               int finished_job_limit) {
    PeerServer server(endpoint, CLOUD_TIMEOUT_MS);
    std::unordered_map<std::string, std::unique_ptr<CachedTfheSession>> sessions;

    std::cout << "V0ID TFHE CUDA evaluator " << peer_id
              << " listening on " << endpoint << '\n'
              << "session cache cap      : " << MAX_CACHED_TFHE_SESSIONS << '\n'
              << "session TTL            : 30 minutes\n"
              << "transport              : ZeroMQ multipart\n"
              << "client secret key recv : NO\n";

    int finish_requests = 0;
    while (finish_requests < finished_job_limit) {
        auto request = server.receive_multipart();
        expire_sessions(sessions);

        const auto request_type = request.envelope.type;
        const auto request_peer_id = request.envelope.peer_id;
        const auto request_job_id = request.envelope.job_id;
        const auto request_epoch = request.envelope.epoch;
        const bool counts_as_finish = request_type == MessageType::tfhe_job_finish;

        MultipartEnvelope reply;
        try {
            if (request_peer_id.empty())
                throw std::runtime_error("TFHE cloud peer id must not be empty");
            if (request_job_id.empty())
                throw std::runtime_error("TFHE cloud job id must not be empty");

            if (request_type == MessageType::install_tfhe_session) {
                auto install = v0id::net::unpack_tfhe_cloud_install(std::move(request));
                const auto key = session_key(install.session_id);
                if (sessions.contains(key))
                    throw std::runtime_error("TFHE cloud session id already installed");
                if (sessions.size() >= MAX_CACHED_TFHE_SESSIONS)
                    throw std::runtime_error("TFHE cloud evaluator session cache is full");

                auto cached = std::make_unique<CachedTfheSession>();
                cached->peer_id = request_peer_id;
                cached->job_id = request_job_id;
                cached->epoch = request_epoch;
                cached->expected_instruction_count =
                    static_cast<std::size_t>(install.total_instruction_count);
                cached->expected_output_word_count = install.output_word_count;
                cached->last_activity = std::chrono::steady_clock::now();
                cached->evaluator = std::make_unique<TfheCudaServerSession>(
                    install.server_key_blob, install.encrypted_init_blob);

                const auto short_id =
                    v0id::net::tfhe_cloud_session_id_hex(install.session_id).substr(0, 16);
                const auto session_id = install.session_id;
                sessions.emplace(key, std::move(cached));

                reply = v0id::net::pack_tfhe_cloud_ack(
                    base_envelope(peer_id, request_job_id, request_epoch),
                    TfheCloudAck{session_id, 0},
                    MessageType::tfhe_session_ready);

                std::cout << "installed TFHE session=" << short_id
                          << " instructions=" << install.total_instruction_count
                          << " outputs=" << install.output_word_count
                          << " cached=" << sessions.size() << '\n'
                          << "  server key received : YES\n"
                          << "  encrypted init recv  : YES\n"
                          << "  plaintext program    : NO\n"
                          << "  plaintext inputs     : NO\n"
                          << "  ClientKey received   : NO\n";
            } else if (request_type == MessageType::tfhe_instruction_chunk) {
                auto chunk = v0id::net::unpack_tfhe_cloud_chunk(std::move(request));
                const auto it = sessions.find(session_key(chunk.session_id));
                if (it == sessions.end())
                    throw std::runtime_error("TFHE instruction chunk references unknown session");
                auto& cached = *it->second;
                require_same_binding(cached, request_peer_id, request_job_id, request_epoch);

                if (chunk.total_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE chunk total differs from installed session total");
                if (chunk.start_instruction != cached.completed_instruction_count)
                    throw std::runtime_error("TFHE chunk replay/reorder/gap rejected");
                if (chunk.instruction_count >
                    cached.expected_instruction_count - cached.completed_instruction_count)
                    throw std::runtime_error("TFHE chunk exceeds remaining instruction budget");

                cached.evaluator->evaluate_chunk(chunk.encrypted_chunk_blob);
                cached.completed_instruction_count += chunk.instruction_count;
                cached.last_activity = std::chrono::steady_clock::now();

                reply = v0id::net::pack_tfhe_cloud_ack(
                    base_envelope(peer_id, request_job_id, request_epoch),
                    TfheCloudAck{chunk.session_id, cached.completed_instruction_count},
                    MessageType::tfhe_chunk_ready);

                std::cout << "session="
                          << v0id::net::tfhe_cloud_session_id_hex(chunk.session_id).substr(0, 16)
                          << " executed chunk start=" << chunk.start_instruction
                          << " count=" << chunk.instruction_count
                          << " completed=" << cached.completed_instruction_count
                          << '/' << cached.expected_instruction_count << '\n';
            } else if (request_type == MessageType::tfhe_job_finish) {
                const auto finish = v0id::net::unpack_tfhe_cloud_finish(request);
                const auto key = session_key(finish.session_id);
                const auto it = sessions.find(key);
                if (it == sessions.end())
                    throw std::runtime_error("TFHE finish references unknown session");
                auto& cached = *it->second;
                require_same_binding(cached, request_peer_id, request_job_id, request_epoch);

                if (finish.expected_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE finish instruction count mismatch");
                if (finish.expected_output_word_count != cached.expected_output_word_count)
                    throw std::runtime_error("TFHE finish output count mismatch");
                if (cached.completed_instruction_count != cached.expected_instruction_count)
                    throw std::runtime_error("TFHE finish rejected before all instructions completed");

                auto encrypted_result = cached.evaluator->finish();
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

                std::cout << "finished TFHE session="
                          << v0id::net::tfhe_cloud_session_id_hex(session_id).substr(0, 16)
                          << " completed=" << completed
                          << " session released=YES\n";
            } else {
                throw std::runtime_error("expected TFHE session install/chunk/finish message");
            }
        } catch (const std::exception& e) {
            reply = error_reply(peer_id, request_job_id, request_epoch, e.what());
            std::cerr << "TFHE cloud request failed: " << e.what() << '\n';
        }

        server.reply_multipart(reply);
        if (counts_as_finish)
            ++finish_requests;
    }
    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint) {
    const auto image = smoke_image();
    constexpr std::uint64_t input_word = 0x0123456789abcdefULL;
    const std::vector<std::uint64_t> inputs{input_word};
    const auto plain = v0id::integrity::evaluate_boolean_program_image(image, inputs);
    require(plain.output_words == inputs,
            "TFHE cloud smoke plaintext oracle did not preserve input word");

    std::size_t last_execution = static_cast<std::size_t>(-1);
    auto progress = [&](v0id::fhe::GpuFheProgressStage stage,
                        std::size_t current,
                        std::size_t total) {
        if (stage == v0id::fhe::GpuFheProgressStage::Execution &&
            current != last_execution) {
            last_execution = current;
            std::cout << "[CUDA] encrypted execution " << current << '/' << total << '\n';
        }
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

    PeerClient client(endpoint, CLOUD_TIMEOUT_MS);

    TfheCloudInstall install;
    install.session_id = session_id;
    install.total_instruction_count = prepared.instruction_count;
    install.output_word_count = static_cast<std::uint32_t>(prepared.output_word_count);
    install.server_key_blob = std::move(prepared.server_key_blob);
    install.encrypted_init_blob = std::move(prepared.encrypted_init_blob);

    std::cout << "session id             : "
              << v0id::net::tfhe_cloud_session_id_hex(session_id).substr(0, 16) << "...\n"
              << "client key bytes       : " << prepared.client_key_blob.size() << '\n'
              << "server key frame bytes : " << server_key_bytes << '\n'
              << "encrypted init bytes   : " << init_bytes << '\n'
              << "evaluator receives SK  : NO\n"
              << "installing remote GPU session...\n" << std::flush;

    auto install_reply = client.round_trip_multipart(
        v0id::net::pack_tfhe_cloud_install(
            base_envelope(peer_id, job_id, DEMO_EPOCH), std::move(install)));
    throw_if_error(install_reply, "TFHE session install");
    const auto install_ack = v0id::net::unpack_tfhe_cloud_ack(
        install_reply, MessageType::tfhe_session_ready);
    require(install_ack.session_id == session_id,
            "TFHE session acknowledgement id mismatch");
    require(install_ack.completed_instruction_count == 0,
            "new TFHE session acknowledgement must start at instruction zero");

    std::cout << "remote evaluator       : SESSION READY\n";

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

    std::cout << "[PASS] TFHE server key installed once over ZeroMQ multipart\n"
              << "[PASS] encrypted instruction chunks executed in bound order\n"
              << "[PASS] evaluator never received ClientKey or plaintext program/input\n"
              << "[PASS] encrypted remote result decrypted to the plaintext oracle\n";
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
        int count = 1;
        if (argc >= 5) {
            count = std::stoi(argv[4]);
            if (count <= 0)
                throw std::runtime_error("finished-job-count must be positive");
        }
        return run_server(peer_id, endpoint, count);
    }
    if (mode == "client")
        return run_client(peer_id, endpoint);

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "TFHE cloud demo FAILED: " << e.what() << '\n';
    return 1;
}
