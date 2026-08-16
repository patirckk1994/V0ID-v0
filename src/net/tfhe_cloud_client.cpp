#include "tfhe_cloud_client.hpp"

#include "gpu_fhe_backend.hpp"
#include "tfhe_cloud_codec.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace v0id::net {
namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

std::string read_key_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("cannot open CURVE key file: " + path);
    std::string key;
    std::string extra;
    if (!(in >> key))
        throw std::runtime_error("CURVE key file is empty: " + path);
    if (in >> extra)
        throw std::runtime_error("CURVE key file contains extra tokens: " + path);
    if (key.size() != 40)
        throw std::runtime_error(
            "CURVE key file must contain one 40-character Z85 key: " + path);
    return key;
}

TfheCloudSessionId random_session_id() {
    TfheCloudSessionId id{};
    do {
        if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1)
            throw std::runtime_error(
                "RAND_bytes failed while generating TFHE cloud session id");
    } while (!valid_tfhe_cloud_session_id(id));
    return id;
}

Envelope base_envelope(const TfheCloudClientConfig& config) {
    Envelope out;
    out.peer_id = config.client_peer_id;
    out.job_id = config.job_id;
    out.epoch = config.epoch;
    return out;
}

void require_reply_binding(const MultipartEnvelope& reply,
                           const TfheCloudClientConfig& config) {
    if (reply.envelope.peer_id != config.expected_server_peer_id)
        throw std::runtime_error("TFHE cloud reply server peer-id mismatch");
    if (reply.envelope.job_id != config.job_id)
        throw std::runtime_error("TFHE cloud reply job binding mismatch");
    if (reply.envelope.epoch != config.epoch)
        throw std::runtime_error("TFHE cloud reply epoch binding mismatch");
}

void throw_if_error(const MultipartEnvelope& reply, const char* operation) {
    if (reply.envelope.type == MessageType::error) {
        throw std::runtime_error(
            std::string(operation) + " failed: " + text(reply.envelope.payload));
    }
}

const char* gpu_stage_name(v0id::fhe::GpuFheProgressStage stage) {
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

void emit(const TfheCloudClientProgress& progress,
          const std::string& stage,
          std::uint64_t current,
          std::uint64_t total,
          const std::string& message) {
    if (progress) progress(stage, current, total, message);
}

class ResilientCurveClient {
public:
    ResilientCurveClient(const TfheCloudClientConfig& config,
                         TfheCloudClientProgress progress)
        : config_(config), progress_(std::move(progress)) {
        reconnect();
    }

    MultipartEnvelope round_trip(const MultipartEnvelope& request,
                                 const std::string& operation) {
        std::exception_ptr last_error;
        const std::uint32_t attempts = std::max<std::uint32_t>(1, config_.retry_attempts);
        for (std::uint32_t attempt = 1; attempt <= attempts; ++attempt) {
            try {
                return client_->round_trip_multipart(request);
            } catch (...) {
                last_error = std::current_exception();
                if (attempt == attempts) break;
                emit(progress_, "transport-retry", attempt, attempts,
                     operation + ": reconnecting and replaying the exact authenticated request");
                reconnect();
            }
        }
        std::rethrow_exception(last_error);
    }

private:
    void reconnect() {
        client_ = std::make_unique<CurvePeerClient>(
            config_.endpoint,
            config_.client_keys,
            config_.server_public_key_z85,
            config_.timeout_ms);
    }

    const TfheCloudClientConfig& config_;
    TfheCloudClientProgress progress_;
    std::unique_ptr<CurvePeerClient> client_;
};

void validate_config(const TfheCloudClientConfig& config) {
    if (config.client_peer_id.empty())
        throw std::runtime_error("TFHE cloud client peer id must not be empty");
    if (config.endpoint.empty())
        throw std::runtime_error("TFHE cloud endpoint must not be empty");
    if (config.server_public_key_z85.empty())
        throw std::runtime_error("TFHE cloud server public key must not be empty");
    if (config.expected_server_peer_id.empty())
        throw std::runtime_error("TFHE cloud expected server peer id must not be empty");
    if (config.job_id.empty())
        throw std::runtime_error("TFHE cloud job id must not be empty");
    if (config.timeout_ms <= 0)
        throw std::runtime_error("TFHE cloud timeout must be positive");
    if (config.retry_attempts == 0 || config.retry_attempts > 8)
        throw std::runtime_error("TFHE cloud retry attempts must be in 1..8");
    if (config.instruction_chunk_size == 0 ||
        config.instruction_chunk_size > v0id::fhe::kTfheCudaInstructionChunkSize)
        throw std::runtime_error("TFHE cloud client chunk size outside supported range");
}

} // namespace

CurveKeyPair load_curve_keypair_files(const std::string& public_path,
                                      const std::string& secret_path) {
    return CurveKeyPair{read_key_file(public_path), read_key_file(secret_path)};
}

std::string load_curve_public_key_file(const std::string& path) {
    return read_key_file(path);
}

TfheCloudClientResult execute_boolean_program_tfhe_cloud(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    const TfheCloudClientConfig& config,
    TfheCloudClientProgress progress) {
    validate_config(config);
    image.validate();
    if (input_words.size() != image.input_word_count)
        throw std::runtime_error("TFHE cloud input word count does not match program image");
    if (!v0id::fhe::tfhe_cuda_backend_available())
        throw std::runtime_error("TFHE CUDA backend is unavailable on this client");

    std::vector<std::uint64_t> plaintext_oracle;
    if (config.verify_plaintext_result) {
        emit(progress, "plaintext-oracle", 0, 1,
             "evaluating cheap local plaintext oracle before encrypted submission");
        plaintext_oracle =
            v0id::integrity::evaluate_boolean_program_image(image, input_words).output_words;
        emit(progress, "plaintext-oracle", 1, 1, "plaintext oracle ready");
    }

    emit(progress, "client-prepare", 0, 1,
         "generating client/server TFHE material and encrypting initial state");
    auto gpu_progress = [&](v0id::fhe::GpuFheProgressStage stage,
                            std::size_t current,
                            std::size_t total) {
        emit(progress,
             std::string("client-") + gpu_stage_name(stage),
             current,
             total,
             "trusted-client TFHE preparation");
    };
    auto prepared = v0id::fhe::prepare_boolean_program_image_tfhe_cuda_client(
        image, input_words, gpu_progress);
    require(prepared.instruction_count == image.instructions.size(),
            "prepared TFHE instruction count mismatch");
    require(prepared.output_word_count == image.output_registers.size(),
            "prepared TFHE output count mismatch");

    const auto session_id = random_session_id();
    const auto session_hex = tfhe_cloud_session_id_hex(session_id);
    const auto server_key_bytes = prepared.server_key_blob.size();
    const auto encrypted_init_bytes = prepared.encrypted_init_blob.size();

    ResilientCurveClient client(config, progress);

    TfheCloudInstall install;
    install.session_id = session_id;
    install.total_instruction_count = prepared.instruction_count;
    install.output_word_count = static_cast<std::uint32_t>(prepared.output_word_count);
    install.server_key_blob = std::move(prepared.server_key_blob);
    install.encrypted_init_blob = std::move(prepared.encrypted_init_blob);
    auto install_request = pack_tfhe_cloud_install(base_envelope(config), std::move(install));

    emit(progress, "remote-install", 0, 1,
         "installing authenticated encrypted evaluator session at " + config.endpoint);
    auto install_reply = client.round_trip(install_request, "TFHE session install");
    require_reply_binding(install_reply, config);
    throw_if_error(install_reply, "TFHE session install");
    const auto install_ack = unpack_tfhe_cloud_ack(
        install_reply, MessageType::tfhe_session_ready);
    require(install_ack.session_id == session_id,
            "TFHE session acknowledgement id mismatch");
    require(install_ack.completed_instruction_count == 0,
            "new TFHE cloud session did not start at instruction zero");
    emit(progress, "remote-install", 1, 1, "remote encrypted evaluator session ready");

    const std::size_t chunk_size = config.instruction_chunk_size;
    const std::size_t chunk_total =
        (image.instructions.size() + chunk_size - 1) / chunk_size;
    std::size_t chunk_index = 0;

    for (std::size_t first = 0; first < image.instructions.size(); first += chunk_size) {
        const auto count = std::min(chunk_size, image.instructions.size() - first);
        const auto instruction_span =
            std::span<const v0id::integrity::BooleanProgramInstruction>(
                image.instructions.data() + first, count);

        emit(progress, "encrypt-chunk", chunk_index, chunk_total,
             "encrypting instruction chunk " + std::to_string(chunk_index + 1) +
             "/" + std::to_string(chunk_total));
        auto encrypted_chunk =
            v0id::fhe::encrypt_boolean_program_chunk_tfhe_cuda_client(
                prepared.client_key_blob,
                instruction_span,
                first,
                image.instructions.size(),
                gpu_progress);

        TfheCloudChunk chunk;
        chunk.session_id = session_id;
        chunk.start_instruction = first;
        chunk.instruction_count = static_cast<std::uint32_t>(count);
        chunk.total_instruction_count = image.instructions.size();
        chunk.encrypted_chunk_blob = std::move(encrypted_chunk);
        auto chunk_request = pack_tfhe_cloud_chunk(base_envelope(config), std::move(chunk));

        emit(progress, "remote-execution", chunk_index, chunk_total,
             "submitting encrypted chunk to remote evaluator");
        auto chunk_reply = client.round_trip(chunk_request, "TFHE chunk execution");
        require_reply_binding(chunk_reply, config);
        throw_if_error(chunk_reply, "TFHE chunk execution");
        const auto ack = unpack_tfhe_cloud_ack(
            chunk_reply, MessageType::tfhe_chunk_ready);
        require(ack.session_id == session_id,
                "TFHE chunk acknowledgement session mismatch");
        require(ack.completed_instruction_count == first + count,
                "TFHE chunk acknowledgement progress mismatch");

        ++chunk_index;
        emit(progress, "remote-execution", chunk_index, chunk_total,
             "remote evaluator completed encrypted chunk");
    }

    TfheCloudFinish finish;
    finish.session_id = session_id;
    finish.expected_instruction_count = prepared.instruction_count;
    finish.expected_output_word_count =
        static_cast<std::uint32_t>(prepared.output_word_count);
    auto finish_request = pack_tfhe_cloud_finish(base_envelope(config), finish);

    emit(progress, "remote-finish", 0, 1,
         "requesting encrypted output selection from remote evaluator");
    auto finish_reply = client.round_trip(finish_request, "TFHE job finish");
    require_reply_binding(finish_reply, config);
    throw_if_error(finish_reply, "TFHE job finish");
    auto result = unpack_tfhe_cloud_result(std::move(finish_reply));
    require(result.session_id == session_id, "TFHE result session id mismatch");
    require(result.completed_instruction_count == prepared.instruction_count,
            "TFHE result completed-instruction count mismatch");
    const auto encrypted_result_bytes = result.encrypted_result_blob.size();
    emit(progress, "remote-finish", 1, 1, "encrypted result received from remote endpoint");

    emit(progress, "client-decrypt", 0, 1,
         "decrypting encrypted result locally with the client key");
    auto outputs = v0id::fhe::decrypt_boolean_program_image_tfhe_cuda_client(
        prepared.client_key_blob,
        result.encrypted_result_blob,
        prepared.instruction_count,
        prepared.output_word_count);
    emit(progress, "client-decrypt", 1, 1, "local result decryption complete");

    bool verified = false;
    if (config.verify_plaintext_result) {
        if (outputs != plaintext_oracle)
            throw std::runtime_error(
                "remote TFHE result differs from the local plaintext oracle");
        verified = true;
        emit(progress, "verify", 1, 1,
             "decrypted remote result matches local plaintext oracle");
    }

    TfheCloudClientResult out;
    out.session_id_hex = session_hex;
    out.instruction_count = prepared.instruction_count;
    out.output_word_count = prepared.output_word_count;
    out.server_key_bytes = server_key_bytes;
    out.encrypted_init_bytes = encrypted_init_bytes;
    out.encrypted_result_bytes = encrypted_result_bytes;
    out.output_words = std::move(outputs);
    out.plaintext_verified = verified;
    return out;
}

} // namespace v0id::net
