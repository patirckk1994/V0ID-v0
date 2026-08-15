#pragma once

#include "boolean_program_image.hpp"
#include "curve_peer_transport.hpp"
#include "tfhe_cloud_codec.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace v0id::net {

struct TfheCloudClientConfig {
    std::string client_peer_id;
    std::string endpoint;
    CurveKeyPair client_keys;
    std::string server_public_key_z85;
    std::string expected_server_peer_id;
    std::string job_id;
    std::uint64_t epoch{1};
    int timeout_ms{3'600'000};
    std::uint32_t retry_attempts{2};
    std::size_t instruction_chunk_size{32};
    bool verify_plaintext_result{true};
};

struct TfheCloudClientResult {
    std::string session_id_hex;
    std::size_t instruction_count{};
    std::size_t output_word_count{};
    std::size_t server_key_bytes{};
    std::size_t encrypted_init_bytes{};
    std::size_t encrypted_result_bytes{};
    std::vector<std::uint64_t> output_words;
    bool plaintext_verified{};
};

using TfheCloudClientProgress = std::function<void(
    const std::string& stage,
    std::uint64_t current,
    std::uint64_t total,
    const std::string& message)>;

CurveKeyPair load_curve_keypair_files(
    const std::string& public_path,
    const std::string& secret_path);

std::string load_curve_public_key_file(const std::string& path);

// Trusted-client wrapper around the existing streamed TFHE CUDA cloud protocol.
// The ClientKey never enters the request transport. Exact transport failures are
// retried by reconnecting and resending the same request, allowing the server's
// authenticated idempotent replay window to return a previous ACK/result without
// re-entering evaluator execution.
TfheCloudClientResult execute_boolean_program_tfhe_cloud(
    const v0id::integrity::BooleanProgramImage& image,
    const std::vector<std::uint64_t>& input_words,
    const TfheCloudClientConfig& config,
    TfheCloudClientProgress progress = {});

} // namespace v0id::net
