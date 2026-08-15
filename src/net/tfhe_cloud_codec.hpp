#pragma once

#include "peer_transport.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::net {

using TfheCloudSessionId = std::array<std::uint8_t, 16>;

inline constexpr std::uint32_t kTfheCloudProtocolVersion = 1;
inline constexpr std::size_t kTfheCloudMaxInstructions = 65536;
inline constexpr std::size_t kTfheCloudMaxChunkInstructions = 64;
inline constexpr std::size_t kTfheCloudMaxOutputs = 64;
inline constexpr std::size_t kTfheCloudMaxFrameBytes = 512ull * 1024ull * 1024ull;

struct TfheCloudInstall {
    TfheCloudSessionId session_id{};
    std::uint64_t total_instruction_count{};
    std::uint32_t output_word_count{};
    std::vector<std::uint8_t> server_key_blob;
    std::vector<std::uint8_t> encrypted_init_blob;
};

struct TfheCloudChunk {
    TfheCloudSessionId session_id{};
    std::uint64_t start_instruction{};
    std::uint32_t instruction_count{};
    std::uint64_t total_instruction_count{};
    std::vector<std::uint8_t> encrypted_chunk_blob;
};

struct TfheCloudAck {
    TfheCloudSessionId session_id{};
    std::uint64_t completed_instruction_count{};
};

struct TfheCloudFinish {
    TfheCloudSessionId session_id{};
    std::uint64_t expected_instruction_count{};
    std::uint32_t expected_output_word_count{};
};

struct TfheCloudResult {
    TfheCloudSessionId session_id{};
    std::uint64_t completed_instruction_count{};
    std::vector<std::uint8_t> encrypted_result_blob;
};

bool valid_tfhe_cloud_session_id(const TfheCloudSessionId& id);
std::string tfhe_cloud_session_id_hex(const TfheCloudSessionId& id);

// Large blob-bearing messages are accepted/returned by value so callers can
// std::move server keys, encrypted chunks and results through the framing layer
// without duplicating hundreds of MiB of opaque ciphertext/key material.
MultipartEnvelope pack_tfhe_cloud_install(
    Envelope envelope,
    TfheCloudInstall install);
TfheCloudInstall unpack_tfhe_cloud_install(MultipartEnvelope message);

MultipartEnvelope pack_tfhe_cloud_chunk(
    Envelope envelope,
    TfheCloudChunk chunk);
TfheCloudChunk unpack_tfhe_cloud_chunk(MultipartEnvelope message);

MultipartEnvelope pack_tfhe_cloud_ack(
    Envelope envelope,
    const TfheCloudAck& ack,
    MessageType type);
TfheCloudAck unpack_tfhe_cloud_ack(
    const MultipartEnvelope& message,
    MessageType expected_type);

MultipartEnvelope pack_tfhe_cloud_finish(
    Envelope envelope,
    const TfheCloudFinish& finish);
TfheCloudFinish unpack_tfhe_cloud_finish(const MultipartEnvelope& message);

MultipartEnvelope pack_tfhe_cloud_result(
    Envelope envelope,
    TfheCloudResult result);
TfheCloudResult unpack_tfhe_cloud_result(MultipartEnvelope message);

} // namespace v0id::net
