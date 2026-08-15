#include "tfhe_cloud_codec.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace v0id::net {
namespace {

constexpr std::array<std::uint8_t, 8> MAGIC{'V','0','T','F','H','E','0','1'};

enum class PayloadKind : std::uint8_t {
    install = 1,
    chunk = 2,
    ack = 3,
    finish = 4,
    result = 5,
};

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffu));
    out.push_back(static_cast<std::uint8_t>(value & 0xffu));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffu));
}

std::uint32_t get_u32(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 4)
        throw std::runtime_error("truncated TFHE cloud metadata");
    const auto out = (std::uint32_t(p[0]) << 24) |
                     (std::uint32_t(p[1]) << 16) |
                     (std::uint32_t(p[2]) << 8) |
                     std::uint32_t(p[3]);
    p += 4;
    return out;
}

std::uint64_t get_u64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 8)
        throw std::runtime_error("truncated TFHE cloud metadata");
    std::uint64_t out = 0;
    for (int i = 0; i < 8; ++i)
        out = (out << 8) | p[i];
    p += 8;
    return out;
}

void put_session(std::vector<std::uint8_t>& out, const TfheCloudSessionId& id) {
    out.insert(out.end(), id.begin(), id.end());
}

TfheCloudSessionId get_session(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < static_cast<std::ptrdiff_t>(TfheCloudSessionId{}.size()))
        throw std::runtime_error("truncated TFHE cloud session id");
    TfheCloudSessionId out{};
    std::copy_n(p, out.size(), out.begin());
    p += out.size();
    if (!valid_tfhe_cloud_session_id(out))
        throw std::runtime_error("TFHE cloud session id must be nonzero");
    return out;
}

std::vector<std::uint8_t> metadata_prefix(PayloadKind kind,
                                          const TfheCloudSessionId& session_id) {
    if (!valid_tfhe_cloud_session_id(session_id))
        throw std::runtime_error("TFHE cloud session id must be nonzero");
    std::vector<std::uint8_t> out;
    out.reserve(64);
    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
    put_u32(out, kTfheCloudProtocolVersion);
    out.push_back(static_cast<std::uint8_t>(kind));
    out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    put_session(out, session_id);
    return out;
}

TfheCloudSessionId parse_prefix(const std::vector<std::uint8_t>& metadata,
                                PayloadKind expected,
                                const std::uint8_t*& p,
                                const std::uint8_t*& end) {
    p = metadata.data();
    end = p + metadata.size();
    constexpr std::size_t prefix_bytes = 8 + 4 + 4 + 16;
    if (metadata.size() < prefix_bytes)
        throw std::runtime_error("TFHE cloud metadata too short");
    if (!std::equal(MAGIC.begin(), MAGIC.end(), p))
        throw std::runtime_error("bad TFHE cloud metadata magic");
    p += MAGIC.size();
    if (get_u32(p, end) != kTfheCloudProtocolVersion)
        throw std::runtime_error("unsupported TFHE cloud protocol version");
    if (*p++ != static_cast<std::uint8_t>(expected))
        throw std::runtime_error("wrong TFHE cloud metadata kind");
    p += 3;
    return get_session(p, end);
}

void require_exact_end(const std::uint8_t* p, const std::uint8_t* end) {
    if (p != end)
        throw std::runtime_error("trailing bytes in TFHE cloud metadata");
}

void require_frame_size(std::size_t size, const char* what) {
    if (size == 0)
        throw std::runtime_error(std::string(what) + " must not be empty");
    if (size > kTfheCloudMaxFrameBytes)
        throw std::runtime_error(std::string(what) + " exceeds TFHE cloud frame cap");
}

void require_frame_length(std::uint64_t advertised,
                          const std::vector<std::uint8_t>& frame,
                          const char* what) {
    require_frame_size(frame.size(), what);
    if (advertised != frame.size())
        throw std::runtime_error(std::string(what) + " frame length mismatch");
}

void require_instruction_total(std::uint64_t total) {
    if (total == 0 || total > kTfheCloudMaxInstructions)
        throw std::runtime_error("TFHE cloud instruction total outside protocol limit");
}

void require_outputs(std::uint32_t outputs) {
    if (outputs == 0 || outputs > kTfheCloudMaxOutputs)
        throw std::runtime_error("TFHE cloud output count outside protocol limit");
}

void require_type(const MultipartEnvelope& message, MessageType expected) {
    if (message.envelope.type != expected)
        throw std::runtime_error("unexpected TFHE cloud envelope type");
}

} // namespace

bool valid_tfhe_cloud_session_id(const TfheCloudSessionId& id) {
    return std::any_of(id.begin(), id.end(), [](std::uint8_t byte) { return byte != 0; });
}

std::string tfhe_cloud_session_id_hex(const TfheCloudSessionId& id) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : id)
        out << std::setw(2) << static_cast<unsigned>(byte);
    return out.str();
}

MultipartEnvelope pack_tfhe_cloud_install(
    Envelope envelope,
    TfheCloudInstall install) {
    require_instruction_total(install.total_instruction_count);
    require_outputs(install.output_word_count);
    require_frame_size(install.server_key_blob.size(), "TFHE server key");
    require_frame_size(install.encrypted_init_blob.size(), "TFHE encrypted init");

    envelope.type = MessageType::install_tfhe_session;
    envelope.payload = metadata_prefix(PayloadKind::install, install.session_id);
    put_u64(envelope.payload, install.total_instruction_count);
    put_u32(envelope.payload, install.output_word_count);
    put_u64(envelope.payload, install.server_key_blob.size());
    put_u64(envelope.payload, install.encrypted_init_blob.size());

    MultipartEnvelope out;
    out.envelope = std::move(envelope);
    out.frames.push_back(std::move(install.server_key_blob));
    out.frames.push_back(std::move(install.encrypted_init_blob));
    return out;
}

TfheCloudInstall unpack_tfhe_cloud_install(MultipartEnvelope message) {
    require_type(message, MessageType::install_tfhe_session);
    if (message.frames.size() != 2)
        throw std::runtime_error("INSTALL_TFHE_SESSION requires exactly two blob frames");

    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    TfheCloudInstall out;
    out.session_id = parse_prefix(message.envelope.payload, PayloadKind::install, p, end);
    out.total_instruction_count = get_u64(p, end);
    out.output_word_count = get_u32(p, end);
    const auto server_len = get_u64(p, end);
    const auto init_len = get_u64(p, end);
    require_exact_end(p, end);

    require_instruction_total(out.total_instruction_count);
    require_outputs(out.output_word_count);
    require_frame_length(server_len, message.frames[0], "TFHE server key");
    require_frame_length(init_len, message.frames[1], "TFHE encrypted init");
    out.server_key_blob = std::move(message.frames[0]);
    out.encrypted_init_blob = std::move(message.frames[1]);
    return out;
}

MultipartEnvelope pack_tfhe_cloud_chunk(
    Envelope envelope,
    TfheCloudChunk chunk) {
    require_instruction_total(chunk.total_instruction_count);
    if (chunk.instruction_count == 0 ||
        chunk.instruction_count > kTfheCloudMaxChunkInstructions)
        throw std::runtime_error("TFHE cloud chunk instruction count outside protocol limit");
    if (chunk.start_instruction > chunk.total_instruction_count ||
        chunk.instruction_count > chunk.total_instruction_count - chunk.start_instruction)
        throw std::runtime_error("TFHE cloud chunk exceeds advertised instruction total");
    require_frame_size(chunk.encrypted_chunk_blob.size(), "TFHE encrypted chunk");

    envelope.type = MessageType::tfhe_instruction_chunk;
    envelope.payload = metadata_prefix(PayloadKind::chunk, chunk.session_id);
    put_u64(envelope.payload, chunk.start_instruction);
    put_u32(envelope.payload, chunk.instruction_count);
    put_u64(envelope.payload, chunk.total_instruction_count);
    put_u64(envelope.payload, chunk.encrypted_chunk_blob.size());

    MultipartEnvelope out;
    out.envelope = std::move(envelope);
    out.frames.push_back(std::move(chunk.encrypted_chunk_blob));
    return out;
}

TfheCloudChunk unpack_tfhe_cloud_chunk(MultipartEnvelope message) {
    require_type(message, MessageType::tfhe_instruction_chunk);
    if (message.frames.size() != 1)
        throw std::runtime_error("TFHE_INSTRUCTION_CHUNK requires exactly one blob frame");

    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    TfheCloudChunk out;
    out.session_id = parse_prefix(message.envelope.payload, PayloadKind::chunk, p, end);
    out.start_instruction = get_u64(p, end);
    out.instruction_count = get_u32(p, end);
    out.total_instruction_count = get_u64(p, end);
    const auto chunk_len = get_u64(p, end);
    require_exact_end(p, end);

    require_instruction_total(out.total_instruction_count);
    if (out.instruction_count == 0 ||
        out.instruction_count > kTfheCloudMaxChunkInstructions)
        throw std::runtime_error("TFHE cloud chunk instruction count outside protocol limit");
    if (out.start_instruction > out.total_instruction_count ||
        out.instruction_count > out.total_instruction_count - out.start_instruction)
        throw std::runtime_error("TFHE cloud chunk exceeds advertised instruction total");
    require_frame_length(chunk_len, message.frames[0], "TFHE encrypted chunk");
    out.encrypted_chunk_blob = std::move(message.frames[0]);
    return out;
}

MultipartEnvelope pack_tfhe_cloud_ack(
    Envelope envelope,
    const TfheCloudAck& ack,
    MessageType type) {
    if (type != MessageType::tfhe_session_ready && type != MessageType::tfhe_chunk_ready)
        throw std::runtime_error("invalid TFHE cloud acknowledgement message type");
    envelope.type = type;
    envelope.payload = metadata_prefix(PayloadKind::ack, ack.session_id);
    put_u64(envelope.payload, ack.completed_instruction_count);
    return MultipartEnvelope{std::move(envelope), {}};
}

TfheCloudAck unpack_tfhe_cloud_ack(
    const MultipartEnvelope& message,
    MessageType expected_type) {
    if (expected_type != MessageType::tfhe_session_ready &&
        expected_type != MessageType::tfhe_chunk_ready)
        throw std::runtime_error("invalid expected TFHE cloud acknowledgement type");
    require_type(message, expected_type);
    if (!message.frames.empty())
        throw std::runtime_error("TFHE cloud acknowledgement must not contain blob frames");

    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    TfheCloudAck out;
    out.session_id = parse_prefix(message.envelope.payload, PayloadKind::ack, p, end);
    out.completed_instruction_count = get_u64(p, end);
    require_exact_end(p, end);
    return out;
}

MultipartEnvelope pack_tfhe_cloud_finish(
    Envelope envelope,
    const TfheCloudFinish& finish) {
    require_instruction_total(finish.expected_instruction_count);
    require_outputs(finish.expected_output_word_count);
    envelope.type = MessageType::tfhe_job_finish;
    envelope.payload = metadata_prefix(PayloadKind::finish, finish.session_id);
    put_u64(envelope.payload, finish.expected_instruction_count);
    put_u32(envelope.payload, finish.expected_output_word_count);
    return MultipartEnvelope{std::move(envelope), {}};
}

TfheCloudFinish unpack_tfhe_cloud_finish(const MultipartEnvelope& message) {
    require_type(message, MessageType::tfhe_job_finish);
    if (!message.frames.empty())
        throw std::runtime_error("TFHE_JOB_FINISH must not contain blob frames");

    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    TfheCloudFinish out;
    out.session_id = parse_prefix(message.envelope.payload, PayloadKind::finish, p, end);
    out.expected_instruction_count = get_u64(p, end);
    out.expected_output_word_count = get_u32(p, end);
    require_exact_end(p, end);
    require_instruction_total(out.expected_instruction_count);
    require_outputs(out.expected_output_word_count);
    return out;
}

MultipartEnvelope pack_tfhe_cloud_result(
    Envelope envelope,
    TfheCloudResult result) {
    require_frame_size(result.encrypted_result_blob.size(), "TFHE encrypted result");
    envelope.type = MessageType::tfhe_job_result;
    envelope.payload = metadata_prefix(PayloadKind::result, result.session_id);
    put_u64(envelope.payload, result.completed_instruction_count);
    put_u64(envelope.payload, result.encrypted_result_blob.size());

    MultipartEnvelope out;
    out.envelope = std::move(envelope);
    out.frames.push_back(std::move(result.encrypted_result_blob));
    return out;
}

TfheCloudResult unpack_tfhe_cloud_result(MultipartEnvelope message) {
    require_type(message, MessageType::tfhe_job_result);
    if (message.frames.size() != 1)
        throw std::runtime_error("TFHE_JOB_RESULT requires exactly one blob frame");

    const std::uint8_t* p = nullptr;
    const std::uint8_t* end = nullptr;
    TfheCloudResult out;
    out.session_id = parse_prefix(message.envelope.payload, PayloadKind::result, p, end);
    out.completed_instruction_count = get_u64(p, end);
    const auto result_len = get_u64(p, end);
    require_exact_end(p, end);
    require_frame_length(result_len, message.frames[0], "TFHE encrypted result");
    out.encrypted_result_blob = std::move(message.frames[0]);
    return out;
}

} // namespace v0id::net
