#include "peer_transport.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace v0id::net {
namespace {

constexpr std::array<std::uint8_t, 8> MAGIC{'V','0','I','D','N','E','T','1'};
constexpr std::uint8_t VERSION = 1;
constexpr std::size_t HEADER_SIZE = 8 + 1 + 1 + 2 + 8 + 4 + 4 + 4;
constexpr std::size_t MAX_MULTIPART_FRAMES = 16;

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xffu));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xffu));
    out.push_back(static_cast<std::uint8_t>(v & 0xffu));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xffu));
}

std::uint32_t get_u32(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 4) throw std::runtime_error("truncated V0ID envelope");
    const auto v = (std::uint32_t(p[0]) << 24) |
                   (std::uint32_t(p[1]) << 16) |
                   (std::uint32_t(p[2]) << 8) |
                   std::uint32_t(p[3]);
    p += 4;
    return v;
}

std::uint64_t get_u64(const std::uint8_t*& p, const std::uint8_t* end) {
    if (end - p < 8) throw std::runtime_error("truncated V0ID envelope");
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    p += 8;
    return v;
}

void require_u32_size(std::size_t n, const char* what) {
    if (n > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error(std::string(what) + " too large for V0ID envelope");
}

void configure_socket(zmq::socket_t& socket, int timeout_ms) {
    socket.set(zmq::sockopt::linger, 0);
    socket.set(zmq::sockopt::rcvtimeo, timeout_ms);
    socket.set(zmq::sockopt::sndtimeo, timeout_ms);
}

void drain_remaining_frames(zmq::socket_t& socket) {
    while (socket.get(zmq::sockopt::rcvmore)) {
        zmq::message_t ignored;
        const auto result = socket.recv(ignored, zmq::recv_flags::none);
        if (!result) throw std::runtime_error("ZeroMQ receive timed out while draining multipart message");
    }
}

void send_envelope(zmq::socket_t& socket, const Envelope& envelope) {
    const auto wire = envelope.encode();
    zmq::message_t message(wire.data(), wire.size());
    const auto result = socket.send(message, zmq::send_flags::none);
    if (!result) throw std::runtime_error("ZeroMQ send timed out");
}

Envelope recv_envelope(zmq::socket_t& socket) {
    zmq::message_t message;
    const auto result = socket.recv(message, zmq::recv_flags::none);
    if (!result) throw std::runtime_error("ZeroMQ receive timed out");
    if (socket.get(zmq::sockopt::rcvmore)) {
        drain_remaining_frames(socket);
        throw std::runtime_error("unexpected multipart V0ID message on single-frame API");
    }
    return Envelope::decode(message.data(), message.size());
}

void send_multipart(zmq::socket_t& socket, const MultipartEnvelope& message) {
    if (message.frames.size() > MAX_MULTIPART_FRAMES)
        throw std::runtime_error("too many V0ID multipart frames");

    const auto wire = message.envelope.encode();
    zmq::message_t header(wire.data(), wire.size());
    const auto header_flags = message.frames.empty()
        ? zmq::send_flags::none
        : zmq::send_flags::sndmore;
    if (!socket.send(header, header_flags))
        throw std::runtime_error("ZeroMQ multipart header send timed out");

    for (std::size_t i = 0; i < message.frames.size(); ++i) {
        const auto& frame = message.frames[i];
        zmq::message_t payload(frame.data(), frame.size());
        const auto flags = (i + 1 == message.frames.size())
            ? zmq::send_flags::none
            : zmq::send_flags::sndmore;
        if (!socket.send(payload, flags))
            throw std::runtime_error("ZeroMQ multipart payload send timed out");
    }
}

MultipartEnvelope recv_multipart(zmq::socket_t& socket) {
    zmq::message_t header;
    const auto result = socket.recv(header, zmq::recv_flags::none);
    if (!result) throw std::runtime_error("ZeroMQ multipart header receive timed out");

    MultipartEnvelope out;
    out.envelope = Envelope::decode(header.data(), header.size());

    bool too_many = false;
    while (socket.get(zmq::sockopt::rcvmore)) {
        zmq::message_t frame;
        const auto frame_result = socket.recv(frame, zmq::recv_flags::none);
        if (!frame_result)
            throw std::runtime_error("ZeroMQ multipart payload receive timed out");
        if (out.frames.size() >= MAX_MULTIPART_FRAMES) {
            too_many = true;
            continue;
        }
        const auto* begin = static_cast<const std::uint8_t*>(frame.data());
        out.frames.emplace_back(begin, begin + frame.size());
    }
    if (too_many)
        throw std::runtime_error("too many V0ID multipart frames");
    return out;
}

} // namespace

std::vector<std::uint8_t> Envelope::encode() const {
    require_u32_size(peer_id.size(), "peer id");
    require_u32_size(job_id.size(), "job id");
    require_u32_size(payload.size(), "payload");

    std::vector<std::uint8_t> out;
    out.reserve(HEADER_SIZE + peer_id.size() + job_id.size() + payload.size());
    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
    out.push_back(VERSION);
    out.push_back(static_cast<std::uint8_t>(type));
    out.push_back(0);
    out.push_back(0);
    put_u64(out, epoch);
    put_u32(out, static_cast<std::uint32_t>(peer_id.size()));
    put_u32(out, static_cast<std::uint32_t>(job_id.size()));
    put_u32(out, static_cast<std::uint32_t>(payload.size()));
    out.insert(out.end(), peer_id.begin(), peer_id.end());
    out.insert(out.end(), job_id.begin(), job_id.end());
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Envelope Envelope::decode(const void* data, std::size_t size) {
    if (size < HEADER_SIZE) throw std::runtime_error("V0ID envelope too short");

    const auto* begin = static_cast<const std::uint8_t*>(data);
    const auto* p = begin;
    const auto* end = begin + size;

    if (!std::equal(MAGIC.begin(), MAGIC.end(), p))
        throw std::runtime_error("bad V0ID envelope magic");
    p += MAGIC.size();

    const auto version = *p++;
    if (version != VERSION) throw std::runtime_error("unsupported V0ID network version");

    Envelope out;
    out.type = static_cast<MessageType>(*p++);
    p += 2; // reserved
    out.epoch = get_u64(p, end);
    const auto peer_len = get_u32(p, end);
    const auto job_len = get_u32(p, end);
    const auto payload_len = get_u32(p, end);

    const std::uint64_t remaining = static_cast<std::uint64_t>(end - p);
    const std::uint64_t expected = static_cast<std::uint64_t>(peer_len) +
                                   static_cast<std::uint64_t>(job_len) +
                                   static_cast<std::uint64_t>(payload_len);
    if (remaining != expected) throw std::runtime_error("bad V0ID envelope lengths");

    out.peer_id.assign(reinterpret_cast<const char*>(p), peer_len);
    p += peer_len;
    out.job_id.assign(reinterpret_cast<const char*>(p), job_len);
    p += job_len;
    out.payload.assign(p, p + payload_len);
    return out;
}

std::string to_string(MessageType type) {
    switch (type) {
        case MessageType::hello: return "HELLO";
        case MessageType::pong: return "PONG";
        case MessageType::store_slot: return "STORE_SLOT";
        case MessageType::fetch_slot: return "FETCH_SLOT";
        case MessageType::slot_value: return "SLOT_VALUE";
        case MessageType::execute_job: return "EXECUTE_JOB";
        case MessageType::job_result: return "JOB_RESULT";
        case MessageType::install_evaluator_session: return "INSTALL_EVALUATOR_SESSION";
        case MessageType::evaluator_session_ready: return "EVALUATOR_SESSION_READY";
        case MessageType::module_offer: return "MODULE_OFFER";
        case MessageType::module_request: return "MODULE_REQUEST";
        case MessageType::module_blob: return "MODULE_BLOB";
        case MessageType::module_ready: return "MODULE_READY";
        case MessageType::install_tfhe_session: return "INSTALL_TFHE_SESSION";
        case MessageType::tfhe_session_ready: return "TFHE_SESSION_READY";
        case MessageType::tfhe_instruction_chunk: return "TFHE_INSTRUCTION_CHUNK";
        case MessageType::tfhe_chunk_ready: return "TFHE_CHUNK_READY";
        case MessageType::tfhe_job_finish: return "TFHE_JOB_FINISH";
        case MessageType::tfhe_job_result: return "TFHE_JOB_RESULT";
        case MessageType::error: return "ERROR";
    }
    return "UNKNOWN";
}

PeerServer::PeerServer(const std::string& bind_endpoint, int timeout_ms) {
    configure_socket(socket_, timeout_ms);
    socket_.bind(bind_endpoint);
}

Envelope PeerServer::receive() {
    return recv_envelope(socket_);
}

void PeerServer::reply(const Envelope& envelope) {
    send_envelope(socket_, envelope);
}

MultipartEnvelope PeerServer::receive_multipart() {
    return recv_multipart(socket_);
}

void PeerServer::reply_multipart(const MultipartEnvelope& message) {
    send_multipart(socket_, message);
}

PeerClient::PeerClient(const std::string& connect_endpoint, int timeout_ms) {
    configure_socket(socket_, timeout_ms);
    socket_.connect(connect_endpoint);
}

Envelope PeerClient::round_trip(const Envelope& envelope) {
    send_envelope(socket_, envelope);
    return recv_envelope(socket_);
}

MultipartEnvelope PeerClient::round_trip_multipart(const MultipartEnvelope& message) {
    send_multipart(socket_, message);
    return recv_multipart(socket_);
}

std::vector<std::uint8_t> bytes(std::string_view value) {
    return {value.begin(), value.end()};
}

std::string text(const std::vector<std::uint8_t>& data) {
    return {data.begin(), data.end()};
}

} // namespace v0id::net
