#pragma once

#include <zmq.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace v0id::net {

enum class MessageType : std::uint8_t {
    hello = 1,
    pong = 2,
    store_slot = 3,
    fetch_slot = 4,
    slot_value = 5,
    execute_job = 6,
    job_result = 7,
    install_evaluator_session = 8,
    evaluator_session_ready = 9,
    module_offer = 10,
    module_request = 11,
    module_blob = 12,
    module_ready = 13,
    install_tfhe_session = 14,
    tfhe_session_ready = 15,
    tfhe_instruction_chunk = 16,
    tfhe_chunk_ready = 17,
    tfhe_job_finish = 18,
    tfhe_job_result = 19,
    error = 255,
};

struct Envelope {
    MessageType type{MessageType::hello};
    std::string peer_id;
    std::string job_id;
    std::uint64_t epoch{};
    std::vector<std::uint8_t> payload;

    std::vector<std::uint8_t> encode() const;
    static Envelope decode(const void* data, std::size_t size);
};

// Frame 0 is always the canonical V0ID Envelope. Additional frames carry large
// opaque objects without concatenating them into another giant serialization.
// TFHE cloud transport uses this for server keys, encrypted init/chunks/results.
struct MultipartEnvelope {
    Envelope envelope;
    std::vector<std::vector<std::uint8_t>> frames;
};

std::string to_string(MessageType type);

class PeerServer {
public:
    explicit PeerServer(const std::string& bind_endpoint, int timeout_ms = 10000);

    Envelope receive();
    void reply(const Envelope& envelope);

    MultipartEnvelope receive_multipart();
    void reply_multipart(const MultipartEnvelope& message);

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::rep};
};

class PeerClient {
public:
    explicit PeerClient(const std::string& connect_endpoint, int timeout_ms = 10000);

    Envelope round_trip(const Envelope& envelope);
    MultipartEnvelope round_trip_multipart(const MultipartEnvelope& message);

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::req};
};

std::vector<std::uint8_t> bytes(std::string_view text);
std::string text(const std::vector<std::uint8_t>& data);

} // namespace v0id::net
