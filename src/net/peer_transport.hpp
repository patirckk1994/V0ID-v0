#pragma once

#include <zmq.hpp>

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

std::string to_string(MessageType type);

class PeerServer {
public:
    explicit PeerServer(const std::string& bind_endpoint, int timeout_ms = 10000);

    Envelope receive();
    void reply(const Envelope& envelope);

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::rep};
};

class PeerClient {
public:
    explicit PeerClient(const std::string& connect_endpoint, int timeout_ms = 10000);

    Envelope round_trip(const Envelope& envelope);

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::req};
};

std::vector<std::uint8_t> bytes(std::string_view text);
std::string text(const std::vector<std::uint8_t>& data);

} // namespace v0id::net
