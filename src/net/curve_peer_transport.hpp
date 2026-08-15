#pragma once

#include "peer_transport.hpp"

#include <string>
#include <thread>
#include <vector>

namespace v0id::net {

struct CurveKeyPair {
    std::string public_key_z85;
    std::string secret_key_z85;
};

struct CurveAuthorizedClient {
    std::string public_key_z85;
    std::string user_id;
};

bool curve_transport_supported();
CurveKeyPair generate_curve_keypair();

// CURVE + ZAP authenticated multipart transport. The ZAP handler accepts only
// explicitly configured client public keys and maps each accepted key to a
// stable User-Id. receive_multipart() exposes that User-Id in
// MultipartEnvelope::authenticated_user_id so application session state can be
// bound to the cryptographically authenticated transport identity.
class CurvePeerServer {
public:
    CurvePeerServer(const std::string& bind_endpoint,
                    const std::string& server_secret_key_z85,
                    std::vector<CurveAuthorizedClient> authorized_clients,
                    int timeout_ms = 10000);
    ~CurvePeerServer();

    CurvePeerServer(const CurvePeerServer&) = delete;
    CurvePeerServer& operator=(const CurvePeerServer&) = delete;

    MultipartEnvelope receive_multipart();
    void reply_multipart(const MultipartEnvelope& message);
    std::string last_endpoint() const;

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::rep};
    std::thread zap_thread_;
};

class CurvePeerClient {
public:
    CurvePeerClient(const std::string& connect_endpoint,
                    const CurveKeyPair& client_keys,
                    const std::string& server_public_key_z85,
                    int timeout_ms = 10000);

    MultipartEnvelope round_trip_multipart(const MultipartEnvelope& message);

private:
    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::req};
};

} // namespace v0id::net
