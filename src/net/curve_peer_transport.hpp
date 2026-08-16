#pragma once

#include "peer_transport.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <unordered_map>
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
//
// The server also keeps one bounded idempotent reply record per authenticated
// User-Id for the state-changing TFHE cloud acknowledgements/results. An exact
// retry of the immediately preceding authenticated request is answered from the
// cached reply without re-entering application execution. The cache stores only
// a SHA3-512 request fingerprint plus the reply that already had to be returned;
// it does not retain computation traces or historical evaluator state.
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
    using ReplayDigest512 = std::array<std::uint8_t, 64>;

    struct ReplayRecord {
        ReplayDigest512 request_digest{};
        MultipartEnvelope reply;
        std::chrono::steady_clock::time_point stored_at;
    };

    zmq::context_t context_{1};
    zmq::socket_t socket_{context_, zmq::socket_type::rep};
    std::thread zap_thread_;

    // REP sockets process one application request at a time. The pending fields
    // bind reply_multipart() to the exact request returned by receive_multipart().
    bool pending_request_{};
    std::string pending_user_id_;
    ReplayDigest512 pending_request_digest_{};

    // One replayable response per authenticated user is enough for the REQ/REP
    // protocol: a client cannot legitimately advance to its next request before
    // receiving the previous reply. A later distinct request invalidates the old
    // replay window for that user.
    std::unordered_map<std::string, ReplayRecord> replay_by_user_;
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
