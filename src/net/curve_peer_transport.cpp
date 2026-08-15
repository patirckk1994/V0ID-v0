#include "curve_peer_transport.hpp"

#include <zmq.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <future>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace v0id::net {
namespace {

constexpr std::size_t MAX_MULTIPART_FRAMES = 16;
constexpr const char* ZAP_ENDPOINT = "inproc://zeromq.zap.01";
constexpr const char* ZAP_DOMAIN = "v0id.tfhe.cloud.v1";

struct RawAuthorizedClient {
    std::array<std::uint8_t, 32> public_key{};
    std::string user_id;
};

void require_curve() {
    if (!curve_transport_supported())
        throw std::runtime_error("linked libzmq was built without CURVE support");
}

void require_z85_key(const std::string& key, const char* what) {
    if (key.size() != 40)
        throw std::runtime_error(std::string(what) + " must be a 40-character Z85 CURVE key");
    std::array<std::uint8_t, 32> decoded{};
    if (!zmq_z85_decode(decoded.data(), key.c_str()))
        throw std::runtime_error(std::string(what) + " is not valid Z85");
}

std::array<std::uint8_t, 32> decode_z85_public_key(const std::string& key) {
    require_z85_key(key, "CURVE public key");
    std::array<std::uint8_t, 32> decoded{};
    if (!zmq_z85_decode(decoded.data(), key.c_str()))
        throw std::runtime_error("failed to decode CURVE public key");
    return decoded;
}

void require_user_id(const std::string& user_id) {
    if (user_id.empty() || user_id.size() > 255)
        throw std::runtime_error("CURVE ZAP user id must contain 1..255 ASCII bytes");
    for (const unsigned char ch : user_id) {
        if (ch < 0x21 || ch > 0x7e)
            throw std::runtime_error("CURVE ZAP user id must use printable non-space ASCII");
    }
}

std::vector<RawAuthorizedClient> decode_authorized_clients(
    const std::vector<CurveAuthorizedClient>& clients) {
    if (clients.empty())
        throw std::runtime_error("CURVE server requires at least one authorized client key");

    std::vector<RawAuthorizedClient> out;
    out.reserve(clients.size());
    for (const auto& client : clients) {
        require_user_id(client.user_id);
        RawAuthorizedClient raw{decode_z85_public_key(client.public_key_z85), client.user_id};
        for (const auto& existing : out) {
            if (existing.public_key == raw.public_key)
                throw std::runtime_error("duplicate CURVE client public key in allowlist");
            if (existing.user_id == raw.user_id)
                throw std::runtime_error("duplicate CURVE ZAP user id in allowlist");
        }
        out.push_back(std::move(raw));
    }
    return out;
}

void configure_socket(zmq::socket_t& socket, int timeout_ms) {
    socket.set(zmq::sockopt::linger, 0);
    socket.set(zmq::sockopt::rcvtimeo, timeout_ms);
    socket.set(zmq::sockopt::sndtimeo, timeout_ms);
}

void checked_setsockopt(void* socket,
                        int option,
                        const void* value,
                        std::size_t size,
                        const char* what) {
    if (zmq_setsockopt(socket, option, value, size) != 0)
        throw std::runtime_error(std::string("failed to set ") + what + ": " + zmq_strerror(zmq_errno()));
}

void configure_curve_server(zmq::socket_t& socket,
                            const std::string& secret_key_z85) {
    require_z85_key(secret_key_z85, "CURVE server secret key");
    const int enabled = 1;
    checked_setsockopt(socket.handle(), ZMQ_CURVE_SERVER,
                       &enabled, sizeof(enabled), "ZMQ_CURVE_SERVER");
    checked_setsockopt(socket.handle(), ZMQ_CURVE_SECRETKEY,
                       secret_key_z85.data(), secret_key_z85.size(),
                       "ZMQ_CURVE_SECRETKEY");
    checked_setsockopt(socket.handle(), ZMQ_ZAP_DOMAIN,
                       ZAP_DOMAIN, std::char_traits<char>::length(ZAP_DOMAIN),
                       "ZMQ_ZAP_DOMAIN");
}

void configure_curve_client(zmq::socket_t& socket,
                            const CurveKeyPair& client_keys,
                            const std::string& server_public_key_z85) {
    require_z85_key(client_keys.public_key_z85, "CURVE client public key");
    require_z85_key(client_keys.secret_key_z85, "CURVE client secret key");
    require_z85_key(server_public_key_z85, "CURVE server public key");

    checked_setsockopt(socket.handle(), ZMQ_CURVE_PUBLICKEY,
                       client_keys.public_key_z85.data(), client_keys.public_key_z85.size(),
                       "ZMQ_CURVE_PUBLICKEY");
    checked_setsockopt(socket.handle(), ZMQ_CURVE_SECRETKEY,
                       client_keys.secret_key_z85.data(), client_keys.secret_key_z85.size(),
                       "ZMQ_CURVE_SECRETKEY");
    checked_setsockopt(socket.handle(), ZMQ_CURVE_SERVERKEY,
                       server_public_key_z85.data(), server_public_key_z85.size(),
                       "ZMQ_CURVE_SERVERKEY");
}

std::string frame_string(const zmq::message_t& frame) {
    return std::string(static_cast<const char*>(frame.data()), frame.size());
}

void send_frame(zmq::socket_t& socket,
                const void* data,
                std::size_t size,
                bool more) {
    zmq::message_t frame(data, size);
    const auto flags = more ? zmq::send_flags::sndmore : zmq::send_flags::none;
    if (!socket.send(frame, flags))
        throw std::runtime_error("ZeroMQ send timed out");
}

void send_text_frame(zmq::socket_t& socket,
                     const std::string& value,
                     bool more) {
    send_frame(socket, value.data(), value.size(), more);
}

std::vector<zmq::message_t> receive_all_frames(zmq::socket_t& socket) {
    std::vector<zmq::message_t> frames;
    while (true) {
        frames.emplace_back();
        if (!socket.recv(frames.back(), zmq::recv_flags::none))
            throw std::runtime_error("ZeroMQ receive timed out");
        if (!socket.get(zmq::sockopt::rcvmore))
            break;
        if (frames.size() > 32)
            throw std::runtime_error("excessive ZAP frame count");
    }
    return frames;
}

void send_zap_reply(zmq::socket_t& socket,
                    const std::string& version,
                    const std::string& request_id,
                    bool accepted,
                    const std::string& user_id) {
    send_text_frame(socket, version.empty() ? std::string("1.0") : version, true);
    send_text_frame(socket, request_id, true);
    send_text_frame(socket, accepted ? std::string("200") : std::string("400"), true);
    send_text_frame(socket, accepted ? std::string("OK") : std::string("DENIED"), true);
    send_text_frame(socket, accepted ? user_id : std::string{}, true);
    send_frame(socket, nullptr, 0, false);
}

void zap_loop(zmq::context_t& context,
              std::vector<RawAuthorizedClient> authorized,
              std::promise<void> ready) {
    bool ready_signalled = false;
    try {
        zmq::socket_t zap(context, zmq::socket_type::rep);
        zap.set(zmq::sockopt::linger, 0);
        zap.bind(ZAP_ENDPOINT);
        ready.set_value();
        ready_signalled = true;

        while (true) {
            const auto frames = receive_all_frames(zap);
            const std::string version = frames.size() > 0 ? frame_string(frames[0]) : "1.0";
            const std::string request_id = frames.size() > 1 ? frame_string(frames[1]) : std::string{};

            bool accepted = false;
            std::string user_id;
            if (frames.size() == 7 &&
                version == "1.0" &&
                frame_string(frames[2]) == ZAP_DOMAIN &&
                frame_string(frames[5]) == "CURVE" &&
                frames[6].size() == 32) {
                const auto* credential = static_cast<const std::uint8_t*>(frames[6].data());
                for (const auto& client : authorized) {
                    if (std::equal(client.public_key.begin(), client.public_key.end(), credential)) {
                        accepted = true;
                        user_id = client.user_id;
                        break;
                    }
                }
            }
            send_zap_reply(zap, version, request_id, accepted, user_id);
        }
    } catch (const zmq::error_t& e) {
        if (!ready_signalled) {
            try {
                ready.set_exception(std::make_exception_ptr(e));
            } catch (...) {
            }
        } else if (e.num() != ETERM) {
            // Context shutdown is the expected exit path. Other failures end
            // the handler; subsequent authenticated handshakes fail closed.
        }
    } catch (...) {
        if (!ready_signalled) {
            try {
                ready.set_exception(std::current_exception());
            } catch (...) {
            }
        }
    }
}

void send_multipart(zmq::socket_t& socket, const MultipartEnvelope& message) {
    if (message.frames.size() > MAX_MULTIPART_FRAMES)
        throw std::runtime_error("too many CURVE V0ID multipart frames");

    const auto wire = message.envelope.encode();
    send_frame(socket, wire.data(), wire.size(), !message.frames.empty());
    for (std::size_t i = 0; i < message.frames.size(); ++i) {
        const auto& frame = message.frames[i];
        send_frame(socket, frame.data(), frame.size(), i + 1 != message.frames.size());
    }
}

MultipartEnvelope recv_multipart(zmq::socket_t& socket,
                                 bool require_authenticated_user) {
    zmq::message_t header;
    if (!socket.recv(header, zmq::recv_flags::none))
        throw std::runtime_error("ZeroMQ CURVE header receive timed out");

    MultipartEnvelope out;
    out.envelope = Envelope::decode(header.data(), header.size());
    if (require_authenticated_user) {
        const char* user_id = zmq_msg_gets(header.handle(), "User-Id");
        if (!user_id || *user_id == '\0')
            throw std::runtime_error("CURVE message missing ZAP authenticated User-Id");
        out.authenticated_user_id = user_id;
    }

    while (socket.get(zmq::sockopt::rcvmore)) {
        if (out.frames.size() >= MAX_MULTIPART_FRAMES)
            throw std::runtime_error("too many CURVE V0ID multipart frames");
        zmq::message_t frame;
        if (!socket.recv(frame, zmq::recv_flags::none))
            throw std::runtime_error("ZeroMQ CURVE multipart receive timed out");
        const auto* begin = static_cast<const std::uint8_t*>(frame.data());
        out.frames.emplace_back(begin, begin + frame.size());
    }
    return out;
}

} // namespace

bool curve_transport_supported() {
    return zmq_has("curve") == 1;
}

CurveKeyPair generate_curve_keypair() {
    require_curve();
    std::array<char, 41> public_key{};
    std::array<char, 41> secret_key{};
    if (zmq_curve_keypair(public_key.data(), secret_key.data()) != 0)
        throw std::runtime_error(std::string("zmq_curve_keypair failed: ") + zmq_strerror(zmq_errno()));
    return CurveKeyPair{std::string(public_key.data()), std::string(secret_key.data())};
}

CurvePeerServer::CurvePeerServer(
    const std::string& bind_endpoint,
    const std::string& server_secret_key_z85,
    std::vector<CurveAuthorizedClient> authorized_clients,
    int timeout_ms) {
    require_curve();
    const auto raw_authorized = decode_authorized_clients(authorized_clients);

    std::promise<void> ready;
    auto ready_future = ready.get_future();
    zap_thread_ = std::thread(
        [this, raw_authorized, ready = std::move(ready)]() mutable {
            zap_loop(context_, raw_authorized, std::move(ready));
        });
    try {
        ready_future.get();
        configure_socket(socket_, timeout_ms);
        configure_curve_server(socket_, server_secret_key_z85);
        socket_.bind(bind_endpoint);
    } catch (...) {
        zmq_ctx_shutdown(context_.handle());
        if (zap_thread_.joinable())
            zap_thread_.join();
        throw;
    }
}

CurvePeerServer::~CurvePeerServer() {
    zmq_ctx_shutdown(context_.handle());
    if (zap_thread_.joinable())
        zap_thread_.join();
}

MultipartEnvelope CurvePeerServer::receive_multipart() {
    return recv_multipart(socket_, true);
}

void CurvePeerServer::reply_multipart(const MultipartEnvelope& message) {
    send_multipart(socket_, message);
}

std::string CurvePeerServer::last_endpoint() const {
    return socket_.get(zmq::sockopt::last_endpoint);
}

CurvePeerClient::CurvePeerClient(const std::string& connect_endpoint,
                                 const CurveKeyPair& client_keys,
                                 const std::string& server_public_key_z85,
                                 int timeout_ms) {
    require_curve();
    configure_socket(socket_, timeout_ms);
    configure_curve_client(socket_, client_keys, server_public_key_z85);
    socket_.connect(connect_endpoint);
}

MultipartEnvelope CurvePeerClient::round_trip_multipart(
    const MultipartEnvelope& message) {
    send_multipart(socket_, message);
    return recv_multipart(socket_, false);
}

} // namespace v0id::net
