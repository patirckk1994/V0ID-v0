#include "curve_peer_transport.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

} // namespace

int main() try {
    require(v0id::net::curve_transport_supported(),
            "linked libzmq does not provide CURVE support");

    const auto server_keys = v0id::net::generate_curve_keypair();
    const auto client_keys = v0id::net::generate_curve_keypair();

    v0id::net::CurvePeerServer server(
        "tcp://127.0.0.1:*",
        server_keys.secret_key_z85,
        {{client_keys.public_key_z85, "client-a"}},
        5000);

    std::exception_ptr server_error;
    std::thread server_thread([&] {
        try {
            auto request = server.receive_multipart();
            require(request.authenticated_user_id == "client-a",
                    "server did not receive the ZAP authenticated client identity");
            require(request.envelope.peer_id == "client-a",
                    "test request peer id mismatch");
            require(request.envelope.type == v0id::net::MessageType::hello,
                    "test request type mismatch");

            v0id::net::Envelope reply;
            reply.type = v0id::net::MessageType::pong;
            reply.peer_id = "server-a";
            reply.job_id = request.envelope.job_id;
            reply.epoch = request.envelope.epoch;
            reply.payload = v0id::net::bytes("curve-ok");
            server.reply_multipart({std::move(reply), {}, {}});
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    v0id::net::CurvePeerClient client(
        server.last_endpoint(), client_keys, server_keys.public_key_z85, 5000);

    v0id::net::Envelope request;
    request.type = v0id::net::MessageType::hello;
    request.peer_id = "client-a";
    request.job_id = "curve-transport-test";
    request.epoch = 7;

    const auto reply = client.round_trip_multipart({std::move(request), {}, {}});
    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);

    require(reply.envelope.type == v0id::net::MessageType::pong,
            "CURVE reply type mismatch");
    require(reply.envelope.peer_id == "server-a",
            "CURVE reply server id mismatch");
    require(v0id::net::text(reply.envelope.payload) == "curve-ok",
            "CURVE reply payload mismatch");

    std::cout << "[PASS] ZeroMQ CURVE encrypted the client/server transport\n"
              << "[PASS] ZAP allowlist mapped the client public key to client-a\n"
              << "[PASS] application received the authenticated User-Id metadata\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "CURVE transport tests FAILED: " << e.what() << '\n';
    return 1;
}
