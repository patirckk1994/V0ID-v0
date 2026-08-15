#include "curve_peer_transport.hpp"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

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
    int application_requests = 0;
    std::thread server_thread([&] {
        try {
            auto chunk_request = server.receive_multipart();
            ++application_requests;
            require(chunk_request.authenticated_user_id == "client-a",
                    "server did not receive the ZAP authenticated client identity");
            require(chunk_request.envelope.peer_id == "client-a",
                    "test request peer id mismatch");
            require(chunk_request.envelope.type ==
                        v0id::net::MessageType::tfhe_instruction_chunk,
                    "first test request type mismatch");

            v0id::net::Envelope chunk_reply;
            chunk_reply.type = v0id::net::MessageType::tfhe_chunk_ready;
            chunk_reply.peer_id = "server-a";
            chunk_reply.job_id = chunk_request.envelope.job_id;
            chunk_reply.epoch = chunk_request.envelope.epoch;
            chunk_reply.payload = v0id::net::bytes("chunk-ack-1");
            server.reply_multipart({std::move(chunk_reply), {}, {}});

            // receive_multipart() internally consumes an exact retry of the
            // chunk request and replays the cached ACK. Application code should
            // only see the next distinct FINISH request.
            auto finish_request = server.receive_multipart();
            ++application_requests;
            require(finish_request.envelope.type ==
                        v0id::net::MessageType::tfhe_job_finish,
                    "duplicate chunk leaked back into application execution");

            v0id::net::Envelope result_reply;
            result_reply.type = v0id::net::MessageType::tfhe_job_result;
            result_reply.peer_id = "server-a";
            result_reply.job_id = finish_request.envelope.job_id;
            result_reply.epoch = finish_request.envelope.epoch;
            result_reply.payload = v0id::net::bytes("result-meta");
            server.reply_multipart(
                {std::move(result_reply), {{0xaa, 0xbb, 0xcc, 0xdd}}, {}});

            // Same check for a potentially expensive final result: the exact
            // FINISH retry is answered from the transport cache, and the cloud
            // application only receives the later distinct HELLO request.
            auto final_request = server.receive_multipart();
            ++application_requests;
            require(final_request.envelope.type == v0id::net::MessageType::hello,
                    "duplicate finish leaked back into application execution");

            v0id::net::Envelope pong;
            pong.type = v0id::net::MessageType::pong;
            pong.peer_id = "server-a";
            pong.job_id = final_request.envelope.job_id;
            pong.epoch = final_request.envelope.epoch;
            pong.payload = v0id::net::bytes("curve-ok");
            server.reply_multipart({std::move(pong), {}, {}});
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    v0id::net::CurvePeerClient client(
        server.last_endpoint(), client_keys, server_keys.public_key_z85, 5000);

    v0id::net::Envelope chunk;
    chunk.type = v0id::net::MessageType::tfhe_instruction_chunk;
    chunk.peer_id = "client-a";
    chunk.job_id = "curve-idempotency-test";
    chunk.epoch = 7;
    chunk.payload = v0id::net::bytes("same-encrypted-chunk-request");
    const v0id::net::MultipartEnvelope chunk_request{
        chunk, {{1, 2, 3, 4}}, {}};

    const auto first_chunk_reply = client.round_trip_multipart(chunk_request);
    require(first_chunk_reply.envelope.type ==
                v0id::net::MessageType::tfhe_chunk_ready,
            "first TFHE chunk acknowledgement type mismatch");
    require(v0id::net::text(first_chunk_reply.envelope.payload) == "chunk-ack-1",
            "first TFHE chunk acknowledgement payload mismatch");

    const auto replayed_chunk_reply = client.round_trip_multipart(chunk_request);
    require(replayed_chunk_reply.envelope.type ==
                v0id::net::MessageType::tfhe_chunk_ready &&
            replayed_chunk_reply.envelope.payload == first_chunk_reply.envelope.payload,
            "exact TFHE chunk retry did not replay the prior acknowledgement");

    v0id::net::Envelope finish;
    finish.type = v0id::net::MessageType::tfhe_job_finish;
    finish.peer_id = "client-a";
    finish.job_id = "curve-idempotency-test";
    finish.epoch = 7;
    finish.payload = v0id::net::bytes("same-finish-request");
    const v0id::net::MultipartEnvelope finish_request{finish, {}, {}};

    const auto first_result = client.round_trip_multipart(finish_request);
    require(first_result.envelope.type == v0id::net::MessageType::tfhe_job_result &&
            first_result.frames ==
                std::vector<std::vector<std::uint8_t>>{{0xaa, 0xbb, 0xcc, 0xdd}},
            "first TFHE final result mismatch");

    const auto replayed_result = client.round_trip_multipart(finish_request);
    require(replayed_result.envelope.type == v0id::net::MessageType::tfhe_job_result &&
            replayed_result.envelope.payload == first_result.envelope.payload &&
            replayed_result.frames == first_result.frames,
            "exact TFHE FINISH retry did not replay the cached encrypted result");

    v0id::net::Envelope final_request;
    final_request.type = v0id::net::MessageType::hello;
    final_request.peer_id = "client-a";
    final_request.job_id = "curve-transport-final";
    final_request.epoch = 8;
    const auto final_reply = client.round_trip_multipart(
        {std::move(final_request), {}, {}});

    server_thread.join();
    if (server_error)
        std::rethrow_exception(server_error);

    require(final_reply.envelope.type == v0id::net::MessageType::pong,
            "CURVE final reply type mismatch");
    require(final_reply.envelope.peer_id == "server-a",
            "CURVE final reply server id mismatch");
    require(v0id::net::text(final_reply.envelope.payload) == "curve-ok",
            "CURVE final reply payload mismatch");
    require(application_requests == 3,
            "idempotent transport retries re-entered application execution");

    std::cout << "[PASS] ZeroMQ CURVE encrypted the client/server transport\n"
              << "[PASS] ZAP allowlist mapped the client public key to client-a\n"
              << "[PASS] application received the authenticated User-Id metadata\n"
              << "[PASS] exact TFHE chunk retry replayed ACK without re-execution\n"
              << "[PASS] exact TFHE FINISH retry replayed cached encrypted result\n"
              << "[PASS] distinct requests invalidate the previous replay window\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "CURVE transport tests FAILED: " << e.what() << '\n';
    return 1;
}
