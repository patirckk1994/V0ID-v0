#include "peer_transport.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace v0id::net;

namespace {

void usage(const char* argv0) {
    std::cerr
        << "usage:\n"
        << "  " << argv0 << " server <peer-id> <bind-endpoint> [count]\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint> [message]\n\n"
        << "examples:\n"
        << "  " << argv0 << " server A tcp://*:7001 2\n"
        << "  " << argv0 << " client B tcp://127.0.0.1:7001 hello\n"
        << "  " << argv0 << " client C tcp://127.0.0.1:7001 world\n";
}

int run_server(const std::string& peer_id,
               const std::string& endpoint,
               int count) {
    PeerServer server(endpoint);
    std::cout << "V0ID peer " << peer_id << " listening on " << endpoint << '\n';

    for (int i = 0; i < count; ++i) {
        const auto request = server.receive();
        std::cout << "rx " << to_string(request.type)
                  << " from=" << request.peer_id
                  << " job=" << request.job_id
                  << " epoch=" << request.epoch
                  << " payload='" << text(request.payload) << "'\n";

        Envelope reply;
        reply.type = MessageType::pong;
        reply.peer_id = peer_id;
        reply.job_id = request.job_id;
        reply.epoch = request.epoch;
        reply.payload = bytes("ack:" + text(request.payload));
        server.reply(reply);
    }

    std::cout << "server completed " << count << " request(s)\n";
    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint,
               const std::string& message) {
    PeerClient client(endpoint);

    Envelope request;
    request.type = MessageType::hello;
    request.peer_id = peer_id;
    request.job_id = "smoke-test";
    request.epoch = 1;
    request.payload = bytes(message);

    const auto reply = client.round_trip(request);
    std::cout << "tx HELLO to " << endpoint << '\n'
              << "rx " << to_string(reply.type)
              << " from=" << reply.peer_id
              << " job=" << reply.job_id
              << " epoch=" << reply.epoch
              << " payload='" << text(reply.payload) << "'\n";

    if (reply.type != MessageType::pong)
        throw std::runtime_error("peer did not return PONG");
    return 0;
}

} // namespace

int main(int argc, char** argv) try {
    if (argc < 4) {
        usage(argv[0]);
        return 2;
    }

    const std::string mode = argv[1];
    const std::string peer_id = argv[2];
    const std::string endpoint = argv[3];

    if (mode == "server") {
        const int count = argc >= 5 ? std::stoi(argv[4]) : 1;
        if (count <= 0) throw std::runtime_error("count must be positive");
        return run_server(peer_id, endpoint, count);
    }

    if (mode == "client") {
        const std::string message = argc >= 5 ? argv[4] : "hello-v0id";
        return run_client(peer_id, endpoint, message);
    }

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "V0ID peer error: " << e.what() << '\n';
    return 1;
}
