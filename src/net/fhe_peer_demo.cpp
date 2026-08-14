#include "peer_transport.hpp"
#include "fhe_codec.hpp"

#include "binfhecontext.h"

#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lbcrypto;
using namespace v0id::net;

namespace {

void usage(const char* argv0) {
    std::cerr
        << "usage:\n"
        << "  " << argv0 << " server <peer-id> <bind-endpoint> [count]\n"
        << "  " << argv0 << " client <peer-id> <connect-endpoint> <bit>\n\n"
        << "remote operation: encrypted NOT(bit)\n";
}

int run_server(const std::string& peer_id,
               const std::string& endpoint,
               int count) {
    PeerServer server(endpoint, 30000);
    std::cout << "V0ID FHE evaluator " << peer_id << " listening on " << endpoint << '\n';

    for (int i = 0; i < count; ++i) {
        const auto request = server.receive();
        Envelope reply;
        reply.peer_id = peer_id;
        reply.job_id = request.job_id;
        reply.epoch = request.epoch;

        try {
            if (request.type != MessageType::execute_job)
                throw std::runtime_error("expected EXECUTE_JOB");

            const auto bundle = v0id::fhe::unpack_remote_eval_bundle(request.payload);

            BinFHEContext cc;
            RingGSWACCKey refresh_key;
            LWESwitchingKey switching_key;
            LWECiphertext input;

            v0id::fhe::deserialize_binary(bundle.context, cc);
            v0id::fhe::deserialize_binary(bundle.refresh_key, refresh_key);
            v0id::fhe::deserialize_binary(bundle.switching_key, switching_key);
            v0id::fhe::deserialize_binary(bundle.ciphertext, input);

            cc.BTKeyLoad({refresh_key, switching_key});
            auto output = cc.EvalNOT(input);

            reply.type = MessageType::job_result;
            reply.payload = v0id::fhe::serialize_binary(output);

            std::cout << "evaluated encrypted NOT for job=" << request.job_id
                      << " from=" << request.peer_id
                      << " without secret key\n";
        } catch (const std::exception& e) {
            reply.type = MessageType::error;
            reply.payload = bytes(e.what());
        }

        server.reply(reply);
    }

    return 0;
}

int run_client(const std::string& peer_id,
               const std::string& endpoint,
               int bit) {
    if (bit != 0 && bit != 1) throw std::runtime_error("bit must be 0 or 1");

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    std::cout << "generating OpenFHE bootstrapping keys...\n";
    cc.BTKeyGen(sk);

    const auto ciphertext = cc.Encrypt(sk, bit);

    v0id::fhe::RemoteEvalBundle bundle;
    bundle.context = v0id::fhe::serialize_binary(cc);
    bundle.refresh_key = v0id::fhe::serialize_binary(cc.GetRefreshKey());
    bundle.switching_key = v0id::fhe::serialize_binary(cc.GetSwitchKey());
    bundle.ciphertext = v0id::fhe::serialize_binary(ciphertext);

    Envelope request;
    request.type = MessageType::execute_job;
    request.peer_id = peer_id;
    request.job_id = "remote-not-smoke-test";
    request.epoch = 1;
    request.payload = v0id::fhe::pack_remote_eval_bundle(bundle);

    PeerClient client(endpoint, 30000);
    const auto reply = client.round_trip(request);

    if (reply.type == MessageType::error)
        throw std::runtime_error("remote evaluator error: " + text(reply.payload));
    if (reply.type != MessageType::job_result)
        throw std::runtime_error("unexpected remote reply type");

    LWECiphertext result_ciphertext;
    v0id::fhe::deserialize_binary(reply.payload, result_ciphertext);

    LWEPlaintext result{};
    cc.Decrypt(sk, result_ciphertext, &result);
    const int output = static_cast<int>(result & 1);

    std::cout << "input plaintext  : " << bit << '\n'
              << "remote operation : NOT under BinFHE\n"
              << "decrypted result : " << output << '\n'
              << "secret key sent  : NO\n";

    const int expected = bit ? 0 : 1;
    if (output != expected)
        throw std::runtime_error("wrong remote FHE result");

    std::cout << "OK: remote evaluator transformed ciphertext without secret key\n";
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
        if (argc < 5) {
            usage(argv[0]);
            return 2;
        }
        return run_client(peer_id, endpoint, std::stoi(argv[4]));
    }

    usage(argv[0]);
    return 2;
} catch (const std::exception& e) {
    std::cerr << "V0ID FHE peer error: " << e.what() << '\n';
    return 1;
}
