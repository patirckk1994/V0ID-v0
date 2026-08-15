#include "fhe_codec.hpp"
#include "program.hpp"
#include "program_morpher.hpp"
#include "remote_machine.hpp"
#include "round_receipt.hpp"

#include "binfhecontext.h"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

class Heartbeat {
public:
    explicit Heartbeat(std::string label,
                       std::chrono::seconds interval = std::chrono::seconds(10))
        : label_(std::move(label)), interval_(interval),
          start_(std::chrono::steady_clock::now()),
          thread_([this] { run(); }) {}

    ~Heartbeat() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        thread_.join();
    }

    Heartbeat(const Heartbeat&) = delete;
    Heartbeat& operator=(const Heartbeat&) = delete;

private:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!cv_.wait_for(lock, interval_, [this] { return stop_; })) {
            const std::chrono::duration<double> elapsed =
                std::chrono::steady_clock::now() - start_;
            std::cout << "  ... " << label_ << " still running ("
                      << elapsed.count() << " s elapsed)\n";
        }
    }

    std::string label_;
    std::chrono::seconds interval_;
    std::chrono::steady_clock::time_point start_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_{false};
    std::thread thread_;
};

using namespace lbcrypto;
using v0id::core::Program;
using v0id::fhe::CryptoProfileId;
using v0id::fhe::EvaluatorSessionId;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteEncryptedMachine;
using v0id::integrity::RoundLink;
using v0id::integrity::RoundReceipt;
using v0id::integrity::RoundReceiptContext;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;

constexpr std::size_t PUBLIC_STATES = 4;
constexpr std::size_t TAPE_CELLS = 8;
constexpr std::size_t REQUESTED_ROUNDS = 4;

std::vector<int> decrypt_bits(BinFHEContext& cc,
                              const LWEPrivateKey& sk,
                              const std::vector<LWECiphertext>& ciphertexts) {
    std::vector<int> out(ciphertexts.size());
    for (std::size_t i = 0; i < ciphertexts.size(); ++i) {
        LWEPlaintext p{};
        cc.Decrypt(sk, ciphertexts[i], &p);
        out[i] = static_cast<int>(p & 1u);
    }
    return out;
}

std::vector<int> run_plaintext(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t rounds) {
    auto tape = input;
    std::size_t state = initial_state;
    std::size_t head = 0;
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto& r = program.rule(state, tape.at(head));
        tape[head] = r.write;
        state = r.next_state;
        if (r.move < 0 && head > 0) --head;
        else if (r.move > 0 && head + 1 < tape.size()) ++head;
    }
    return tape;
}

struct EncryptedStart {
    std::vector<LWECiphertext> program;
    std::vector<LWECiphertext> state;
    std::vector<LWECiphertext> head;
    std::vector<LWECiphertext> tape;
};

v0id::fhe::ByteBlob serialize_ciphertext_vector(
    const std::vector<LWECiphertext>& cts) {
    v0id::fhe::ByteBlob out;
    for (const auto& ct : cts) {
        const auto bytes = v0id::fhe::serialize_binary(ct);
        for (int shift = 56; shift >= 0; shift -= 8)
            out.push_back(static_cast<std::uint8_t>((bytes.size() >> shift) & 0xffu));
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

struct RoundExecutionResult {
    std::vector<int> final_tape;
    std::vector<RoundLink> witness_digests;
};

RoundExecutionResult execute_rounds_with_receipt(
    BinFHEContext& cc,
    const LWEPrivateKey& sk,
    const PublicMachineShape& shape,
    const EncryptedStart& start,
    std::size_t actual_rounds,
    const std::string& run_label) {
    RemoteEncryptedMachine machine(
        cc, shape, start.program, start.state, start.head, start.tape,
        cc.Encrypt(sk, 0));

    RoundExecutionResult result;
    result.witness_digests.reserve(actual_rounds);
    for (std::size_t round = 0; round < actual_rounds; ++round) {
        std::cout << "  [" << run_label << "] round " << (round + 1)
                  << '/' << actual_rounds << " starting...\n";
        const auto t0 = std::chrono::steady_clock::now();
        {
            Heartbeat hb(run_label + " round " + std::to_string(round + 1) +
                         "/" + std::to_string(actual_rounds));
            machine.step();
        }
        const auto t1 = std::chrono::steady_clock::now();
        const std::chrono::duration<double, std::milli> step_ms = t1 - t0;
        result.witness_digests.push_back(v0id::integrity::round_state_digest(
            serialize_ciphertext_vector(machine.state_bits()),
            serialize_ciphertext_vector(machine.head_bits()),
            serialize_ciphertext_vector(machine.tape_bits())));
        std::cout << "  [" << run_label << "] round " << (round + 1)
                  << '/' << actual_rounds << " done (" << step_ms.count()
                  << " ms, " << machine.program_bits().size()
                  << " program bits under FHE)\n";
    }
    result.final_tape = decrypt_bits(cc, sk, machine.tape_bits());
    return result;
}

EvaluatorSessionId harness_session_id() {
    EvaluatorSessionId id{};
    for (std::size_t i = 0; i < id.size(); ++i)
        id[i] = static_cast<std::uint8_t>(i + 1);
    return id;
}

CryptoProfileId harness_profile() {
    return CryptoProfileId{
        "openfhe-binfhe",
        "STD128Q",
        "v0id-remote-machine-v4",
        "round-receipt-sha3-512-v1",
        "v0id-malicious-evaluator-harness-fixed-seed-v1",
        1,
    };
}

RoundReceiptContext harness_receipt_context(const PublicMachineShape& shape,
                                            const std::string& job_id,
                                            std::uint64_t epoch) {
    RoundReceiptContext context;
    context.session_id = harness_session_id();
    context.shape = shape;
    context.profile = harness_profile();
    context.job_id = job_id;
    context.epoch = epoch;
    return context;
}

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

} // namespace

int main() try {
    std::cout << std::unitbuf;

    const Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
    increment.validate();
    const std::vector<int> input{1,0,1,1,0,0,0,0};

    MorphSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i + 1);

    const auto morph = ProgramMorpher::morph(increment, 0, PUBLIC_STATES, seed);
    const PublicMachineShape shape{
        PUBLIC_STATES,
        TAPE_CELLS,
        REQUESTED_ROUNDS,
        0,
    };

    const auto expected_full = run_plaintext(
        morph.program, morph.initial_state, input, REQUESTED_ROUNDS);
    const auto expected_two = run_plaintext(morph.program, morph.initial_state, input, 2);
    const auto expected_one = run_plaintext(morph.program, morph.initial_state, input, 1);
    if (expected_two != expected_full)
        throw std::runtime_error("benchmark program no longer reaches the same output after two rounds");
    if (expected_one == expected_full)
        throw std::runtime_error("benchmark program unexpectedly reaches full output after one round");

    std::cout << "generating BinFHE context (STD128Q)...\n";
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128Q);
    std::cout << "generating LWE key pair...\n";
    const auto sk = cc.KeyGen();
    std::cout << "generating bootstrapping keys (BTKeyGen)...\n";
    const auto t_btkeygen_start = std::chrono::steady_clock::now();
    {
        Heartbeat hb("BTKeyGen");
        cc.BTKeyGen(sk);
    }
    const auto t_btkeygen_end = std::chrono::steady_clock::now();
    const std::chrono::duration<double> btkeygen_s =
        t_btkeygen_end - t_btkeygen_start;
    std::cout << "BTKeyGen complete (" << btkeygen_s.count() << " s)\n\n";

    std::cout << "encrypting program/state/head/tape bits...\n";
    EncryptedStart start;
    start.program = v0id::fhe::encrypt_remote_bits(
        cc, sk, v0id::fhe::canonical_remote_program_bits(morph.program));

    std::vector<int> state(PUBLIC_STATES, 0);
    state.at(morph.initial_state) = 1;
    start.state = v0id::fhe::encrypt_remote_bits(cc, sk, state);

    std::vector<int> head(TAPE_CELLS, 0);
    head[0] = 1;
    start.head = v0id::fhe::encrypt_remote_bits(cc, sk, head);
    start.tape = v0id::fhe::encrypt_remote_bits(cc, sk, input);
    std::cout << "encryption complete (" << start.program.size()
              << " program bits, " << start.tape.size() << " tape bits)\n\n";

    std::cout << "V0ID malicious evaluator execution-soundness harness\n"
              << "  requested rounds        : " << REQUESTED_ROUNDS << '\n'
              << "  FHE profile             : OpenFHE BinFHE STD128Q\n"
              << "  baseline semantic check : final plaintext result only\n"
              << "  audit layer             : SHA3-512 round-receipt chain\n\n";

    const auto t_honest_start = std::chrono::steady_clock::now();
    const auto honest = execute_rounds_with_receipt(
        cc, sk, shape, start, REQUESTED_ROUNDS, "honest");
    const auto t_honest_end = std::chrono::steady_clock::now();
    require(honest.final_tape == expected_full, "honest evaluator failed expected output");
    std::cout << "[PASS] honest evaluator executes all 4 rounds and returns expected output\n";

    const auto honest_context = harness_receipt_context(shape, "harness-honest-job", 1);
    const auto t_verify_start = std::chrono::steady_clock::now();
    const auto honest_verdict = verify_round_receipt(
        honest_context,
        RoundReceipt{honest_context, honest.witness_digests},
        honest.witness_digests.back());
    const auto t_verify_end = std::chrono::steady_clock::now();
    require(honest_verdict.ok,
            "round-receipt audit rejected an honest receipt: " + honest_verdict.reason);
    std::cout << "[PASS] round-receipt audit accepts the honest 4-round receipt\n";

    const std::chrono::duration<double, std::milli> honest_ms =
        t_honest_end - t_honest_start;
    const std::chrono::duration<double, std::milli> verify_ms =
        t_verify_end - t_verify_start;
    std::cout << "[INFO] 4 real BinFHE rounds took " << honest_ms.count()
              << " ms; round-receipt verification took " << verify_ms.count()
              << " ms\n\n";

    const auto skip_half = execute_rounds_with_receipt(
        cc, sk, shape, start, 2, "skip-half");
    require(skip_half.final_tape == expected_full,
            "two-round cheat no longer reproduces final output");
    std::cout << "[BREAK] evaluator executes only 2/4 rounds and returns the SAME final output\n"
              << "[BREAK] final-output-only verification therefore accepts the shortcut\n";

    std::vector<RoundLink> padded_witnesses = skip_half.witness_digests;
    padded_witnesses.push_back(skip_half.witness_digests.back());
    padded_witnesses.push_back(skip_half.witness_digests.back());
    const auto skip_context = harness_receipt_context(shape, "harness-skip-job", 1);
    const auto skip_verdict = verify_round_receipt(
        skip_context,
        RoundReceipt{skip_context, padded_witnesses},
        padded_witnesses.back());
    require(!skip_verdict.ok,
            "round-receipt audit failed to reject the 2/4 skip cheat");
    std::cout << "[PASS] round-receipt audit REJECTS the 2/4 skip cheat: "
              << skip_verdict.reason << '\n';

    const auto short_verdict = verify_round_receipt(
        skip_context,
        RoundReceipt{skip_context, skip_half.witness_digests},
        skip_half.witness_digests.back());
    require(!short_verdict.ok,
            "round-receipt audit failed to reject a short (2-link) receipt");
    std::cout << "[PASS] round-receipt audit REJECTS a short 2-link receipt: "
              << short_verdict.reason << "\n\n";

    const auto one_round = execute_rounds_with_receipt(
        cc, sk, shape, start, 1, "one-round");
    require(one_round.final_tape != expected_full,
            "one-round negative control unexpectedly accepted");
    std::cout << "[PASS] one-round early return changes output and is caught by known-output comparison\n\n";

    const auto replayed_context = harness_receipt_context(
        shape, "harness-replayed-job", 1);
    const auto replay_verdict = verify_round_receipt(
        replayed_context,
        RoundReceipt{honest_context, honest.witness_digests},
        honest.witness_digests.back());
    require(!replay_verdict.ok,
            "round-receipt audit failed to reject a replayed job result");
    std::cout << "[PASS] round-receipt audit REJECTS a receipt replayed from a different job: "
              << replay_verdict.reason << '\n';

    const auto splice_verdict = verify_round_receipt(
        honest_context,
        RoundReceipt{honest_context, honest.witness_digests},
        skip_half.witness_digests.back());
    require(!splice_verdict.ok,
            "round-receipt audit failed to reject a spliced final result");
    std::cout << "[PASS] round-receipt audit REJECTS a receipt spliced onto a different execution's output: "
              << splice_verdict.reason << "\n\n";

    std::cout << "V0ID execution soundness summary\n"
              << "  ToyFingerprint32: removed; it added no execution-soundness property.\n"
              << "  final-output-only checks: fooled by the 2/4 fixed-point shortcut.\n"
              << "  round-receipt SHA3-512 audit: rejects the skip, short-receipt, replay\n"
              << "    and splice strategies exercised above, much cheaper than recomputation.\n"
              << "  NOT claimed: complete verifiable-computation soundness against adaptive\n"
              << "    ciphertext transformations or every possible interior-round attack.\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID malicious evaluator harness fatal error: " << e.what() << '\n';
    return 2;
}
