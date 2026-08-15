#include "program.hpp"
#include "program_morpher.hpp"
#include "remote_machine.hpp"
#include "toy_fingerprint.hpp"

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

using namespace lbcrypto;
using v0id::core::Program;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteEncryptedMachine;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;

constexpr std::size_t PUBLIC_STATES = 5;
constexpr std::size_t TAPE_CELLS = 8;
constexpr std::size_t REQUESTED_ROUNDS = 4;
constexpr std::size_t INTEGRITY_SLOTS = 4;

// BinFHE bootstrapping can leave this harness silent for minutes at a time.
// Keep stdout visibly alive during every expensive phase so "slow" is never
// confused with "hung". The worker sleeps on a condition variable so teardown
// does not add a full heartbeat interval after a stage finishes.
class Heartbeat {
public:
    explicit Heartbeat(std::string label,
                       std::chrono::seconds interval = std::chrono::seconds(10))
        : label_(std::move(label)),
          interval_(interval),
          start_(std::chrono::steady_clock::now()),
          thread_([this] { run(); }) {}

    ~Heartbeat() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
    }

    Heartbeat(const Heartbeat&) = delete;
    Heartbeat& operator=(const Heartbeat&) = delete;

private:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!cv_.wait_for(lock, interval_, [this] { return stop_; })) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start_);
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

struct PlainRun {
    std::size_t state{};
    std::size_t head{};
    std::vector<int> tape;
};

PlainRun run_plain(const Program& program,
                   std::size_t initial_state,
                   const std::vector<int>& input,
                   std::size_t rounds) {
    PlainRun out{initial_state, 0, input};
    for (std::size_t round = 0; round < rounds; ++round) {
        const auto& rule = program.rule(out.state, out.tape.at(out.head));
        out.tape[out.head] = rule.write;
        out.state = rule.next_state;
        if (rule.move < 0 && out.head > 0)
            --out.head;
        else if (rule.move > 0 && out.head + 1 < out.tape.size())
            ++out.head;
    }
    return out;
}

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

std::size_t decode_one_hot(const std::vector<int>& bits, const char* what) {
    std::size_t index = bits.size();
    for (std::size_t i = 0; i < bits.size(); ++i) {
        if (bits[i] == 0)
            continue;
        if (bits[i] != 1 || index != bits.size())
            throw std::runtime_error(std::string(what) + " is not one-hot");
        index = i;
    }
    if (index == bits.size())
        throw std::runtime_error(std::string(what) + " has no active bit");
    return index;
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
    const auto plain_two = run_plain(increment, 0, input, 2);
    const auto plain_four = run_plain(increment, 0, input, REQUESTED_ROUNDS);
    require(plain_two.tape == plain_four.tape,
            "benchmark no longer has the same semantic tape after 2 and 4 rounds");

    MorphSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i + 1);

    const auto schedule = ProgramMorpher::morph_round_schedule(
        increment, 0, PUBLIC_STATES, REQUESTED_ROUNDS, seed, INTEGRITY_SLOTS);

    const auto expected_two_state =
        schedule.manifest.logical_to_morphed[2][plain_two.state];
    const auto expected_four_state =
        schedule.manifest.logical_to_morphed[REQUESTED_ROUNDS][plain_four.state];
    require(expected_two_state != expected_four_state,
            "round-boundary encodings unexpectedly collide in 2/4 benchmark");

    const auto plain_schedule_bits =
        v0id::integrity::canonical_program_schedule_bits(schedule.round_programs);
    const auto expected_fingerprint = v0id::integrity::toy_fingerprint32_plain_schedule(
        schedule.round_programs, input, schedule.manifest.integrity_nonce);

    std::cout << "V0ID round-polymorphic FHE execution-binding harness\n"
              << "  public states           : " << PUBLIC_STATES << '\n'
              << "  requested rounds        : " << REQUESTED_ROUNDS << '\n'
              << "  encrypted tables        : " << schedule.round_programs.size() << '\n'
              << "  encrypted schedule bits : " << plain_schedule_bits.size() << '\n'
              << "  FHE profile             : OpenFHE BinFHE STD128Q\n\n";

    std::cout << "generating BinFHE context + keys...\n";
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128Q);
    const auto sk = cc.KeyGen();

    std::cout << "generating bootstrapping keys...\n";
    const auto bt_start = std::chrono::steady_clock::now();
    {
        Heartbeat heartbeat("BTKeyGen");
        cc.BTKeyGen(sk);
    }
    const std::chrono::duration<double> bt_elapsed =
        std::chrono::steady_clock::now() - bt_start;
    std::cout << "bootstrapping keys complete (" << bt_elapsed.count() << " s)\n";

    std::cout << "encrypting full round-polymorphic schedule...\n";
    std::vector<LWECiphertext> encrypted_program_bits;
    const auto enc_start = std::chrono::steady_clock::now();
    {
        Heartbeat heartbeat("schedule encryption");
        encrypted_program_bits = v0id::integrity::encrypt_plain_bits(
            cc, sk, plain_schedule_bits);
    }
    const std::chrono::duration<double> enc_elapsed =
        std::chrono::steady_clock::now() - enc_start;
    std::cout << "schedule encryption complete (" << enc_elapsed.count() << " s)\n";

    std::vector<int> initial_state(PUBLIC_STATES, 0);
    initial_state.at(schedule.initial_state) = 1;
    const auto encrypted_state =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_state);

    std::vector<int> initial_head(TAPE_CELLS, 0);
    initial_head[0] = 1;
    const auto encrypted_head =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_head);
    const auto encrypted_tape =
        v0id::integrity::encrypt_plain_bits(cc, sk, input);

    const auto encrypted_nonce = v0id::integrity::encrypt_u32_bits(
        cc, sk, schedule.manifest.integrity_nonce);
    const auto encrypted_fp_state = v0id::integrity::encrypt_u32_bits(
        cc, sk, v0id::integrity::TOY_FINGERPRINT_INITIAL_STATE);

    // The self-fingerprint now binds the complete ordered transition schedule,
    // not one stable program table. This is still the deliberately toy mixer;
    // it exists to exercise the architecture before a real Keccak/KMAC circuit.
    std::cout << "homomorphically fingerprinting the complete encrypted schedule...\n";
    v0id::integrity::EncryptedDigest32 encrypted_fingerprint{};
    const auto fp_start = std::chrono::steady_clock::now();
    {
        Heartbeat heartbeat("encrypted schedule fingerprint");
        encrypted_fingerprint = v0id::integrity::toy_fingerprint32_fhe(
            cc, encrypted_program_bits, encrypted_tape,
            encrypted_nonce, encrypted_fp_state);
    }
    const std::chrono::duration<double> fp_elapsed =
        std::chrono::steady_clock::now() - fp_start;
    std::cout << "encrypted schedule fingerprint complete ("
              << fp_elapsed.count() << " s)\n";

    const auto recovered_fingerprint = v0id::integrity::decrypt_u32_bits(
        cc, sk, encrypted_fingerprint);
    require(recovered_fingerprint == expected_fingerprint,
            "encrypted schedule fingerprint does not match client reference");
    std::cout << "[PASS] evaluator homomorphically fingerprints the exact ordered hidden schedule\n";

    const PublicMachineShape shape{
        PUBLIC_STATES,
        TAPE_CELLS,
        REQUESTED_ROUNDS,
        INTEGRITY_SLOTS,
    };

    std::cout << "running honest 4/4 scheduled FHE execution...\n";
    RemoteEncryptedMachine honest(
        cc, shape, encrypted_program_bits, encrypted_state,
        encrypted_head, encrypted_tape, cc.Encrypt(sk, 0));
    require(honest.uses_round_schedule(),
            "remote machine failed to recognize concatenated round schedule");

    for (std::size_t round = 0; round < REQUESTED_ROUNDS; ++round) {
        const auto label = "honest round " + std::to_string(round + 1) + "/" +
                           std::to_string(REQUESTED_ROUNDS);
        std::cout << "  [honest] round " << (round + 1) << '/' << REQUESTED_ROUNDS
                  << " starting...\n";
        const auto round_start = std::chrono::steady_clock::now();
        {
            Heartbeat heartbeat(label);
            honest.step();
        }
        const std::chrono::duration<double> round_elapsed =
            std::chrono::steady_clock::now() - round_start;
        std::cout << "  [honest] round " << (round + 1) << '/' << REQUESTED_ROUNDS
                  << " done (" << round_elapsed.count() << " s)\n";
    }

    const auto honest_tape = decrypt_bits(cc, sk, honest.tape_bits());
    const auto honest_state = decode_one_hot(
        decrypt_bits(cc, sk, honest.state_bits()), "honest final state");
    require(honest_tape == plain_four.tape,
            "honest scheduled FHE execution returned wrong semantic tape");
    require(honest_state == expected_four_state,
            "honest scheduled FHE execution returned wrong boundary-4 state encoding");
    std::cout << "[PASS] honest 4/4 evaluator returns correct tape AND boundary-4 hidden state\n";

    std::cout << "running malicious 2/4 scheduled FHE execution...\n";
    RemoteEncryptedMachine early(
        cc, shape, encrypted_program_bits, encrypted_state,
        encrypted_head, encrypted_tape, cc.Encrypt(sk, 0));

    for (std::size_t round = 0; round < 2; ++round) {
        const auto label = "2/4 evaluator round " + std::to_string(round + 1) + "/2";
        std::cout << "  [2/4] round " << (round + 1) << "/2 starting...\n";
        const auto round_start = std::chrono::steady_clock::now();
        {
            Heartbeat heartbeat(label);
            early.step();
        }
        const std::chrono::duration<double> round_elapsed =
            std::chrono::steady_clock::now() - round_start;
        std::cout << "  [2/4] round " << (round + 1) << "/2 done ("
                  << round_elapsed.count() << " s)\n";
    }

    const auto early_tape = decrypt_bits(cc, sk, early.tape_bits());
    const auto early_state = decode_one_hot(
        decrypt_bits(cc, sk, early.state_bits()), "2/4 final state");

    require(early_tape == plain_four.tape,
            "benchmark lost the intended same-output 2/4 condition under FHE");
    require(early_state == expected_two_state,
            "2/4 evaluator did not remain in boundary-2 hidden state encoding");
    require(early_state != expected_four_state,
            "2/4 evaluator accidentally matches requested boundary-4 hidden state");

    std::cout << "[BREAK-CLOSED] 2/4 evaluator still has the accepted semantic tape\n"
              << "[PASS]          but its encrypted machine state decrypts to boundary 2, not boundary 4\n\n"
              << "Boundary: this closes the concrete skip-and-stop fixed-point cheat for\n"
              << "the round-polymorphic representation. It is NOT a proof that no faster\n"
              << "equivalent encrypted-state transform exists; such structural shortcuts\n"
              << "remain UNCERTAIN and belong in the attacker harness.\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID round-polymorphic FHE harness failure: " << e.what() << '\n';
    return 1;
}
