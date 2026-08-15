#include "program.hpp"
#include "program_morpher.hpp"
#include "remote_machine.hpp"
#include "toy_fingerprint.hpp"

#include "binfhecontext.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
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
    cc.BTKeyGen(sk);

    std::cout << "encrypting full round-polymorphic schedule...\n";
    const auto encrypted_program_bits = v0id::integrity::encrypt_plain_bits(
        cc, sk, plain_schedule_bits);

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
    const auto encrypted_fingerprint = v0id::integrity::toy_fingerprint32_fhe(
        cc, encrypted_program_bits, encrypted_tape,
        encrypted_nonce, encrypted_fp_state);
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
    honest.run_fixed();

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
    early.step();
    early.step();

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
