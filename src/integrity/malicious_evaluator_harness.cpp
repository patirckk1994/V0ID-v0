#include "program.hpp"
#include "program_morpher.hpp"
#include "remote_machine.hpp"
#include "toy_fingerprint.hpp"

#include "binfhecontext.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

using namespace lbcrypto;
using v0id::core::Program;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteEncryptedMachine;
using v0id::integrity::EncryptedDigest32;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;

constexpr std::size_t PUBLIC_STATES = 4;
constexpr std::size_t TAPE_CELLS = 8;
constexpr std::size_t REQUESTED_ROUNDS = 4;
constexpr std::size_t INTEGRITY_SLOTS = 4;

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

std::vector<int> execute_rounds(BinFHEContext& cc,
                                const LWEPrivateKey& sk,
                                const PublicMachineShape& shape,
                                const EncryptedStart& start,
                                std::size_t actual_rounds) {
    RemoteEncryptedMachine machine(
        cc,
        shape,
        start.program,
        start.state,
        start.head,
        start.tape,
        cc.Encrypt(sk, 0));

    for (std::size_t round = 0; round < actual_rounds; ++round)
        machine.step();

    return decrypt_bits(cc, sk, machine.tape_bits());
}

} // namespace

int main() try {
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

    const auto morph = ProgramMorpher::morph(
        increment, 0, PUBLIC_STATES, seed, INTEGRITY_SLOTS);

    const PublicMachineShape shape{
        PUBLIC_STATES,
        TAPE_CELLS,
        REQUESTED_ROUNDS,
        INTEGRITY_SLOTS,
    };

    const auto expected_full = run_plaintext(
        morph.program, morph.initial_state, input, REQUESTED_ROUNDS);
    const auto expected_two = run_plaintext(
        morph.program, morph.initial_state, input, 2);
    const auto expected_one = run_plaintext(
        morph.program, morph.initial_state, input, 1);

    if (expected_two != expected_full)
        throw std::runtime_error(
            "benchmark program no longer reaches the same output after two rounds");
    if (expected_one == expected_full)
        throw std::runtime_error(
            "benchmark program unexpectedly reaches full output after one round");

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128Q);
    const auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    EncryptedStart start;
    start.program = v0id::integrity::encrypt_plain_bits(
        cc, sk, v0id::integrity::canonical_program_bits(morph.program));

    std::vector<int> state(PUBLIC_STATES, 0);
    state.at(morph.initial_state) = 1;
    start.state = v0id::integrity::encrypt_plain_bits(cc, sk, state);

    std::vector<int> head(TAPE_CELLS, 0);
    head[0] = 1;
    start.head = v0id::integrity::encrypt_plain_bits(cc, sk, head);
    start.tape = v0id::integrity::encrypt_plain_bits(cc, sk, input);

    // This is the current legacy integrity plumbing. Crucially, it commits to the
    // encrypted program + initial input, not to having executed every round.
    const auto expected_digest = v0id::integrity::toy_fingerprint32_plain(
        morph.program, input, morph.manifest.integrity_nonce);
    const auto encrypted_nonce = v0id::integrity::encrypt_u32_bits(
        cc, sk, morph.manifest.integrity_nonce);
    const auto encrypted_initial = v0id::integrity::encrypt_u32_bits(
        cc, sk, v0id::integrity::TOY_FINGERPRINT_INITIAL_STATE);
    const auto encrypted_digest = v0id::integrity::toy_fingerprint32_fhe(
        cc, start.program, start.tape, encrypted_nonce, encrypted_initial);

    std::vector<EncryptedDigest32> candidates;
    candidates.reserve(morph.manifest.integrity_output_masks.size());
    for (const auto mask : morph.manifest.integrity_output_masks) {
        const auto encrypted_mask = v0id::integrity::encrypt_u32_bits(cc, sk, mask);
        candidates.push_back(v0id::integrity::mask_digest_fhe(
            cc, encrypted_digest, encrypted_mask));
    }

    const auto slot = morph.manifest.integrity_output_slot;
    const auto masked = v0id::integrity::decrypt_u32_bits(
        cc, sk, candidates.at(slot));
    const auto recovered_digest =
        masked ^ morph.manifest.integrity_output_masks.at(slot);
    if (recovered_digest != expected_digest)
        throw std::runtime_error("legacy fingerprint plumbing failed positive control");

    std::cout << "V0ID malicious evaluator execution-soundness harness\n"
              << "  requested rounds        : " << REQUESTED_ROUNDS << '\n'
              << "  FHE profile             : OpenFHE BinFHE STD128Q\n"
              << "  current semantic checks : final plaintext result + legacy FHE fingerprint\n\n";

    const auto honest = execute_rounds(
        cc, sk, shape, start, REQUESTED_ROUNDS);
    if (honest != expected_full)
        throw std::runtime_error("honest evaluator failed expected output");
    std::cout << "[PASS] honest evaluator executes all 4 rounds and returns expected output\n";

    const auto skip_half = execute_rounds(cc, sk, shape, start, 2);
    if (skip_half != expected_full)
        throw std::runtime_error("two-round cheat no longer reproduces final output");
    std::cout << "[BREAK] evaluator executes only 2/4 rounds and returns the SAME accepted output\n";
    std::cout << "[BREAK] legacy encrypted fingerprint still passes because it is independent of round execution\n";

    const auto one_round = execute_rounds(cc, sk, shape, start, 1);
    if (one_round == expected_full)
        throw std::runtime_error("one-round negative control unexpectedly accepted");
    std::cout << "[PASS] one-round early return changes output and is caught by known-output comparison\n";

    std::cout << "\nV0ID execution soundness: FAIL / OPEN\n"
              << "Current checks cannot prove that the evaluator performed the requested round budget.\n"
              << "The 2/4-round evaluator is a concrete malicious strategy that preserves both the\n"
              << "expected final output for this job and the legacy integrity check. This is the\n"
              << "execution-proof target; quine/job commitments do not close it.\n";

    // Exit 1 intentionally: the harness has found the known architectural break.
    return 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID malicious evaluator harness fatal error: " << e.what() << '\n';
    return 2;
}
