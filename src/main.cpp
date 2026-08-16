#include "program.hpp"
#include "program_morpher.hpp"

#include "binfhecontext.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace lbcrypto;
using v0id::core::Program;
using v0id::polymorph::MorphedProgram;
using v0id::polymorph::ProgramMorpher;

struct EncryptedTransition {
    std::vector<LWECiphertext> next_state;
    LWECiphertext write_one;
    LWECiphertext move_left;
    LWECiphertext move_stay;
    LWECiphertext move_right;
};

class EncryptedProgram {
public:
    static EncryptedProgram encrypt(BinFHEContext& cc,
                                    const LWEPrivateKey& sk,
                                    const Program& plain) {
        plain.validate();
        std::vector<EncryptedTransition> table;
        table.reserve(plain.states * 2);
        for (std::size_t q = 0; q < plain.states; ++q) {
            for (int read = 0; read <= 1; ++read) {
                const auto& r = plain.rule(q, read);
                EncryptedTransition t;
                t.next_state.reserve(plain.states);
                for (std::size_t q2 = 0; q2 < plain.states; ++q2)
                    t.next_state.push_back(cc.Encrypt(sk, q2 == r.next_state ? 1 : 0));
                t.write_one = cc.Encrypt(sk, r.write == 1 ? 1 : 0);
                t.move_left = cc.Encrypt(sk, r.move < 0 ? 1 : 0);
                t.move_stay = cc.Encrypt(sk, r.move == 0 ? 1 : 0);
                t.move_right = cc.Encrypt(sk, r.move > 0 ? 1 : 0);
                table.push_back(std::move(t));
            }
        }
        return EncryptedProgram(plain.states, std::move(table));
    }

    std::size_t states() const { return states_; }

    const EncryptedTransition& transition(std::size_t state, int read) const {
        if (state >= states_ || (read != 0 && read != 1))
            throw std::runtime_error("encrypted transition index out of range");
        return table_.at(state * 2 + static_cast<std::size_t>(read));
    }

private:
    EncryptedProgram(std::size_t states, std::vector<EncryptedTransition> table)
        : states_(states), table_(std::move(table)) {}

    std::size_t states_{};
    std::vector<EncryptedTransition> table_;
};

class TapeRemapper {
public:
    using Key = std::array<unsigned char, 32>;

    TapeRemapper(const Key& key, std::uint64_t epoch, std::size_t n)
        : key_(key), epoch_(epoch), forward_(n), inverse_(n) {
        std::iota(forward_.begin(), forward_.end(), std::size_t{0});
        for (std::size_t i = n; i > 1; --i)
            std::swap(forward_[i - 1], forward_[static_cast<std::size_t>(uniform(i))]);
        for (std::size_t logical = 0; logical < n; ++logical)
            inverse_[forward_[logical]] = logical;
    }

    std::size_t physical(std::size_t logical) const { return forward_.at(logical); }
    std::size_t logical(std::size_t physical) const { return inverse_.at(physical); }
    std::size_t size() const { return forward_.size(); }

private:
    static void put_u64(std::array<unsigned char, 24>& msg, std::size_t off, std::uint64_t v) {
        for (int i = 7; i >= 0; --i)
            msg[off + static_cast<std::size_t>(7 - i)] =
                static_cast<unsigned char>((v >> (i * 8)) & 0xffu);
    }

    std::uint64_t next64() {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
        if (!mac) throw std::runtime_error("OpenSSL KMAC-256 unavailable");
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx) throw std::runtime_error("EVP_MAC_CTX_new failed");

        std::array<unsigned char, 24> msg{};
        put_u64(msg, 0, 0x563049442d524d50ULL);
        put_u64(msg, 8, epoch_);
        put_u64(msg, 16, counter_++);
        std::array<unsigned char, 64> out{};
        std::size_t out_len = 0;
        const bool ok = EVP_MAC_init(ctx, key_.data(), key_.size(), nullptr) == 1 &&
                        EVP_MAC_update(ctx, msg.data(), msg.size()) == 1 &&
                        EVP_MAC_final(ctx, out.data(), &out_len, out.size()) == 1;
        EVP_MAC_CTX_free(ctx);
        if (!ok || out_len < 8) throw std::runtime_error("KMAC-256 failed");

        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i) x = (x << 8) | out[static_cast<std::size_t>(i)];
        return x;
    }

    std::uint64_t uniform(std::uint64_t bound) {
        if (!bound) throw std::runtime_error("zero remap bound");
        const std::uint64_t threshold = (std::uint64_t{0} - bound) % bound;
        for (;;) {
            const auto x = next64();
            if (x >= threshold) return x % bound;
        }
    }

    Key key_;
    std::uint64_t epoch_{};
    std::uint64_t counter_{};
    std::vector<std::size_t> forward_, inverse_;
};

class EncryptedMachine {
public:
    EncryptedMachine(BinFHEContext& cc, const LWEPrivateKey& sk,
                     EncryptedProgram program,
                     const std::vector<int>& tape, std::size_t initial_state,
                     std::size_t initial_head, TapeRemapper::Key remap_key,
                     std::uint64_t epoch)
        : cc_(cc), program_(std::move(program)), remap_key_(remap_key),
          map_(remap_key_, epoch, tape.size()) {
        if (tape.empty() || initial_state >= program_.states() || initial_head >= tape.size())
            throw std::runtime_error("invalid initial machine state");

        zero_ = cc_.Encrypt(sk, 0);
        state_.resize(program_.states());
        head_.resize(tape.size());
        physical_tape_.resize(tape.size());
        for (std::size_t q = 0; q < state_.size(); ++q)
            state_[q] = cc_.Encrypt(sk, q == initial_state ? 1 : 0);
        for (std::size_t i = 0; i < head_.size(); ++i)
            head_[i] = cc_.Encrypt(sk, i == initial_head ? 1 : 0);
        for (std::size_t i = 0; i < tape.size(); ++i) {
            if (tape[i] != 0 && tape[i] != 1) throw std::runtime_error("tape is binary");
            physical_tape_[map_.physical(i)] = cc_.Encrypt(sk, tape[i]);
        }
    }

    void step() {
        const std::size_t n = head_.size();
        const std::size_t states = program_.states();
        std::vector<LWECiphertext> next_state(states, zero_);
        std::vector<LWECiphertext> next_head(n, zero_);
        std::vector<LWECiphertext> write_any(n, zero_);
        std::vector<LWECiphertext> write_one(n, zero_);
        std::vector<LWECiphertext> not_tape(n);
        for (std::size_t i = 0; i < n; ++i)
            not_tape[i] = cc_.EvalNOT(tape(i));

        for (std::size_t i = 0; i < n; ++i) {
            for (std::size_t q = 0; q < states; ++q) {
                for (int read = 0; read <= 1; ++read) {
                    auto active = And(state_[q], head_[i]);
                    active = And(active, read ? tape(i) : not_tape[i]);
                    const auto& t = program_.transition(q, read);
                    for (std::size_t q2 = 0; q2 < states; ++q2)
                        next_state[q2] = Or(next_state[q2], And(active, t.next_state[q2]));
                    write_any[i] = Or(write_any[i], active);
                    write_one[i] = Or(write_one[i], And(active, t.write_one));
                    const std::size_t left = i > 0 ? i - 1 : i;
                    const std::size_t right = i + 1 < n ? i + 1 : i;
                    next_head[left] = Or(next_head[left], And(active, t.move_left));
                    next_head[i] = Or(next_head[i], And(active, t.move_stay));
                    next_head[right] = Or(next_head[right], And(active, t.move_right));
                }
            }
        }

        std::vector<LWECiphertext> next_tape(n);
        for (std::size_t i = 0; i < n; ++i) {
            auto keep_old = And(cc_.EvalNOT(write_any[i]), tape(i));
            next_tape[i] = Or(write_one[i], keep_old);
        }
        state_ = std::move(next_state);
        head_ = std::move(next_head);
        for (std::size_t i = 0; i < n; ++i)
            physical_tape_[map_.physical(i)] = std::move(next_tape[i]);
    }

    void run_fixed(std::size_t steps, std::uint64_t remap_epoch_after_first_step = 0) {
        for (std::size_t s = 0; s < steps; ++s) {
            step();
            if (s == 0 && remap_epoch_after_first_step != 0)
                remap(remap_epoch_after_first_step);
        }
    }

    void remap(std::uint64_t epoch) {
        TapeRemapper next(remap_key_, epoch, map_.size());
        std::vector<LWECiphertext> moved(map_.size());
        for (std::size_t logical = 0; logical < map_.size(); ++logical)
            moved[next.physical(logical)] = std::move(physical_tape_[map_.physical(logical)]);
        physical_tape_ = std::move(moved);
        map_ = std::move(next);
    }

    std::vector<int> decrypt_tape(const LWEPrivateKey& sk) {
        std::vector<int> out(map_.size());
        for (std::size_t i = 0; i < out.size(); ++i) {
            LWEPlaintext p{};
            cc_.Decrypt(sk, tape(i), &p);
            out[i] = static_cast<int>(p & 1);
        }
        return out;
    }

private:
    LWECiphertext& tape(std::size_t logical) { return physical_tape_[map_.physical(logical)]; }
    LWECiphertext And(const LWECiphertext& a, const LWECiphertext& b) {
        return cc_.EvalBinGate(AND, a, b);
    }
    LWECiphertext Or(const LWECiphertext& a, const LWECiphertext& b) {
        return cc_.EvalBinGate(OR, a, b);
    }

    BinFHEContext& cc_;
    EncryptedProgram program_;
    TapeRemapper::Key remap_key_{};
    TapeRemapper map_;
    LWECiphertext zero_;
    std::vector<LWECiphertext> state_, head_, physical_tape_;
};

static void print_msb_first(const std::vector<int>& bits) {
    for (auto it = bits.rbegin(); it != bits.rend(); ++it) std::cout << *it;
    std::cout << '\n';
}

static void print_state_map(const std::string& name, const MorphedProgram& morph) {
    std::cout << name << " state map    : ";
    for (std::size_t q = 0; q < morph.manifest.base_to_morphed.size(); ++q) {
        if (q) std::cout << ", ";
        std::cout << q << "->" << morph.manifest.base_to_morphed[q];
    }
    std::cout << " | dummy=";
    for (std::size_t i = 0; i < morph.manifest.dummy_states.size(); ++i) {
        if (i) std::cout << ',';
        std::cout << morph.manifest.dummy_states[i];
    }
    std::cout << '\n';
}

static std::vector<int> run_plaintext(const Program& program,
                                      std::size_t initial_state,
                                      const std::vector<int>& input,
                                      std::size_t steps) {
    program.validate();
    if (input.empty() || initial_state >= program.states)
        throw std::runtime_error("invalid plaintext machine input");
    auto tape = input;
    std::size_t state = initial_state;
    std::size_t head = 0;
    for (std::size_t s = 0; s < steps; ++s) {
        const auto& r = program.rule(state, tape.at(head));
        tape[head] = r.write;
        state = r.next_state;
        if (r.move < 0 && head > 0) --head;
        else if (r.move > 0 && head + 1 < tape.size()) ++head;
    }
    return tape;
}

static void require_plain_equivalent(const std::string& name,
                                     const MorphedProgram& morph,
                                     const std::vector<int>& input,
                                     const std::vector<int>& expected,
                                     std::size_t steps) {
    if (run_plaintext(morph.program, morph.initial_state, input, steps) != expected)
        throw std::runtime_error(name + " plaintext morph mismatch");
}

static void run_fhe_case(BinFHEContext& cc,
                         const LWEPrivateKey& sk,
                         const TapeRemapper::Key& remap_key,
                         const std::string& name,
                         const MorphedProgram& morph,
                         const std::vector<int>& input,
                         const std::vector<int>& expected,
                         std::size_t fixed_steps) {
    auto encrypted_program = EncryptedProgram::encrypt(cc, sk, morph.program);
    EncryptedMachine machine(cc, sk, std::move(encrypted_program), input,
                             morph.initial_state, 0, remap_key, 1);
    machine.run_fixed(fixed_steps, 2);
    auto output = machine.decrypt_tape(sk);
    std::cout << name << " output      : ";
    print_msb_first(output);
    if (output != expected)
        throw std::runtime_error(name + " encrypted morph result mismatch");
}

int main() try {
    constexpr std::size_t FIXED_STEPS = 4;
    constexpr std::size_t PUBLIC_STATES = 4;

    Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
    Program decrement{2, {
        {0, 0, 0, 1, +1},
        {0, 1, 1, 0,  0},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};

    const std::vector<int> input{1,0,1,1,0,0,0,0};
    const std::vector<int> expected_inc{0,1,1,1,0,0,0,0};
    const std::vector<int> expected_dec{0,0,1,1,0,0,0,0};

    if (run_plaintext(increment, 0, input, FIXED_STEPS) != expected_inc ||
        run_plaintext(decrement, 0, input, FIXED_STEPS) != expected_dec)
        throw std::runtime_error("base plaintext reference program mismatch");

    auto inc_a = ProgramMorpher::morph(
        increment, 0, PUBLIC_STATES, ProgramMorpher::random_seed());
    auto inc_b = ProgramMorpher::morph(
        increment, 0, PUBLIC_STATES, ProgramMorpher::random_seed());
    for (int retry = 0;
         retry < 32 && inc_b.manifest.base_to_morphed == inc_a.manifest.base_to_morphed;
         ++retry) {
        inc_b = ProgramMorpher::morph(
            increment, 0, PUBLIC_STATES, ProgramMorpher::random_seed());
    }
    if (inc_b.manifest.base_to_morphed == inc_a.manifest.base_to_morphed)
        throw std::runtime_error("failed to generate visibly distinct increment morphs");

    auto dec_a = ProgramMorpher::morph(
        decrement, 0, PUBLIC_STATES, ProgramMorpher::random_seed());
    if (inc_a.program.states != PUBLIC_STATES ||
        inc_b.program.states != PUBLIC_STATES ||
        dec_a.program.states != PUBLIC_STATES)
        throw std::runtime_error("morph leaked variable public shape");

    require_plain_equivalent("increment morph A", inc_a, input, expected_inc, FIXED_STEPS);
    require_plain_equivalent("increment morph B", inc_b, input, expected_inc, FIXED_STEPS);
    require_plain_equivalent("decrement morph A", dec_a, input, expected_dec, FIXED_STEPS);

    std::cout << "input               : ";
    print_msb_first(input);
    std::cout << "public state count  : " << PUBLIC_STATES << '\n'
              << "fixed round budget  : " << FIXED_STEPS << '\n';
    print_state_map("increment morph A", inc_a);
    print_state_map("increment morph B", inc_b);
    print_state_map("decrement morph A", dec_a);
    std::cout << "plaintext morph equivalence: OK\n";

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    std::cout << "generating OpenFHE bootstrapping keys...\n";
    cc.BTKeyGen(sk);

    TapeRemapper::Key remap_key{};
    if (RAND_bytes(remap_key.data(), static_cast<int>(remap_key.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");

    run_fhe_case(cc, sk, remap_key, "encrypted inc morph A", inc_a,
                 input, expected_inc, FIXED_STEPS);
    run_fhe_case(cc, sk, remap_key, "encrypted inc morph B", inc_b,
                 input, expected_inc, FIXED_STEPS);
    run_fhe_case(cc, sk, remap_key, "encrypted dec morph A", dec_a,
                 input, expected_dec, FIXED_STEPS);

    std::cout << "OK: precomputed polymorphism preserves semantics\n"
                 "    + KMAC-derived secret state-label permutation\n"
                 "    + fixed-size dummy-state padding\n"
                 "    + client-only morph manifest\n"
                 "    + identical public evaluator dimensions across morphs\n"
                 "    + exact encrypted state/tape semantics\n"
                 "    + ciphertext-only epoch remap\n"
                 "    + ToyFingerprint removed; SHA3/round-receipt work owns integrity\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID error: " << e.what() << '\n';
    return 1;
}
