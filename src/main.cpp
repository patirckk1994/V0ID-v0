#include "binfhecontext.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <utility>
#include <vector>

using namespace lbcrypto;

struct Rule {
    std::size_t state;
    int read;
    std::size_t next_state;
    int write;
    int move; // -1, 0, +1
};

struct Program {
    std::size_t states;
    std::vector<Rule> rules;

    void validate() const {
        if (states == 0) throw std::runtime_error("program has no states");
        std::vector<int> seen(states * 2, 0);
        for (const auto& r : rules) {
            if (r.state >= states || r.next_state >= states ||
                (r.read != 0 && r.read != 1) ||
                (r.write != 0 && r.write != 1) ||
                r.move < -1 || r.move > 1)
                throw std::runtime_error("invalid transition rule");
            ++seen[r.state * 2 + static_cast<std::size_t>(r.read)];
        }
        for (int n : seen)
            if (n != 1) throw std::runtime_error("need exactly one rule per (state, bit)");
    }
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
        put_u64(msg, 0, 0x563049442d524d50ULL); // "V0ID-RMP"
        put_u64(msg, 8, epoch_);
        put_u64(msg, 16, counter_++);
        std::array<unsigned char, 64> out{};      // KMAC-256 default output
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
    EncryptedMachine(BinFHEContext& cc, const LWEPrivateKey& sk, Program program,
                     const std::vector<int>& tape, std::size_t initial_state,
                     std::size_t initial_head, TapeRemapper::Key remap_key,
                     std::uint64_t epoch)
        : cc_(cc), program_(std::move(program)), remap_key_(remap_key),
          map_(remap_key_, epoch, tape.size()) {
        program_.validate();
        if (tape.empty() || initial_state >= program_.states || initial_head >= tape.size())
            throw std::runtime_error("invalid initial machine state");

        zero_ = cc_.Encrypt(sk, 0);
        state_.resize(program_.states);
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
        std::vector<LWECiphertext> next_state(program_.states, zero_);
        std::vector<LWECiphertext> next_head(n, zero_);
        std::vector<LWECiphertext> write_any(n, zero_);
        std::vector<LWECiphertext> write_one(n, zero_);
        std::vector<LWECiphertext> not_tape(n);

        for (std::size_t i = 0; i < n; ++i) not_tape[i] = cc_.EvalNOT(tape(i));

        for (std::size_t i = 0; i < n; ++i) {
            for (const auto& r : program_.rules) {
                auto active = And(state_[r.state], head_[i]);
                active = And(active, r.read ? tape(i) : not_tape[i]);

                next_state[r.next_state] = Or(next_state[r.next_state], active);
                write_any[i] = Or(write_any[i], active);
                if (r.write) write_one[i] = Or(write_one[i], active);

                std::size_t dst = i;
                if (r.move < 0 && i > 0) dst = i - 1;
                if (r.move > 0 && i + 1 < n) dst = i + 1;
                next_head[dst] = Or(next_head[dst], active);
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
    Program program_;
    TapeRemapper::Key remap_key_{};
    TapeRemapper map_;
    LWECiphertext zero_;
    std::vector<LWECiphertext> state_, head_, physical_tape_;
};

static void print_msb_first(const std::vector<int>& bits) {
    for (auto it = bits.rbegin(); it != bits.rend(); ++it) std::cout << *it;
    std::cout << '\n';
}

int main() try {
    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128);
    auto sk = cc.KeyGen();
    std::cout << "generating OpenFHE bootstrapping keys...\n";
    cc.BTKeyGen(sk);

    TapeRemapper::Key remap_key{};
    if (RAND_bytes(remap_key.data(), static_cast<int>(remap_key.size())) != 1)
        throw std::runtime_error("RAND_bytes failed");

    // Runtime-supplied program: little-endian binary increment with carry.
    // state 0 = carry; state 1 = halted/self-loop.
    Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};

    std::vector<int> input{1,0,1,1,0,0,0,0}; // 00001101 = 13, LSB first
    std::cout << "input : ";
    print_msb_first(input);

    EncryptedMachine m(cc, sk, increment, input, 0, 0, remap_key, 1);
    m.step();
    m.remap(2); // ciphertext movement only
    m.step();   // no intermediate decryption

    auto output = m.decrypt_tape(sk);
    std::cout << "output: ";
    print_msb_first(output);

    if (output != std::vector<int>({0,1,1,1,0,0,0,0}))
        throw std::runtime_error("wrong encrypted-machine result");

    std::cout << "OK: exact encrypted transition + mid-run remap without intermediate decryption\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID error: " << e.what() << '\n';
    return 1;
}
