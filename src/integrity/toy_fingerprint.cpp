#include "toy_fingerprint.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace v0id::integrity {
namespace {

std::vector<int> append_nonce_bits(std::vector<int> bits, std::uint32_t nonce) {
    for (std::size_t i = 0; i < 32; ++i)
        bits.push_back(static_cast<int>((nonce >> i) & 1u));
    return bits;
}

void append_tape_bits(std::vector<int>& bits, const std::vector<int>& initial_tape) {
    for (int bit : initial_tape) {
        if (bit != 0 && bit != 1)
            throw std::runtime_error("toy fingerprint tape must be binary");
        bits.push_back(bit);
    }
}

std::uint32_t mix_plain(const std::vector<int>& source_bits) {
    if (source_bits.empty())
        throw std::runtime_error("toy fingerprint needs at least one source bit");

    std::array<int, 32> state{};
    for (std::size_t i = 0; i < state.size(); ++i)
        state[i] = static_cast<int>((TOY_FINGERPRINT_INITIAL_STATE >> i) & 1u);

    for (std::size_t i = 0; i < source_bits.size(); ++i) {
        const int x = source_bits[i] & 1;
        const std::size_t j = (i * 13 + 5) & 31u;
        const std::size_t k = (j + 7) & 31u;
        const std::size_t m = (j + 19) & 31u;

        const int t = state[j] ^ x;
        const int u = state[k] & x;
        state[j] = t;
        state[m] = state[m] ^ t ^ u;
    }

    std::array<int, 32> next{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        next[i] = state[i] ^
                  (state[(i + 7) & 31u] & state[(i + 13) & 31u]) ^
                  state[(i + 23) & 31u];
    }

    std::uint32_t out = 0;
    for (std::size_t i = 0; i < next.size(); ++i)
        out |= static_cast<std::uint32_t>(next[i] & 1) << i;
    return out;
}

} // namespace

std::vector<int> canonical_program_bits(const v0id::core::Program& program) {
    program.validate();

    std::vector<int> bits;
    bits.reserve(program.states * 2 * (program.states + 4));

    for (std::size_t q = 0; q < program.states; ++q) {
        for (int read = 0; read <= 1; ++read) {
            const auto& r = program.rule(q, read);

            for (std::size_t q2 = 0; q2 < program.states; ++q2)
                bits.push_back(q2 == r.next_state ? 1 : 0);

            bits.push_back(r.write == 1 ? 1 : 0);
            bits.push_back(r.move < 0 ? 1 : 0);
            bits.push_back(r.move == 0 ? 1 : 0);
            bits.push_back(r.move > 0 ? 1 : 0);
        }
    }

    return bits;
}

std::vector<int> canonical_program_schedule_bits(
    const std::vector<v0id::core::Program>& round_programs) {
    if (round_programs.empty())
        throw std::runtime_error("toy fingerprint schedule must not be empty");

    std::vector<int> bits;
    for (const auto& program : round_programs) {
        auto table = canonical_program_bits(program);
        bits.insert(bits.end(), table.begin(), table.end());
    }
    return bits;
}

std::uint32_t toy_fingerprint32_plain(const v0id::core::Program& program,
                                      const std::vector<int>& initial_tape,
                                      std::uint32_t nonce) {
    auto bits = canonical_program_bits(program);
    append_tape_bits(bits, initial_tape);
    return mix_plain(append_nonce_bits(std::move(bits), nonce));
}

std::uint32_t toy_fingerprint32_plain_schedule(
    const std::vector<v0id::core::Program>& round_programs,
    const std::vector<int>& initial_tape,
    std::uint32_t nonce) {
    auto bits = canonical_program_schedule_bits(round_programs);
    append_tape_bits(bits, initial_tape);
    return mix_plain(append_nonce_bits(std::move(bits), nonce));
}

std::vector<lbcrypto::LWECiphertext>
encrypt_plain_bits(lbcrypto::BinFHEContext& cc,
                   const lbcrypto::LWEPrivateKey& sk,
                   const std::vector<int>& bits) {
    std::vector<lbcrypto::LWECiphertext> out;
    out.reserve(bits.size());
    for (int bit : bits) {
        if (bit != 0 && bit != 1)
            throw std::runtime_error("cannot encrypt non-binary integrity bit");
        out.push_back(cc.Encrypt(sk, bit));
    }
    return out;
}

EncryptedDigest32 encrypt_u32_bits(lbcrypto::BinFHEContext& cc,
                                   const lbcrypto::LWEPrivateKey& sk,
                                   std::uint32_t value) {
    EncryptedDigest32 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = cc.Encrypt(sk, static_cast<int>((value >> i) & 1u));
    return out;
}

EncryptedDigest32 toy_fingerprint32_fhe(
    lbcrypto::BinFHEContext& cc,
    const std::vector<lbcrypto::LWECiphertext>& encrypted_program_bits,
    const std::vector<lbcrypto::LWECiphertext>& encrypted_initial_tape,
    const EncryptedDigest32& encrypted_nonce_bits,
    const EncryptedDigest32& encrypted_initial_state_bits) {

    std::vector<lbcrypto::LWECiphertext> source;
    source.reserve(encrypted_program_bits.size() + encrypted_initial_tape.size() +
                   encrypted_nonce_bits.size());
    source.insert(source.end(), encrypted_program_bits.begin(), encrypted_program_bits.end());
    source.insert(source.end(), encrypted_initial_tape.begin(), encrypted_initial_tape.end());
    source.insert(source.end(), encrypted_nonce_bits.begin(), encrypted_nonce_bits.end());

    if (source.empty())
        throw std::runtime_error("toy encrypted fingerprint needs source ciphertexts");

    // Each element was independently encrypted by the client. Do not synthesize
    // constants with EvalBinGate(ct, ct): BinFHE explicitly rejects identical
    // ciphertext operands, and aliasing a single zero/one object across state
    // positions could trigger the same check later in the mixing network.
    EncryptedDigest32 state = encrypted_initial_state_bits;

    for (std::size_t i = 0; i < source.size(); ++i) {
        const std::size_t j = (i * 13 + 5) & 31u;
        const std::size_t k = (j + 7) & 31u;
        const std::size_t m = (j + 19) & 31u;

        auto t = cc.EvalBinGate(lbcrypto::XOR, state[j], source[i]);
        auto u = cc.EvalBinGate(lbcrypto::AND, state[k], source[i]);
        auto v = cc.EvalBinGate(lbcrypto::XOR, state[m], t);
        state[j] = std::move(t);
        state[m] = cc.EvalBinGate(lbcrypto::XOR, v, u);
    }

    EncryptedDigest32 next{};
    for (std::size_t i = 0; i < state.size(); ++i) {
        auto nonlinear = cc.EvalBinGate(lbcrypto::AND,
                                        state[(i + 7) & 31u],
                                        state[(i + 13) & 31u]);
        auto a = cc.EvalBinGate(lbcrypto::XOR, state[i], nonlinear);
        next[i] = cc.EvalBinGate(lbcrypto::XOR, a, state[(i + 23) & 31u]);
    }

    return next;
}

EncryptedDigest32 mask_digest_fhe(lbcrypto::BinFHEContext& cc,
                                  const EncryptedDigest32& digest,
                                  const EncryptedDigest32& encrypted_mask_bits) {
    EncryptedDigest32 out{};
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = cc.EvalBinGate(lbcrypto::XOR, digest[i], encrypted_mask_bits[i]);
    return out;
}

std::uint32_t decrypt_u32_bits(lbcrypto::BinFHEContext& cc,
                               const lbcrypto::LWEPrivateKey& sk,
                               const EncryptedDigest32& bits) {
    std::uint32_t out = 0;
    for (std::size_t i = 0; i < bits.size(); ++i) {
        lbcrypto::LWEPlaintext p{};
        cc.Decrypt(sk, bits[i], &p);
        out |= static_cast<std::uint32_t>(p & 1) << i;
    }
    return out;
}

} // namespace v0id::integrity
