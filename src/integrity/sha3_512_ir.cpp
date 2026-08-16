#include "sha3_512_ir.hpp"

#include "keccak_ir.hpp"

#include <array>
#include <stdexcept>

namespace v0id::integrity {

Sha3_512IR build_sha3_512_ir(std::size_t message_bytes) {
    Sha3_512IR out;
    out.message_bytes = message_bytes;
    out.absorb_blocks = message_bytes / kSha3_512RateBytes + 1;

    std::vector<BoolWire> message_bits;
    message_bits.reserve(message_bytes * 8);
    for (std::size_t i = 0; i < message_bytes * 8; ++i)
        message_bits.push_back(out.ir.add_input());

    const auto zero = out.ir.constant(false);
    const auto one = out.ir.constant(true);

    KeccakStateWires state{};
    state.fill(zero);

    const std::size_t padded_bytes = out.absorb_blocks * kSha3_512RateBytes;
    for (std::size_t block = 0; block < out.absorb_blocks; ++block) {
        for (std::size_t byte = 0; byte < kSha3_512RateBytes; ++byte) {
            const std::size_t global_byte = block * kSha3_512RateBytes + byte;
            for (std::size_t bit = 0; bit < 8; ++bit) {
                BoolWire absorbed = zero;
                if (global_byte < message_bytes) {
                    absorbed = message_bits[global_byte * 8 + bit];
                } else {
                    std::uint8_t pad = 0;
                    if (global_byte == message_bytes)
                        pad ^= 0x06u; // SHA-3 domain separation + first pad bit
                    if (global_byte + 1 == padded_bytes)
                        pad ^= 0x80u; // final pad bit
                    if (((pad >> bit) & 1u) != 0)
                        absorbed = one;
                }

                if (absorbed != zero) {
                    const std::size_t state_bit = byte * 8 + bit;
                    state[state_bit] = out.ir.bit_xor(state[state_bit], absorbed);
                }
            }
        }
        state = append_keccak_f1600(out.ir, state);
    }

    std::vector<BoolWire> digest;
    digest.reserve(kSha3_512DigestBytes * 8);
    for (std::size_t i = 0; i < kSha3_512DigestBytes * 8; ++i)
        digest.push_back(state[i]);
    out.ir.set_outputs(std::move(digest));
    out.ir.validate();
    return out;
}

std::vector<std::uint8_t> bytes_to_lsb_bits(
    const std::vector<std::uint8_t>& bytes) {
    std::vector<std::uint8_t> bits;
    bits.reserve(bytes.size() * 8);
    for (const auto byte : bytes)
        for (unsigned bit = 0; bit < 8; ++bit)
            bits.push_back(static_cast<std::uint8_t>((byte >> bit) & 1u));
    return bits;
}

std::vector<std::uint8_t> lsb_bits_to_bytes(
    const std::vector<std::uint8_t>& bits) {
    if ((bits.size() % 8) != 0)
        throw std::runtime_error("bit vector is not byte aligned");

    std::vector<std::uint8_t> bytes(bits.size() / 8, 0);
    for (std::size_t i = 0; i < bits.size(); ++i)
        if (bits[i] != 0)
            bytes[i / 8] |= static_cast<std::uint8_t>(1u << (i % 8));
    return bytes;
}

} // namespace v0id::integrity
