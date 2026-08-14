#include "program_morpher.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <cstdint>
#include <numeric>
#include <stdexcept>
#include <utility>
#include <vector>

namespace v0id::polymorph {
namespace {

class KmacMorphRng {
public:
    explicit KmacMorphRng(const MorphSeed& seed) : key_(seed) {}

    std::uint64_t uniform(std::uint64_t bound) {
        if (bound == 0)
            throw std::runtime_error("zero morph bound");

        const std::uint64_t threshold = (std::uint64_t{0} - bound) % bound;
        for (;;) {
            const auto x = next64();
            if (x >= threshold)
                return x % bound;
        }
    }

private:
    static void put_u64(std::array<unsigned char, 24>& msg,
                        std::size_t offset,
                        std::uint64_t value) {
        for (int i = 7; i >= 0; --i) {
            msg[offset + static_cast<std::size_t>(7 - i)] =
                static_cast<unsigned char>((value >> (i * 8)) & 0xffu);
        }
    }

    std::uint64_t next64() {
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);
        if (!mac)
            throw std::runtime_error("OpenSSL KMAC-256 unavailable");

        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx)
            throw std::runtime_error("EVP_MAC_CTX_new failed");

        std::array<unsigned char, 24> msg{};
        constexpr char domain[] = "V0ID-MORPH-v1";
        for (std::size_t i = 0; i < sizeof(domain) - 1 && i < 16; ++i)
            msg[i] = static_cast<unsigned char>(domain[i]);
        put_u64(msg, 16, counter_++);

        std::array<unsigned char, 64> out{};
        std::size_t out_len = 0;
        const bool ok = EVP_MAC_init(ctx, key_.data(), key_.size(), nullptr) == 1 &&
                        EVP_MAC_update(ctx, msg.data(), msg.size()) == 1 &&
                        EVP_MAC_final(ctx, out.data(), &out_len, out.size()) == 1;
        EVP_MAC_CTX_free(ctx);

        if (!ok || out_len < 8)
            throw std::runtime_error("KMAC-256 morph RNG failed");

        std::uint64_t x = 0;
        for (int i = 0; i < 8; ++i)
            x = (x << 8) | out[static_cast<std::size_t>(i)];
        return x;
    }

    MorphSeed key_{};
    std::uint64_t counter_{};
};

} // namespace

MorphSeed ProgramMorpher::random_seed() {
    MorphSeed seed{};
    if (RAND_bytes(seed.data(), static_cast<int>(seed.size())) != 1)
        throw std::runtime_error("RAND_bytes failed while generating morph seed");
    return seed;
}

MorphedProgram ProgramMorpher::morph(const v0id::core::Program& base,
                                     std::size_t base_initial_state,
                                     std::size_t public_state_count,
                                     const MorphSeed& seed) {
    base.validate();

    if (base_initial_state >= base.states)
        throw std::runtime_error("base initial state out of range");
    if (public_state_count < base.states)
        throw std::runtime_error("public state count smaller than base program");

    KmacMorphRng rng(seed);

    std::vector<std::size_t> slots(public_state_count);
    std::iota(slots.begin(), slots.end(), std::size_t{0});
    for (std::size_t i = slots.size(); i > 1; --i)
        std::swap(slots[i - 1], slots[static_cast<std::size_t>(rng.uniform(i))]);

    MorphedProgram out;
    out.program.states = public_state_count;
    out.program.rules.resize(public_state_count * 2);
    out.base_to_morphed.resize(base.states);

    for (std::size_t q = 0; q < base.states; ++q)
        out.base_to_morphed[q] = slots[q];

    for (std::size_t q = base.states; q < slots.size(); ++q)
        out.dummy_states.push_back(slots[q]);

    // Start from a complete fixed-size table of harmless identity states. Since
    // the universal evaluator visits every public state every round, padding also
    // pads evaluator work rather than introducing a variable-size side channel.
    for (std::size_t state = 0; state < public_state_count; ++state) {
        for (int read = 0; read <= 1; ++read) {
            out.program.rules[state * 2 + static_cast<std::size_t>(read)] =
                v0id::core::Rule{state, read, state, read, 0};
        }
    }

    // Rewrite every semantic transition through the secret state-label mapping.
    for (const auto& r : base.rules) {
        const auto state = out.base_to_morphed[r.state];
        const auto next_state = out.base_to_morphed[r.next_state];
        out.program.rules[state * 2 + static_cast<std::size_t>(r.read)] =
            v0id::core::Rule{state, r.read, next_state, r.write, r.move};
    }

    out.initial_state = out.base_to_morphed[base_initial_state];
    out.program.validate();
    return out;
}

} // namespace v0id::polymorph
