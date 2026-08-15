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

    std::uint32_t word32() {
        return static_cast<std::uint32_t>(next64() & 0xffffffffu);
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

std::vector<std::size_t> shuffled_slots(std::size_t count, KmacMorphRng& rng) {
    std::vector<std::size_t> slots(count);
    std::iota(slots.begin(), slots.end(), std::size_t{0});
    for (std::size_t i = slots.size(); i > 1; --i)
        std::swap(slots[i - 1], slots[static_cast<std::size_t>(rng.uniform(i))]);
    return slots;
}

std::size_t coprime_stride(std::size_t modulus, KmacMorphRng& rng) {
    if (modulus < 2)
        throw std::runtime_error("round-polymorphic morph needs at least two public states");

    for (;;) {
        const auto candidate =
            std::size_t{1} + static_cast<std::size_t>(rng.uniform(modulus - 1));
        if (std::gcd(candidate, modulus) == 1)
            return candidate;
    }
}

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
                                     const MorphSeed& seed,
                                     std::size_t integrity_candidate_count) {
    base.validate();

    if (base_initial_state >= base.states)
        throw std::runtime_error("base initial state out of range");
    if (public_state_count < base.states)
        throw std::runtime_error("public state count smaller than base program");
    if (integrity_candidate_count == 0)
        throw std::runtime_error("integrity candidate count must be positive");

    KmacMorphRng rng(seed);
    const auto slots = shuffled_slots(public_state_count, rng);

    MorphedProgram out;
    out.program.states = public_state_count;
    out.program.rules.resize(public_state_count * 2);
    out.manifest.base_to_morphed.resize(base.states);

    for (std::size_t q = 0; q < base.states; ++q)
        out.manifest.base_to_morphed[q] = slots[q];

    for (std::size_t q = base.states; q < slots.size(); ++q)
        out.manifest.dummy_states.push_back(slots[q]);

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
        const auto state = out.manifest.base_to_morphed[r.state];
        const auto next_state = out.manifest.base_to_morphed[r.next_state];
        out.program.rules[state * 2 + static_cast<std::size_t>(r.read)] =
            v0id::core::Rule{state, r.read, next_state, r.write, r.move};
    }

    out.initial_state = out.manifest.base_to_morphed[base_initial_state];

    // Client-only integrity metadata. None of these plaintext values belongs in
    // the evaluator protocol. The client will encrypt the nonce/masks before
    // outsourcing the integrity computation and keep the selected slot private.
    out.manifest.integrity_nonce = rng.word32();
    out.manifest.integrity_output_slot =
        static_cast<std::size_t>(rng.uniform(integrity_candidate_count));
    out.manifest.integrity_output_masks.reserve(integrity_candidate_count);
    for (std::size_t i = 0; i < integrity_candidate_count; ++i)
        out.manifest.integrity_output_masks.push_back(rng.word32());

    out.program.validate();
    return out;
}

RoundMorphedProgramSchedule ProgramMorpher::morph_round_schedule(
    const v0id::core::Program& base,
    std::size_t base_initial_state,
    std::size_t public_state_count,
    std::size_t rounds,
    const MorphSeed& seed,
    std::size_t integrity_candidate_count) {

    base.validate();
    if (base_initial_state >= base.states)
        throw std::runtime_error("base initial state out of range");
    if (rounds == 0)
        throw std::runtime_error("round-polymorphic morph needs at least one round");
    if (public_state_count < base.states)
        throw std::runtime_error("public state count smaller than base program");
    if (public_state_count < rounds + 1)
        throw std::runtime_error(
            "round-polymorphic morph needs public_state_count >= rounds + 1");
    if (integrity_candidate_count == 0)
        throw std::runtime_error("integrity candidate count must be positive");

    KmacMorphRng rng(seed);

    // One secret base permutation plus a secret full-cycle stride produces a
    // Latin family of boundary encodings. For every logical state q, its public
    // label is different at every boundary 0..rounds (because rounds < states),
    // while each boundary remains a complete permutation of the public labels.
    // The evaluator sees encrypted transition tables, not base_slots or stride.
    const auto base_slots = shuffled_slots(public_state_count, rng);
    const auto stride = coprime_stride(public_state_count, rng);

    RoundMorphedProgramSchedule out;
    out.base_state_count = base.states;
    out.manifest.logical_to_morphed.resize(rounds + 1);

    for (std::size_t boundary = 0; boundary <= rounds; ++boundary) {
        auto& map = out.manifest.logical_to_morphed[boundary];
        map.resize(public_state_count);
        const auto shift = (boundary * stride) % public_state_count;
        for (std::size_t logical = 0; logical < public_state_count; ++logical)
            map[logical] = base_slots[(logical + shift) % public_state_count];
    }

    out.round_programs.resize(rounds);
    for (std::size_t round = 0; round < rounds; ++round) {
        auto& program = out.round_programs[round];
        program.states = public_state_count;
        program.rules.resize(public_state_count * 2);

        const auto& current_map = out.manifest.logical_to_morphed[round];
        const auto& next_map = out.manifest.logical_to_morphed[round + 1];

        // Every logical public state participates in the same round-to-round
        // representation change. Real states execute the base semantics;
        // padding states remain harmless no-ops while changing their hidden
        // public label too, so dummy positions do not stay stable across rounds.
        for (std::size_t logical = 0; logical < public_state_count; ++logical) {
            const auto state = current_map[logical];
            for (int read = 0; read <= 1; ++read) {
                if (logical < base.states) {
                    const auto& r = base.rule(logical, read);
                    program.rules[state * 2 + static_cast<std::size_t>(read)] =
                        v0id::core::Rule{
                            state,
                            read,
                            next_map[r.next_state],
                            r.write,
                            r.move,
                        };
                } else {
                    program.rules[state * 2 + static_cast<std::size_t>(read)] =
                        v0id::core::Rule{
                            state,
                            read,
                            next_map[logical],
                            read,
                            0,
                        };
                }
            }
        }
        program.validate();
    }

    out.initial_state = out.manifest.logical_to_morphed.front()[base_initial_state];

    out.manifest.integrity_nonce = rng.word32();
    out.manifest.integrity_output_slot =
        static_cast<std::size_t>(rng.uniform(integrity_candidate_count));
    out.manifest.integrity_output_masks.reserve(integrity_candidate_count);
    for (std::size_t i = 0; i < integrity_candidate_count; ++i)
        out.manifest.integrity_output_masks.push_back(rng.word32());

    return out;
}

} // namespace v0id::polymorph
