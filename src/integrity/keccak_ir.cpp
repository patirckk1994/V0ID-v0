#include "keccak_ir.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace v0id::integrity {
namespace {

constexpr std::size_t idx(std::size_t x, std::size_t y, std::size_t z) {
    return (x + 5 * y) * 64 + z;
}

constexpr std::array<std::array<unsigned, 5>, 5> kRho{{
    {{0, 36, 3, 41, 18}},
    {{1, 44, 10, 45, 2}},
    {{62, 6, 43, 15, 61}},
    {{28, 55, 25, 21, 56}},
    {{27, 20, 39, 8, 14}},
}};

constexpr std::array<std::uint64_t, 24> kRoundConstants{{
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
}};

} // namespace

KeccakStateWires append_keccak_f1600(BooleanIR& ir,
                                     const KeccakStateWires& input_state) {
    ir.validate();
    KeccakStateWires a = input_state;

    for (std::size_t round = 0; round < kRoundConstants.size(); ++round) {
        // theta: C[x] = xor_y A[x,y], D[x] = C[x-1] xor ROT(C[x+1],1)
        std::array<std::array<BoolWire, 64>, 5> c{};
        std::array<std::array<BoolWire, 64>, 5> d{};
        for (std::size_t x = 0; x < 5; ++x) {
            for (std::size_t z = 0; z < 64; ++z) {
                BoolWire w = a[idx(x, 0, z)];
                for (std::size_t y = 1; y < 5; ++y)
                    w = ir.bit_xor(w, a[idx(x, y, z)]);
                c[x][z] = w;
            }
        }
        for (std::size_t x = 0; x < 5; ++x) {
            for (std::size_t z = 0; z < 64; ++z) {
                d[x][z] = ir.bit_xor(c[(x + 4) % 5][z],
                                     c[(x + 1) % 5][(z + 63) % 64]);
            }
        }
        for (std::size_t x = 0; x < 5; ++x)
            for (std::size_t y = 0; y < 5; ++y)
                for (std::size_t z = 0; z < 64; ++z)
                    a[idx(x, y, z)] = ir.bit_xor(a[idx(x, y, z)], d[x][z]);

        // rho + pi: pure wire relabeling. For ROTL(r), output bit z reads
        // input bit (z-r) mod 64.
        KeccakStateWires b{};
        for (std::size_t x = 0; x < 5; ++x) {
            for (std::size_t y = 0; y < 5; ++y) {
                const unsigned r = kRho[x][y];
                const std::size_t bx = y;
                const std::size_t by = (2 * x + 3 * y) % 5;
                for (std::size_t z = 0; z < 64; ++z)
                    b[idx(bx, by, z)] = a[idx(x, y, (z + 64 - r) % 64)];
            }
        }

        // chi: A[x,y] = B[x,y] xor ((not B[x+1,y]) and B[x+2,y])
        KeccakStateWires chi{};
        for (std::size_t x = 0; x < 5; ++x) {
            for (std::size_t y = 0; y < 5; ++y) {
                for (std::size_t z = 0; z < 64; ++z) {
                    const auto nb = ir.bit_not(b[idx((x + 1) % 5, y, z)]);
                    const auto t = ir.bit_and(nb, b[idx((x + 2) % 5, y, z)]);
                    chi[idx(x, y, z)] = ir.bit_xor(b[idx(x, y, z)], t);
                }
            }
        }
        a = chi;

        // iota: xor the round constant into lane (0,0).
        for (std::size_t z = 0; z < 64; ++z) {
            if (((kRoundConstants[round] >> z) & 1ULL) != 0)
                a[idx(0, 0, z)] = ir.bit_xor(a[idx(0, 0, z)], ir.constant(true));
        }
    }

    return a;
}

} // namespace v0id::integrity
