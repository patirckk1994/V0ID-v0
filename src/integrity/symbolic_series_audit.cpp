#include "series_generator.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::SeriesSeed;

SeriesSeed reduced_root(std::uint8_t x) {
    SeriesSeed root{};
    root[0] = x;
    constexpr char marker[] = "V0ID-SYMBOLIC-AUDIT";
    for (std::size_t i = 0; i < sizeof(marker) - 1 && i + 1 < root.size(); ++i)
        root[i + 1] = static_cast<unsigned char>(marker[i]);
    return root;
}

bool bit_at(const std::vector<std::uint8_t>& bytes, std::size_t bit) {
    return ((bytes.at(bit / 8) >> (bit % 8)) & 1u) != 0;
}

// Exact GF(2) consistency test for A*c = b. Rows are bit-packed and include
// the right-hand-side bit as the last column. This is the correct decision
// procedure for both affine and degree<=2 ANF recovery here: the monomial
// feature values are constants from each observed series image, while the
// attacker-program coefficients are the unknowns and occur only linearly.
bool gf2_system_has_solution(std::vector<std::vector<std::uint64_t>> rows,
                             std::size_t variables) {
    const std::size_t rhs_col = variables;
    const std::size_t words = (variables + 1 + 63) / 64;
    if (rows.empty())
        return true;
    for (const auto& row : rows) {
        if (row.size() != words)
            throw std::runtime_error("malformed GF(2) audit row");
    }

    auto get_bit = [](const std::vector<std::uint64_t>& row, std::size_t bit) {
        return ((row[bit / 64] >> (bit % 64)) & 1ULL) != 0;
    };

    std::size_t pivot_row = 0;
    for (std::size_t col = 0; col < variables && pivot_row < rows.size(); ++col) {
        std::size_t pivot = pivot_row;
        while (pivot < rows.size() && !get_bit(rows[pivot], col))
            ++pivot;
        if (pivot == rows.size())
            continue;

        if (pivot != pivot_row)
            std::swap(rows[pivot], rows[pivot_row]);

        for (std::size_t r = 0; r < rows.size(); ++r) {
            if (r == pivot_row || !get_bit(rows[r], col))
                continue;
            for (std::size_t w = 0; w < words; ++w)
                rows[r][w] ^= rows[pivot_row][w];
        }
        ++pivot_row;
    }

    // Inconsistency is 0 = 1: all coefficient columns zero, RHS one.
    for (const auto& row : rows) {
        bool any_coefficient = false;
        for (std::size_t col = 0; col < variables; ++col) {
            if (get_bit(row, col)) {
                any_coefficient = true;
                break;
            }
        }
        if (!any_coefficient && get_bit(row, rhs_col))
            return false;
    }
    return true;
}

void set_row_bit(std::vector<std::uint64_t>& row, std::size_t bit) {
    row.at(bit / 64) |= (1ULL << (bit % 64));
}

bool affine_recovery_exists(const std::vector<std::vector<std::uint8_t>>& images,
                            std::size_t public_bits,
                            std::size_t secret_bit) {
    // constant + one coefficient per observed public bit
    const std::size_t variables = 1 + public_bits;
    const std::size_t words = (variables + 1 + 63) / 64;
    std::vector<std::vector<std::uint64_t>> rows(
        images.size(), std::vector<std::uint64_t>(words, 0));

    for (std::size_t x = 0; x < images.size(); ++x) {
        set_row_bit(rows[x], 0); // constant monomial
        for (std::size_t i = 0; i < public_bits; ++i) {
            if (bit_at(images[x], i))
                set_row_bit(rows[x], 1 + i);
        }
        if (((x >> secret_bit) & 1u) != 0)
            set_row_bit(rows[x], variables); // RHS
    }
    return gf2_system_has_solution(std::move(rows), variables);
}

bool quadratic_recovery_exists(const std::vector<std::vector<std::uint8_t>>& images,
                               std::size_t public_bits,
                               std::size_t secret_bit) {
    // constant + linear monomials + pairwise degree-2 monomials
    const std::size_t pair_terms = public_bits * (public_bits - 1) / 2;
    const std::size_t variables = 1 + public_bits + pair_terms;
    const std::size_t words = (variables + 1 + 63) / 64;
    std::vector<std::vector<std::uint64_t>> rows(
        images.size(), std::vector<std::uint64_t>(words, 0));

    for (std::size_t x = 0; x < images.size(); ++x) {
        set_row_bit(rows[x], 0);
        for (std::size_t i = 0; i < public_bits; ++i) {
            if (bit_at(images[x], i))
                set_row_bit(rows[x], 1 + i);
        }

        std::size_t term = 1 + public_bits;
        for (std::size_t i = 0; i < public_bits; ++i) {
            for (std::size_t j = i + 1; j < public_bits; ++j, ++term) {
                if (bit_at(images[x], i) && bit_at(images[x], j))
                    set_row_bit(rows[x], term);
            }
        }

        if (((x >> secret_bit) & 1u) != 0)
            set_row_bit(rows[x], variables);
    }
    return gf2_system_has_solution(std::move(rows), variables);
}

} // namespace

int main() try {
    // Exhaust the full 8-bit reduced private-root domain. One attacker
    // expression must work for every one of the 256 instances; there is no
    // challenge-specific oracle table or per-root program selection.
    constexpr std::size_t DOMAIN = 256;
    constexpr std::size_t AFFINE_PUBLIC_BITS = 64;
    constexpr std::size_t QUADRATIC_PUBLIC_BITS = 16;

    KmacSeriesGenerator generator(16);
    const std::vector<std::uint8_t> input{1,0,1,1,0,0,0,0};
    std::vector<std::vector<std::uint8_t>> images;
    images.reserve(DOMAIN);
    for (std::size_t x = 0; x < DOMAIN; ++x)
        images.push_back(generator.derive(
            input, reduced_root(static_cast<std::uint8_t>(x)), 11).series);

    int passed = 0;
    int failed = 0;

    for (std::size_t secret_bit = 0; secret_bit < 8; ++secret_bit) {
        std::cout << "[RUN ] affine GF(2) recovery for reduced root bit "
                  << secret_bit << " from first " << AFFINE_PUBLIC_BITS
                  << " series bits..." << std::flush;
        const bool affine = affine_recovery_exists(
            images, AFFINE_PUBLIC_BITS, secret_bit);
        if (!affine) {
            ++passed;
            std::cout << " PASS (UNSAT linear system)\n";
        } else {
            ++failed;
            std::cout << " FAIL (generic affine recovery exists)\n";
        }

        std::cout << "[RUN ] degree<=2 ANF recovery for reduced root bit "
                  << secret_bit << " from first " << QUADRATIC_PUBLIC_BITS
                  << " series bits..." << std::flush;
        const bool quadratic = quadratic_recovery_exists(
            images, QUADRATIC_PUBLIC_BITS, secret_bit);
        if (!quadratic) {
            ++passed;
            std::cout << " PASS (UNSAT GF(2) system)\n";
        } else {
            ++failed;
            std::cout << " FAIL (generic degree<=2 recovery exists)\n";
        }
    }

    std::cout << "\nV0ID exact symbolic series audit: "
              << passed << " passed, " << failed << " failed\n"
              << "Scope: exhaustive 8-bit reduced roots; one shared oracle-free "
                 "affine/quadratic ANF expression across the whole domain.\n"
              << "UNSAT here is an exact result for this defined GF(2)/ANF attacker "
                 "class; it is not a proof against arbitrary programs or future "
                 "quantum algorithms.\n"
              << "Z3 remains reserved for the next attacker DSL where rotate/shift/"
                 "add/control-flow make general SMT solving earn its cost.\n";
    return failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID symbolic series audit fatal error: " << e.what() << '\n';
    return 1;
}
