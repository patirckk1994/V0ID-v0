#include "series_generator.hpp"

#include <z3++.h>

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
    constexpr char marker[] = "V0ID-Z3-AUDIT";
    for (std::size_t i = 0; i < sizeof(marker) - 1 && i + 1 < root.size(); ++i)
        root[i + 1] = static_cast<unsigned char>(marker[i]);
    return root;
}

bool bit_at(const std::vector<std::uint8_t>& bytes, std::size_t bit) {
    return ((bytes.at(bit / 8) >> (bit % 8)) & 1u) != 0;
}

z3::expr xor_all(z3::context& ctx, const std::vector<z3::expr>& terms) {
    z3::expr out = ctx.bool_val(false);
    // Boolean inequality is XOR. Using only the core C++ expression operators
    // keeps this compatible with older distro Z3 C++ headers too.
    for (const auto& term : terms)
        out = (out != term);
    return out;
}

bool affine_recovery_exists(const std::vector<std::vector<std::uint8_t>>& images,
                            std::size_t public_bits,
                            std::size_t secret_bit) {
    z3::context ctx;
    z3::solver solver(ctx);

    std::vector<z3::expr> coefficients;
    coefficients.reserve(public_bits + 1);
    coefficients.push_back(ctx.bool_const("affine_const"));
    for (std::size_t i = 0; i < public_bits; ++i)
        coefficients.push_back(ctx.bool_const(("a_" + std::to_string(i)).c_str()));

    for (std::size_t x = 0; x < images.size(); ++x) {
        std::vector<z3::expr> terms;
        terms.push_back(coefficients[0]);
        for (std::size_t i = 0; i < public_bits; ++i) {
            if (bit_at(images[x], i))
                terms.push_back(coefficients[i + 1]);
        }
        const bool target = ((x >> secret_bit) & 1u) != 0;
        solver.add(xor_all(ctx, terms) == ctx.bool_val(target));
    }

    return solver.check() == z3::sat;
}

bool quadratic_recovery_exists(const std::vector<std::vector<std::uint8_t>>& images,
                               std::size_t public_bits,
                               std::size_t secret_bit) {
    z3::context ctx;
    z3::solver solver(ctx);

    z3::expr constant = ctx.bool_const("q_const");
    std::vector<z3::expr> linear;
    linear.reserve(public_bits);
    for (std::size_t i = 0; i < public_bits; ++i)
        linear.push_back(ctx.bool_const(("q_l_" + std::to_string(i)).c_str()));

    std::vector<std::vector<z3::expr>> quadratic;
    quadratic.reserve(public_bits);
    for (std::size_t i = 0; i < public_bits; ++i) {
        std::vector<z3::expr> row;
        row.reserve(public_bits - i - 1);
        for (std::size_t j = i + 1; j < public_bits; ++j)
            row.push_back(ctx.bool_const(
                ("q_" + std::to_string(i) + "_" + std::to_string(j)).c_str()));
        quadratic.push_back(std::move(row));
    }

    for (std::size_t x = 0; x < images.size(); ++x) {
        std::vector<z3::expr> terms;
        terms.push_back(constant);
        for (std::size_t i = 0; i < public_bits; ++i) {
            if (bit_at(images[x], i))
                terms.push_back(linear[i]);
        }
        for (std::size_t i = 0; i < public_bits; ++i) {
            if (!bit_at(images[x], i))
                continue;
            for (std::size_t j = i + 1; j < public_bits; ++j) {
                if (bit_at(images[x], j))
                    terms.push_back(quadratic[i][j - i - 1]);
            }
        }
        const bool target = ((x >> secret_bit) & 1u) != 0;
        solver.add(xor_all(ctx, terms) == ctx.bool_val(target));
    }

    return solver.check() == z3::sat;
}

} // namespace

int main() try {
    // Exhaust the full 8-bit reduced private-root domain. The synthesized
    // relation must be one program shared by all 256 instances; it cannot embed
    // a per-challenge oracle table or use a different expression for each root.
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
        const bool affine = affine_recovery_exists(
            images, AFFINE_PUBLIC_BITS, secret_bit);
        if (!affine) {
            ++passed;
            std::cout << "[PASS] no affine GF(2) recovery for reduced root bit "
                      << secret_bit << " from first " << AFFINE_PUBLIC_BITS
                      << " series bits\n";
        } else {
            ++failed;
            std::cerr << "[FAIL] affine GF(2) recovery exists for reduced root bit "
                      << secret_bit << '\n';
        }

        const bool quadratic = quadratic_recovery_exists(
            images, QUADRATIC_PUBLIC_BITS, secret_bit);
        if (!quadratic) {
            ++passed;
            std::cout << "[PASS] no degree<=2 ANF recovery for reduced root bit "
                      << secret_bit << " from first " << QUADRATIC_PUBLIC_BITS
                      << " series bits\n";
        } else {
            ++failed;
            std::cerr << "[FAIL] degree<=2 ANF recovery exists for reduced root bit "
                      << secret_bit << '\n';
        }
    }

    std::cout << "\nV0ID Z3 symbolic series audit: "
              << passed << " passed, " << failed << " failed\n"
              << "Scope: exhaustive 8-bit reduced roots; one shared oracle-free "
                 "affine/quadratic Boolean relation across the whole domain.\n"
              << "UNSAT closes only this defined attack language; it is not a "
                 "proof against arbitrary Turing machines or future quantum algorithms.\n";
    return failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID Z3 symbolic series audit fatal error: " << e.what() << '\n';
    return 1;
}
