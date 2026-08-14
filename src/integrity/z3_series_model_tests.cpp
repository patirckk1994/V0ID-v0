#include "z3_series_model.hpp"

#include <z3++.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::uint64_t numeral_u64(z3::context& ctx, const z3::expr& value) {
    std::uint64_t out = 0;
    const auto simplified = value.simplify();
    if (!Z3_get_numeral_uint64(ctx, simplified, &out))
        throw std::runtime_error("Z3 model produced a non-numeral byte");
    return out;
}

} // namespace

int main() try {
    constexpr std::size_t OUTPUT_BYTES = 8;
    constexpr std::uint64_t EPOCH = 19;
    const std::vector<std::uint8_t> semantic_input{1,0,1,1,0,0,0,0};

    const auto table = v0id::integrity::build_reduced_series_table(
        semantic_input, EPOCH, OUTPUT_BYTES);

    int passed = 0;
    int failed = 0;
    auto check = [&](bool ok, const std::string& name) {
        if (ok) {
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } else {
            ++failed;
            std::cerr << "[FAIL] " << name << '\n';
        }
    };

    // Independent concrete replay against the production KMAC generator.
    v0id::polymorph::KmacSeriesGenerator generator(OUTPUT_BYTES);
    bool table_matches_generator = true;
    for (unsigned x = 0; x < 256 && table_matches_generator; ++x) {
        const auto derived = generator.derive(
            semantic_input,
            v0id::integrity::reduced_audit_root(static_cast<std::uint8_t>(x)),
            EPOCH);
        for (std::size_t b = 0; b < OUTPUT_BYTES; ++b) {
            if (table[x][b] != derived.series[b]) {
                table_matches_generator = false;
                break;
            }
        }
    }
    check(table_matches_generator,
          "reduced table matches production KMAC series generator for all 256 roots");

    z3::context ctx;
    const auto root = ctx.bv_const("reduced_root", 8);
    const auto symbolic = v0id::integrity::z3_reduced_series(
        ctx, root, table, OUTPUT_BYTES);

    bool symbolic_exact = true;
    for (unsigned x = 0; x < 256 && symbolic_exact; ++x) {
        z3::solver solver(ctx);
        solver.add(root == ctx.bv_val(x, 8));
        if (solver.check() != z3::sat) {
            symbolic_exact = false;
            break;
        }
        const auto model = solver.get_model();
        for (std::size_t b = 0; b < OUTPUT_BYTES; ++b) {
            const auto got = numeral_u64(ctx, model.eval(symbolic[b], true));
            if (got != table[x][b]) {
                symbolic_exact = false;
                break;
            }
        }
    }
    check(symbolic_exact,
          "Z3 reduced-series bytes equal real generator outputs for all 256 symbolic roots");

    bool width_rejected = false;
    try {
        const auto wrong = ctx.bv_const("wrong_root", 16);
        (void)v0id::integrity::z3_reduced_series(
            ctx, wrong, table, OUTPUT_BYTES);
    } catch (const std::exception&) {
        width_rejected = true;
    }
    check(width_rejected, "non-8-bit symbolic root fails closed");

    auto changed_table = table;
    changed_table[73][2] ^= 1u;
    const auto changed_symbolic = v0id::integrity::z3_reduced_series(
        ctx, root, changed_table, OUTPUT_BYTES);
    z3::solver changed_solver(ctx);
    changed_solver.add(root == ctx.bv_val(73, 8));
    bool substitution_visible = false;
    if (changed_solver.check() == z3::sat) {
        const auto model = changed_solver.get_model();
        const auto original = numeral_u64(ctx, model.eval(symbolic[2], true));
        const auto changed = numeral_u64(ctx, model.eval(changed_symbolic[2], true));
        substitution_visible = original != changed;
    }
    check(substitution_visible,
          "one-byte table substitution changes the corresponding symbolic series byte");

    std::cout << "\nV0ID Z3 reduced-series model tests: "
              << passed << " passed, " << failed << " failed\n"
              << "Scope: exact 8-bit reduced-root lifting of real KMAC outputs into Z3. "
                 "This is not a symbolic proof/model of SHA3/KMAC internals or full-width roots.\n";
    return failed == 0 ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID Z3 reduced-series model fatal error: " << e.what() << '\n';
    return 2;
}
