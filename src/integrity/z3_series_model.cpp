#include "z3_series_model.hpp"

#include <stdexcept>
#include <string>

namespace v0id::integrity {

v0id::polymorph::SeriesSeed reduced_audit_root(std::uint8_t value) {
    v0id::polymorph::SeriesSeed root{};
    root[0] = value;
    constexpr char marker[] = "V0ID-BV-AUDIT";
    for (std::size_t i = 0; i < sizeof(marker) - 1 && i + 1 < root.size(); ++i)
        root[i + 1] = static_cast<unsigned char>(marker[i]);
    return root;
}

ReducedSeriesTable build_reduced_series_table(
    const std::vector<std::uint8_t>& semantic_input,
    std::uint64_t epoch,
    std::size_t output_bytes) {
    if (output_bytes == 0)
        throw std::runtime_error("reduced Z3 series model requires output bytes");

    v0id::polymorph::KmacSeriesGenerator generator(output_bytes);
    ReducedSeriesTable table{};
    for (std::size_t x = 0; x < table.size(); ++x) {
        const auto derived = generator.derive(
            semantic_input,
            reduced_audit_root(static_cast<std::uint8_t>(x)),
            epoch);
        if (derived.series.size() < output_bytes)
            throw std::runtime_error(
                "production series generator returned fewer bytes than requested");
        table[x].assign(derived.series.begin(),
                        derived.series.begin() + static_cast<std::ptrdiff_t>(output_bytes));
    }
    return table;
}

std::vector<z3::expr> z3_reduced_series(
    z3::context& ctx,
    const z3::expr& reduced_root_bv8,
    const ReducedSeriesTable& table,
    std::size_t output_bytes) {
    const Z3_sort sort = reduced_root_bv8.get_sort();
    if (Z3_get_sort_kind(ctx, sort) != Z3_BV_SORT ||
        Z3_get_bv_sort_size(ctx, sort) != 8)
        throw std::runtime_error("Z3 reduced-series root must be an 8-bit bit-vector");
    if (output_bytes == 0)
        throw std::runtime_error("Z3 reduced-series model requires output bytes");

    for (const auto& row : table) {
        if (row.size() < output_bytes)
            throw std::runtime_error("reduced-series table row is too short");
    }

    std::vector<z3::expr> out;
    out.reserve(output_bytes);
    for (std::size_t byte = 0; byte < output_bytes; ++byte) {
        z3::expr selected = ctx.bv_val(table[0][byte], 8);
        for (unsigned x = 1; x < 256; ++x) {
            selected = z3::ite(
                reduced_root_bv8 == ctx.bv_val(x, 8),
                ctx.bv_val(table[x][byte], 8),
                selected);
        }
        out.push_back(selected);
    }
    return out;
}

} // namespace v0id::integrity
