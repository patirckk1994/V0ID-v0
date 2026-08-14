#pragma once

#include "series_generator.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace v0id::polymorph {

// Client-only WAMR limits for local polymorphism plugins. This is deliberately
// separate from MathVM's remote provider budgets: the plugin has no host imports
// and only derives private morph material before ProgramMorpher runs.
struct WasmSeriesLimits {
    std::size_t max_module_bytes{1024 * 1024};
    std::uint32_t max_memory_pages{16};          // 16 * 64 KiB = 1 MiB
    std::uint32_t stack_bytes{64 * 1024};
    std::size_t runtime_pool_bytes{16 * 1024 * 1024};
    int max_wasm_instructions{500'000};
    std::size_t max_input_bytes{256 * 1024};
    std::size_t max_output_bytes{256 * 1024};
    std::size_t max_series_bytes{128 * 1024};
    std::size_t max_private_manifest_bytes{64 * 1024};
};

// Local-only portable polymorphism plugin.
//
// The module must:
//   * be ordinary Wasm32 bytecode,
//   * declare exactly one bounded linear memory,
//   * import nothing,
//   * have no start function,
//   * export `v0id_buffer_base() -> i32`, and
//   * export
//       `v0id_polymorph(seed_ptr:i32, input_ptr:i32, input_len:i32,
//                       epoch:i64, output_ptr:i32,
//                       output_capacity:i32) -> i32 written`.
//
// Host and guest exchange only bytes in the guest's linear memory. The returned
// envelope is canonical:
//
//   "V0P1"
//   u32be series_length
//   u32be private_manifest_length
//   32-byte MorphSeed
//   series[series_length]
//   private_manifest[private_manifest_length]
//
// The Wasm never receives a Program object and cannot directly rewrite machine
// transitions. Trusted C++ validates this envelope and hands only MorphSeed to
// ProgramMorpher. The Wasm stays client-side and is never a remote executable
// plugin.
class WasmSeriesGenerator final : public PolymorphicSeriesGenerator {
public:
    WasmSeriesGenerator(std::vector<std::uint8_t> wasm,
                        SeriesProfile profile,
                        WasmSeriesLimits limits = {});

    SeriesProfile profile() const override;

    DerivedSeries derive(const std::vector<std::uint8_t>& input,
                         const SeriesSeed& seed,
                         std::uint64_t epoch) const override;

    const WasmSeriesLimits& limits() const noexcept { return limits_; }
    std::size_t module_bytes() const noexcept { return wasm_.size(); }

private:
    std::vector<std::uint8_t> wasm_;
    SeriesProfile profile_;
    WasmSeriesLimits limits_;
};

} // namespace v0id::polymorph
