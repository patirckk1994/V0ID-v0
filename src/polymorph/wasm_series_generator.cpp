#include "wasm_series_generator.hpp"

#include "wasm_export.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace v0id::polymorph {
namespace {

constexpr std::array<std::uint8_t, 4> OUTPUT_MAGIC{'V', '0', 'P', '1'};
constexpr std::size_t OUTPUT_HEADER_BYTES = 4 + 4 + 4 + 32;
constexpr std::size_t SEED_BYTES = SeriesSeed{}.size();

std::mutex g_wasm_series_runtime_mutex;

class WasmCursor {
public:
    WasmCursor(const std::vector<std::uint8_t>& bytes,
               std::size_t begin,
               std::size_t end)
        : bytes_(bytes), pos_(begin), end_(end) {
        if (begin > end || end > bytes.size())
            throw std::runtime_error("invalid local polymorphism Wasm cursor range");
    }

    bool empty() const noexcept { return pos_ == end_; }
    std::size_t remaining() const noexcept { return end_ - pos_; }
    std::size_t position() const noexcept { return pos_; }

    std::uint8_t read_u8() {
        if (pos_ >= end_)
            throw std::runtime_error("truncated local polymorphism Wasm binary");
        return bytes_[pos_++];
    }

    std::uint32_t read_uleb32() {
        std::uint64_t value = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 5; ++i) {
            const auto byte = read_u8();
            value |= static_cast<std::uint64_t>(byte & 0x7fu) << shift;
            if ((byte & 0x80u) == 0) {
                if (value > std::numeric_limits<std::uint32_t>::max())
                    throw std::runtime_error("local polymorphism Wasm u32 LEB overflow");
                return static_cast<std::uint32_t>(value);
            }
            shift += 7;
        }
        throw std::runtime_error("local polymorphism Wasm u32 LEB is too long");
    }

    void skip(std::size_t count) {
        if (count > remaining())
            throw std::runtime_error("truncated local polymorphism Wasm section");
        pos_ += count;
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t pos_{};
    std::size_t end_{};
};

void validate_profile(const SeriesProfile& profile) {
    if (profile.generator_id.empty() || profile.generator_id.size() > 96)
        throw std::runtime_error("invalid local Wasm series generator id length");
    if (profile.version == 0)
        throw std::runtime_error("local Wasm series generator version must be positive");
    if (profile.parameters.size() > 4096)
        throw std::runtime_error("local Wasm series generator parameter blob too large");
}

void validate_limits(const WasmSeriesLimits& limits) {
    if (limits.max_module_bytes == 0)
        throw std::runtime_error("local Wasm max_module_bytes must be positive");
    if (limits.max_memory_pages == 0)
        throw std::runtime_error("local Wasm max_memory_pages must be positive");
    if (limits.stack_bytes < 4096)
        throw std::runtime_error("local Wasm stack budget is too small");
    if (limits.runtime_pool_bytes < 1024 * 1024 ||
        limits.runtime_pool_bytes > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("local Wasm runtime pool is outside WAMR limits");
    if (limits.max_wasm_instructions <= 0)
        throw std::runtime_error("local Wasm instruction budget must be positive");
    if (limits.max_input_bytes == 0 || limits.max_output_bytes < OUTPUT_HEADER_BYTES)
        throw std::runtime_error("local Wasm byte limits are too small");
    if (limits.max_series_bytes == 0 ||
        limits.max_private_manifest_bytes > limits.max_output_bytes ||
        limits.max_series_bytes > limits.max_output_bytes)
        throw std::runtime_error("local Wasm derived-output limits are inconsistent");
    if (limits.max_input_bytes > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()) ||
        limits.max_output_bytes > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        throw std::runtime_error("local Wasm byte limit exceeds i32 ABI");

    const auto memory_cap =
        static_cast<std::uint64_t>(limits.max_memory_pages) * 65536ull;
    const auto worst_layout = static_cast<std::uint64_t>(SEED_BYTES) +
                              limits.max_input_bytes +
                              limits.max_output_bytes;
    if (worst_layout > memory_cap)
        throw std::runtime_error(
            "local Wasm seed/input/output limits exceed linear-memory cap");
}

void validate_module_policy(const std::vector<std::uint8_t>& wasm,
                            const WasmSeriesLimits& limits) {
    static constexpr std::uint8_t header[] = {
        0x00, 0x61, 0x73, 0x6d,
        0x01, 0x00, 0x00, 0x00,
    };

    if (wasm.empty() || wasm.size() > limits.max_module_bytes)
        throw std::runtime_error("local polymorphism Wasm module size outside limit");
    if (wasm.size() < sizeof(header))
        throw std::runtime_error("local polymorphism Wasm binary is too short");
    for (std::size_t i = 0; i < sizeof(header); ++i) {
        if (wasm[i] != header[i])
            throw std::runtime_error(
                "local polymorphism requires Wasm binary version 1");
    }

    WasmCursor cursor(wasm, sizeof(header), wasm.size());
    bool saw_import_section = false;
    bool saw_memory_section = false;

    while (!cursor.empty()) {
        const auto section_id = cursor.read_u8();
        const auto section_size = static_cast<std::size_t>(cursor.read_uleb32());
        if (section_size > cursor.remaining())
            throw std::runtime_error("truncated local polymorphism Wasm section payload");

        const auto begin = cursor.position();
        const auto end = begin + section_size;

        if (section_id == 2) {
            if (saw_import_section)
                throw std::runtime_error("duplicate local polymorphism import section");
            saw_import_section = true;
            WasmCursor section(wasm, begin, end);
            const auto count = section.read_uleb32();
            if (count != 0)
                throw std::runtime_error(
                    "local polymorphism Wasm forbids all host imports");
            if (!section.empty())
                throw std::runtime_error("malformed empty local Wasm import section");
        }
        else if (section_id == 5) {
            if (saw_memory_section)
                throw std::runtime_error("duplicate local polymorphism memory section");
            saw_memory_section = true;
            WasmCursor section(wasm, begin, end);
            const auto count = section.read_uleb32();
            if (count != 1)
                throw std::runtime_error(
                    "local polymorphism Wasm requires exactly one linear memory");

            const auto flags = section.read_uleb32();
            if (flags != 0x01)
                throw std::runtime_error(
                    "local polymorphism memory must be bounded ordinary Wasm32");
            const auto min_pages = section.read_uleb32();
            const auto max_pages = section.read_uleb32();
            if (max_pages < min_pages ||
                min_pages > limits.max_memory_pages ||
                max_pages > limits.max_memory_pages)
                throw std::runtime_error(
                    "local polymorphism memory declaration exceeds sandbox cap");
            if (!section.empty())
                throw std::runtime_error("malformed local polymorphism memory section");
        }
        else if (section_id == 8) {
            // Start functions run during instantiation, before the per-execution
            // instruction meter is attached. They therefore have no place in this
            // deterministic plugin profile.
            throw std::runtime_error(
                "local polymorphism Wasm forbids a start function");
        }

        cursor.skip(section_size);
    }

    if (!saw_memory_section)
        throw std::runtime_error(
            "local polymorphism Wasm requires a declared linear memory");
}

std::uint32_t read_u32_be(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

void require_signature(wasm_module_inst_t module_inst,
                       wasm_function_inst_t function,
                       const std::vector<wasm_valkind_t>& params,
                       wasm_valkind_t result,
                       const char* name) {
    if (!function)
        throw std::runtime_error(std::string("local Wasm export missing: ") + name);
    if (wasm_func_get_param_count(function, module_inst) != params.size())
        throw std::runtime_error(std::string("local Wasm export has wrong parameter count: ") + name);
    if (wasm_func_get_result_count(function, module_inst) != 1)
        throw std::runtime_error(std::string("local Wasm export must return one value: ") + name);

    std::vector<wasm_valkind_t> actual(params.size());
    if (!actual.empty())
        wasm_func_get_param_types(function, module_inst, actual.data());
    if (actual != params)
        throw std::runtime_error(std::string("local Wasm export has wrong parameter types: ") + name);

    wasm_valkind_t actual_result{};
    wasm_func_get_result_types(function, module_inst, &actual_result);
    if (actual_result != result)
        throw std::runtime_error(std::string("local Wasm export has wrong result type: ") + name);
}

void throw_call_failure(wasm_module_inst_t module_inst, const char* phase) {
    const char* exception = wasm_runtime_get_exception(module_inst);
    throw std::runtime_error(
        std::string("local polymorphism Wasm trapped during ") + phase +
        ": " + (exception ? exception : "unknown WAMR failure"));
}

DerivedSeries parse_output(const std::uint8_t* bytes,
                           std::size_t written,
                           const WasmSeriesLimits& limits) {
    if (written < OUTPUT_HEADER_BYTES)
        throw std::runtime_error("local Wasm returned a truncated polymorphism envelope");
    if (!std::equal(OUTPUT_MAGIC.begin(), OUTPUT_MAGIC.end(), bytes))
        throw std::runtime_error("local Wasm returned invalid polymorphism envelope magic");

    const auto series_len = static_cast<std::size_t>(read_u32_be(bytes + 4));
    const auto manifest_len = static_cast<std::size_t>(read_u32_be(bytes + 8));
    if (series_len == 0 || series_len > limits.max_series_bytes)
        throw std::runtime_error("local Wasm series length outside configured limit");
    if (manifest_len > limits.max_private_manifest_bytes)
        throw std::runtime_error("local Wasm private manifest exceeds configured limit");

    const auto payload_len = series_len + manifest_len;
    if (payload_len < series_len ||
        OUTPUT_HEADER_BYTES > std::numeric_limits<std::size_t>::max() - payload_len)
        throw std::runtime_error("local Wasm polymorphism envelope length overflow");
    const auto expected = OUTPUT_HEADER_BYTES + payload_len;
    if (expected != written)
        throw std::runtime_error("local Wasm polymorphism envelope length mismatch");

    DerivedSeries out;
    std::copy_n(bytes + 12, out.morph_seed.size(), out.morph_seed.begin());
    const auto* series_begin = bytes + OUTPUT_HEADER_BYTES;
    out.series.assign(series_begin, series_begin + series_len);
    out.private_manifest.assign(series_begin + series_len,
                                series_begin + series_len + manifest_len);
    return out;
}

} // namespace

WasmSeriesGenerator::WasmSeriesGenerator(std::vector<std::uint8_t> wasm,
                                         SeriesProfile profile,
                                         WasmSeriesLimits limits)
    : wasm_(std::move(wasm)),
      profile_(std::move(profile)),
      limits_(limits) {
    validate_profile(profile_);
    validate_limits(limits_);
    validate_module_policy(wasm_, limits_);
}

SeriesProfile WasmSeriesGenerator::profile() const {
    return profile_;
}

DerivedSeries WasmSeriesGenerator::derive(
    const std::vector<std::uint8_t>& input,
    const SeriesSeed& seed,
    std::uint64_t epoch) const {
    if (input.size() > limits_.max_input_bytes)
        throw std::runtime_error("local Wasm polymorphism input exceeds configured limit");

    // WAMR's runtime is process-global. Keep the first implementation deliberately
    // simple and deterministic: one local derivation owns the runtime for the
    // duration of this call, then destroys it. The remote-machine client does not
    // host MathVM at the same time, so there is no reason to introduce a larger
    // shared runtime manager before a real co-residency use-case exists.
    std::lock_guard<std::mutex> runtime_lock(g_wasm_series_runtime_mutex);

    std::vector<std::uint8_t> runtime_pool(limits_.runtime_pool_bytes);
    RuntimeInitArgs init_args{};
    init_args.mem_alloc_type = Alloc_With_Pool;
    init_args.mem_alloc_option.pool.heap_buf = runtime_pool.data();
    init_args.mem_alloc_option.pool.heap_size =
        static_cast<std::uint32_t>(runtime_pool.size());
    init_args.running_mode = Mode_Interp;

    if (!wasm_runtime_full_init(&init_args))
        throw std::runtime_error(
            "failed to initialize local polymorphism WAMR runtime");

    bool runtime_active = true;
    wasm_module_t module = nullptr;
    wasm_module_inst_t module_inst = nullptr;
    wasm_exec_env_t exec_env = nullptr;

    auto cleanup = [&]() {
        if (exec_env)
            wasm_runtime_destroy_exec_env(exec_env);
        if (module_inst)
            wasm_runtime_deinstantiate(module_inst);
        if (module)
            wasm_runtime_unload(module);
        exec_env = nullptr;
        module_inst = nullptr;
        module = nullptr;
        if (runtime_active) {
            wasm_runtime_destroy();
            runtime_active = false;
        }
    };

    try {
        auto wasm_bytes = wasm_;
        if (wasm_runtime_get_file_package_type(
                wasm_bytes.data(), static_cast<std::uint32_t>(wasm_bytes.size())) !=
            Wasm_Module_Bytecode)
            throw std::runtime_error(
                "local polymorphism accepts portable Wasm bytecode only");

        char error_buf[512]{};
        module = wasm_runtime_load(
            wasm_bytes.data(), static_cast<std::uint32_t>(wasm_bytes.size()),
            error_buf, static_cast<std::uint32_t>(sizeof(error_buf)));
        if (!module)
            throw std::runtime_error(
                std::string("local polymorphism WAMR load failed: ") + error_buf);

        InstantiationArgs instantiate_args{};
        instantiate_args.default_stack_size = limits_.stack_bytes;
        instantiate_args.host_managed_heap_size = 0;
        instantiate_args.max_memory_pages = 0;
        module_inst = wasm_runtime_instantiate_ex(
            module, &instantiate_args, error_buf,
            static_cast<std::uint32_t>(sizeof(error_buf)));
        if (!module_inst)
            throw std::runtime_error(
                std::string("local polymorphism WAMR instantiate failed: ") + error_buf);

        auto buffer_base_fn = wasm_runtime_lookup_function(
            module_inst, "v0id_buffer_base");
        require_signature(module_inst, buffer_base_fn, {}, WASM_I32,
                          "v0id_buffer_base");

        auto polymorph_fn = wasm_runtime_lookup_function(
            module_inst, "v0id_polymorph");
        require_signature(module_inst, polymorph_fn,
                          {WASM_I32, WASM_I32, WASM_I32,
                           WASM_I64, WASM_I32, WASM_I32},
                          WASM_I32, "v0id_polymorph");

        exec_env = wasm_runtime_create_exec_env(module_inst, limits_.stack_bytes);
        if (!exec_env)
            throw std::runtime_error(
                "failed to create local polymorphism WAMR execution environment");
        wasm_runtime_set_instruction_count_limit(
            exec_env, limits_.max_wasm_instructions);

        wasm_val_t base_result{};
        if (!wasm_runtime_call_wasm_a(
                exec_env, buffer_base_fn, 1, &base_result, 0, nullptr))
            throw_call_failure(module_inst, "buffer-base query");
        if (base_result.kind != WASM_I32)
            throw std::runtime_error("local Wasm buffer-base export returned wrong type");

        const auto base = static_cast<std::uint32_t>(base_result.of.i32);
        const auto input_offset64 = static_cast<std::uint64_t>(base) + SEED_BYTES;
        const auto output_offset64 = input_offset64 + input.size();
        const auto layout_bytes = static_cast<std::uint64_t>(SEED_BYTES) +
                                  input.size() + limits_.max_output_bytes;
        if (input_offset64 > std::numeric_limits<std::uint32_t>::max() ||
            output_offset64 > std::numeric_limits<std::uint32_t>::max() ||
            layout_bytes > std::numeric_limits<std::uint32_t>::max() ||
            static_cast<std::uint64_t>(base) + layout_bytes >
                static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) + 1ull)
            throw std::runtime_error("local Wasm buffer layout exceeds Wasm32 address space");

        if (!wasm_runtime_validate_app_addr(module_inst, base, layout_bytes))
            throw std::runtime_error(
                "local Wasm declared buffer does not fit current linear memory");

        auto* seed_ptr = static_cast<std::uint8_t*>(
            wasm_runtime_addr_app_to_native(module_inst, base));
        auto* input_ptr = static_cast<std::uint8_t*>(
            wasm_runtime_addr_app_to_native(module_inst, input_offset64));
        auto* output_ptr = static_cast<std::uint8_t*>(
            wasm_runtime_addr_app_to_native(module_inst, output_offset64));
        if (!seed_ptr || !input_ptr || !output_ptr)
            throw std::runtime_error("local Wasm buffer address conversion failed");

        std::memcpy(seed_ptr, seed.data(), seed.size());
        if (!input.empty())
            std::memcpy(input_ptr, input.data(), input.size());
        std::memset(output_ptr, 0, limits_.max_output_bytes);

        std::int64_t epoch_bits{};
        static_assert(sizeof(epoch_bits) == sizeof(epoch));
        std::memcpy(&epoch_bits, &epoch, sizeof(epoch));

        std::array<wasm_val_t, 6> args{};
        args[0].kind = WASM_I32;
        args[0].of.i32 = static_cast<std::int32_t>(base);
        args[1].kind = WASM_I32;
        args[1].of.i32 = static_cast<std::int32_t>(input_offset64);
        args[2].kind = WASM_I32;
        args[2].of.i32 = static_cast<std::int32_t>(input.size());
        args[3].kind = WASM_I64;
        args[3].of.i64 = epoch_bits;
        args[4].kind = WASM_I32;
        args[4].of.i32 = static_cast<std::int32_t>(output_offset64);
        args[5].kind = WASM_I32;
        args[5].of.i32 = static_cast<std::int32_t>(limits_.max_output_bytes);

        wasm_val_t written_result{};
        if (!wasm_runtime_call_wasm_a(
                exec_env, polymorph_fn, 1, &written_result,
                static_cast<std::uint32_t>(args.size()), args.data()))
            throw_call_failure(module_inst, "derivation");
        if (written_result.kind != WASM_I32 || written_result.of.i32 < 0)
            throw std::runtime_error("local Wasm returned invalid output length");

        const auto written = static_cast<std::size_t>(written_result.of.i32);
        if (written > limits_.max_output_bytes)
            throw std::runtime_error("local Wasm returned output beyond configured capacity");

        auto out = parse_output(output_ptr, written, limits_);
        cleanup();
        return out;
    } catch (...) {
        cleanup();
        throw;
    }
}

} // namespace v0id::polymorph
