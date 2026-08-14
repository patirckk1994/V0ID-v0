#include "wamr_sandbox.hpp"

#include "wasm_export.h"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace v0id::mathvm {
namespace {

using RequirementKey = std::pair<std::uint64_t, std::uint32_t>;

struct ExecutionContext {
    const PrimitiveRegistry* registry{};
    const SandboxLimits* limits{};
    std::set<RequirementKey> allowed;
    std::uint64_t provider_calls{};
    std::uint64_t provider_cost{};
    std::string exception;
};

std::mutex g_runtime_mutex;
bool g_runtime_active = false;

// Small policy parser used before WAMR sees attacker-supplied bytecode. WAMR is
// still responsible for full Wasm validation; this parser extracts the pieces
// V0ID must fail closed on independently of optional WAMR features: host imports
// and declared linear-memory bounds.
class WasmCursor {
public:
    WasmCursor(const std::vector<std::uint8_t>& bytes,
               std::size_t begin,
               std::size_t end)
        : bytes_(bytes), pos_(begin), end_(end) {
        if (begin > end || end > bytes.size())
            throw std::runtime_error("invalid MathVM Wasm cursor range");
    }

    bool empty() const noexcept { return pos_ == end_; }
    std::size_t remaining() const noexcept { return end_ - pos_; }
    std::size_t position() const noexcept { return pos_; }

    std::uint8_t read_u8() {
        if (pos_ >= end_)
            throw std::runtime_error("truncated MathVM Wasm binary");
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
                    throw std::runtime_error("MathVM Wasm u32 LEB overflow");
                return static_cast<std::uint32_t>(value);
            }
            shift += 7;
        }

        throw std::runtime_error("MathVM Wasm u32 LEB is too long");
    }

    std::string read_name() {
        const auto length = static_cast<std::size_t>(read_uleb32());
        if (length > remaining())
            throw std::runtime_error("truncated MathVM Wasm name");

        const auto begin = bytes_.begin() + static_cast<std::ptrdiff_t>(pos_);
        const auto end = begin + static_cast<std::ptrdiff_t>(length);
        pos_ += length;
        return std::string(begin, end);
    }

    void skip(std::size_t count) {
        if (count > remaining())
            throw std::runtime_error("truncated MathVM Wasm section");
        pos_ += count;
    }

private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t pos_{};
    std::size_t end_{};
};

void validate_import_section(WasmCursor& section) {
    const auto count = section.read_uleb32();
    bool saw_u64 = false;
    bool saw_bytes = false;

    for (std::uint32_t i = 0; i < count; ++i) {
        const auto module_name = section.read_name();
        const auto import_name = section.read_name();
        const auto kind = section.read_u8();

        // MathVM ABI v2 exposes exactly two possible host functions and no
        // imported memory/table/global objects. In particular this rejects WASI
        // before WAMR's optional WASI/linker code is involved.
        if (kind != 0x00)
            throw std::runtime_error(
                "MathVM forbids non-function Wasm imports");

        (void)section.read_uleb32(); // function type index; WAMR validates it.

        if (module_name != "v0id_math")
            throw std::runtime_error(
                "MathVM Wasm import is not on the V0ID host allowlist");

        if (import_name == "primitive_u64") {
            if (saw_u64)
                throw std::runtime_error(
                    "MathVM permits only one primitive_u64 host import");
            saw_u64 = true;
        }
        else if (import_name == "primitive_bytes") {
            if (saw_bytes)
                throw std::runtime_error(
                    "MathVM permits only one primitive_bytes host import");
            saw_bytes = true;
        }
        else {
            throw std::runtime_error(
                "MathVM Wasm import is not on the V0ID host allowlist");
        }
    }

    if (!section.empty())
        throw std::runtime_error("malformed MathVM Wasm import section");
}

void validate_memory_section(WasmCursor& section,
                             std::uint32_t max_memory_pages) {
    const auto count = section.read_uleb32();
    if (count > 1)
        throw std::runtime_error("MathVM permits at most one linear memory");

    for (std::uint32_t i = 0; i < count; ++i) {
        const auto flags = section.read_uleb32();

        // V0ID intentionally accepts only ordinary Wasm32 memory with an
        // explicit min+max. Shared-memory/memory64 flags and unbounded memories
        // are outside the current ABI and are rejected before instantiation.
        if (flags != 0x01)
            throw std::runtime_error(
                "MathVM linear memory must declare an explicit Wasm32 maximum");

        const auto min_pages = section.read_uleb32();
        const auto max_pages = section.read_uleb32();

        if (max_pages < min_pages)
            throw std::runtime_error("MathVM linear memory max is below min");
        if (min_pages > max_memory_pages || max_pages > max_memory_pages)
            throw std::runtime_error(
                "MathVM linear memory declaration exceeds sandbox cap");
    }

    if (!section.empty())
        throw std::runtime_error("malformed MathVM Wasm memory section");
}

void validate_wasm_policy(const std::vector<std::uint8_t>& wasm,
                          std::uint32_t max_memory_pages) {
    static constexpr std::uint8_t header[] = {
        0x00, 0x61, 0x73, 0x6d, // \0asm
        0x01, 0x00, 0x00, 0x00, // Wasm binary version 1
    };

    if (wasm.size() < sizeof(header))
        throw std::runtime_error("MathVM Wasm binary is too short");
    for (std::size_t i = 0; i < sizeof(header); ++i) {
        if (wasm[i] != header[i])
            throw std::runtime_error("MathVM requires Wasm binary version 1");
    }

    WasmCursor cursor(wasm, sizeof(header), wasm.size());
    bool saw_import_section = false;
    bool saw_memory_section = false;

    while (!cursor.empty()) {
        const auto section_id = cursor.read_u8();
        const auto section_size = static_cast<std::size_t>(cursor.read_uleb32());
        if (section_size > cursor.remaining())
            throw std::runtime_error("truncated MathVM Wasm section payload");

        const auto section_begin = cursor.position();
        const auto section_end = section_begin + section_size;

        if (section_id == 2) {
            if (saw_import_section)
                throw std::runtime_error("duplicate MathVM Wasm import section");
            saw_import_section = true;
            WasmCursor section(wasm, section_begin, section_end);
            validate_import_section(section);
        }
        else if (section_id == 5) {
            if (saw_memory_section)
                throw std::runtime_error("duplicate MathVM Wasm memory section");
            saw_memory_section = true;
            WasmCursor section(wasm, section_begin, section_end);
            validate_memory_section(section, max_memory_pages);
        }

        cursor.skip(section_size);
    }
}

std::uint32_t checked_version(std::uint64_t version64) {
    if (version64 == 0 ||
        version64 > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("invalid primitive version");
    return static_cast<std::uint32_t>(version64);
}

void require_declared(const ExecutionContext& context,
                      std::uint64_t tag,
                      std::uint32_t version) {
    if (!context.allowed.contains(RequirementKey{tag, version}))
        throw std::runtime_error("Wasm called undeclared primitive");
}

void consume_provider_budget(ExecutionContext& context,
                             const PrimitiveDescriptor& descriptor) {
    if (context.provider_calls >= context.limits->max_provider_calls)
        throw std::runtime_error("MathVM provider call budget exhausted");
    ++context.provider_calls;

    if (descriptor.cost > context.limits->max_provider_cost ||
        context.provider_cost >
            context.limits->max_provider_cost - descriptor.cost)
        throw std::runtime_error("MathVM provider cost budget exhausted");
    context.provider_cost += descriptor.cost;
}

std::uint64_t primitive_u64_native(wasm_exec_env_t exec_env,
                                   std::uint64_t tag,
                                   std::uint64_t version64,
                                   std::uint64_t a,
                                   std::uint64_t b,
                                   std::uint64_t c,
                                   std::uint64_t d) {
    const auto module_inst = wasm_runtime_get_module_inst(exec_env);
    auto* context = static_cast<ExecutionContext*>(
        wasm_runtime_get_custom_data(module_inst));

    if (!context || !context->registry || !context->limits) {
        wasm_runtime_set_exception(module_inst, "V0ID MathVM context missing");
        return 0;
    }

    try {
        const auto version = checked_version(version64);
        require_declared(*context, tag, version);

        const auto& provider = context->registry->require_u64(tag, version);
        const auto descriptor = provider.descriptor();
        consume_provider_budget(*context, descriptor);
        return provider.evaluate_u64(a, b, c, d);
    } catch (const std::exception& e) {
        context->exception = e.what();
        wasm_runtime_set_exception(module_inst, context->exception.c_str());
        return 0;
    } catch (...) {
        context->exception = "unknown MathVM provider failure";
        wasm_runtime_set_exception(module_inst, context->exception.c_str());
        return 0;
    }
}

std::int32_t primitive_bytes_native(wasm_exec_env_t exec_env,
                                    std::uint64_t tag,
                                    std::uint64_t version64,
                                    const std::uint8_t* input,
                                    std::uint32_t input_len,
                                    std::uint8_t* output,
                                    std::uint32_t output_capacity) {
    const auto module_inst = wasm_runtime_get_module_inst(exec_env);
    auto* context = static_cast<ExecutionContext*>(
        wasm_runtime_get_custom_data(module_inst));

    if (!context || !context->registry || !context->limits) {
        wasm_runtime_set_exception(module_inst, "V0ID MathVM context missing");
        return -1;
    }

    try {
        const auto version = checked_version(version64);
        require_declared(*context, tag, version);

        const auto& provider = context->registry->require_bytes(tag, version);
        const auto descriptor = provider.descriptor();

        if (input_len > descriptor.max_input_bytes ||
            input_len > context->limits->max_provider_input_bytes)
            throw std::runtime_error("MathVM byte-provider input exceeds limit");
        if (output_capacity > context->limits->max_provider_output_bytes)
            throw std::runtime_error("MathVM byte-provider output capacity exceeds limit");

        // The NativeSymbol pointer marker translates Wasm offsets to native
        // pointers, but V0ID does not rely on that translation to validate the
        // entire pointer+length range. Validate both directions explicitly before
        // copying input or invoking any native crypto provider.
        if (input_len != 0 &&
            (!input ||
             !wasm_runtime_validate_native_addr(
                 module_inst,
                 const_cast<std::uint8_t*>(input),
                 static_cast<std::uint64_t>(input_len))))
            throw std::runtime_error(
                "MathVM byte-provider input range is outside Wasm memory");

        if (output_capacity != 0 &&
            (!output ||
             !wasm_runtime_validate_native_addr(
                 module_inst,
                 output,
                 static_cast<std::uint64_t>(output_capacity))))
            throw std::runtime_error(
                "MathVM byte-provider output range is outside Wasm memory");

        std::vector<std::uint8_t> input_copy;
        if (input_len != 0)
            input_copy.assign(input, input + input_len);

        consume_provider_budget(*context, descriptor);
        auto result = provider.evaluate_bytes(input_copy);

        if (result.size() > descriptor.max_output_bytes ||
            result.size() > context->limits->max_provider_output_bytes)
            throw std::runtime_error("MathVM byte-provider output exceeds limit");
        if (result.size() > output_capacity)
            throw std::runtime_error("MathVM byte-provider output buffer too small");
        if (result.size() >
            static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
            throw std::runtime_error("MathVM byte-provider output length exceeds i32");

        if (!result.empty())
            std::memcpy(output, result.data(), result.size());
        return static_cast<std::int32_t>(result.size());
    } catch (const std::exception& e) {
        context->exception = e.what();
        wasm_runtime_set_exception(module_inst, context->exception.c_str());
        return -1;
    } catch (...) {
        context->exception = "unknown MathVM byte-provider failure";
        wasm_runtime_set_exception(module_inst, context->exception.c_str());
        return -1;
    }
}

NativeSymbol g_native_symbols[] = {
    {
        "primitive_u64",
        reinterpret_cast<void*>(primitive_u64_native),
        "(IIIIII)I",
        nullptr,
    },
    {
        "primitive_bytes",
        reinterpret_cast<void*>(primitive_bytes_native),
        "(II*~*~)i",
        nullptr,
    },
};

void validate_limits(const SandboxLimits& limits) {
    if (limits.max_module_bytes == 0)
        throw std::runtime_error("MathVM max_module_bytes must be positive");
    if (limits.max_memory_pages == 0)
        throw std::runtime_error("MathVM max_memory_pages must be positive");
    if (limits.stack_bytes < 4096)
        throw std::runtime_error("MathVM stack budget is too small");
    if (limits.runtime_pool_bytes < 1024 * 1024)
        throw std::runtime_error("MathVM runtime pool is too small");
    if (limits.runtime_pool_bytes > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("MathVM runtime pool exceeds WAMR uint32 limit");
    if (limits.max_wasm_instructions <= 0)
        throw std::runtime_error("MathVM instruction budget must be positive");
    if (limits.max_provider_calls == 0 || limits.max_provider_cost == 0)
        throw std::runtime_error("MathVM provider budgets must be positive");
    if (limits.max_provider_input_bytes == 0 ||
        limits.max_provider_output_bytes == 0)
        throw std::runtime_error("MathVM byte-provider limits must be positive");

    const auto linear_memory_cap =
        static_cast<std::uint64_t>(limits.max_memory_pages) * 65536ull;
    if (limits.max_provider_input_bytes > linear_memory_cap ||
        limits.max_provider_output_bytes > linear_memory_cap)
        throw std::runtime_error(
            "MathVM byte-provider limit exceeds linear-memory sandbox cap");
}

void validate_entrypoint(const std::string& entrypoint) {
    if (entrypoint.empty() || entrypoint.size() > 128)
        throw std::runtime_error("invalid MathVM entrypoint length");
    for (unsigned char ch : entrypoint) {
        if (!(std::isalnum(ch) || ch == '_' || ch == '$' || ch == '.' ||
              ch == '-'))
            throw std::runtime_error("invalid MathVM entrypoint character");
    }
}

} // namespace

WamrMathSandbox::WamrMathSandbox(SandboxLimits limits)
    : limits_(limits) {
    validate_limits(limits_);
    runtime_pool_.resize(limits_.runtime_pool_bytes);

    std::lock_guard<std::mutex> lock(g_runtime_mutex);
    if (g_runtime_active)
        throw std::runtime_error("only one V0ID WAMR sandbox may be active");

    RuntimeInitArgs args{};
    args.mem_alloc_type = Alloc_With_Pool;
    args.mem_alloc_option.pool.heap_buf = runtime_pool_.data();
    args.mem_alloc_option.pool.heap_size =
        static_cast<std::uint32_t>(runtime_pool_.size());
    args.native_module_name = "v0id_math";
    args.native_symbols = g_native_symbols;
    args.n_native_symbols =
        static_cast<std::uint32_t>(sizeof(g_native_symbols) /
                                   sizeof(g_native_symbols[0]));
    args.running_mode = Mode_Interp;

    if (!wasm_runtime_full_init(&args))
        throw std::runtime_error("failed to initialize WAMR runtime");

    g_runtime_active = true;
    initialized_ = true;
}

WamrMathSandbox::~WamrMathSandbox() {
    if (!initialized_)
        return;

    std::lock_guard<std::mutex> lock(g_runtime_mutex);
    wasm_runtime_destroy();
    initialized_ = false;
    g_runtime_active = false;
}

ExecutionReport WamrMathSandbox::execute(const WasmMathProgram& program,
                                         const PrimitiveRegistry& registry) {
    std::lock_guard<std::mutex> execution_lock(execution_mutex_);

    if (!initialized_)
        throw std::runtime_error("WAMR MathVM sandbox is not initialized");
    if (program.wasm.empty())
        throw std::runtime_error("MathVM module is empty");
    if (program.wasm.size() > limits_.max_module_bytes)
        throw std::runtime_error("MathVM module exceeds byte limit");
    if (program.wasm.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::runtime_error("MathVM module exceeds WAMR size type");
    validate_entrypoint(program.entrypoint);

    ExecutionContext context;
    context.registry = &registry;
    context.limits = &limits_;

    for (const auto& requirement : program.required_primitives) {
        (void)registry.require(requirement);
        const RequirementKey key{requirement.tag, requirement.version};
        if (!context.allowed.insert(key).second)
            throw std::runtime_error("duplicate MathVM primitive requirement");
    }

    // Enforce the V0ID host-surface and memory policy ourselves before WAMR's
    // loader/linker runs. This remains active even though WAMR is compiled with
    // WASI support disabled and therefore cannot rely on WASI helper symbols.
    validate_wasm_policy(program.wasm, limits_.max_memory_pages);

    auto wasm_bytes = program.wasm;
    const auto package_type = wasm_runtime_get_file_package_type(
        wasm_bytes.data(), static_cast<std::uint32_t>(wasm_bytes.size()));
    if (package_type != Wasm_Module_Bytecode)
        throw std::runtime_error(
            "MathVM accepts Wasm bytecode only, not AOT/native images");

    char error_buf[512]{};
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
    };

    try {
        module = wasm_runtime_load(
            wasm_bytes.data(), static_cast<std::uint32_t>(wasm_bytes.size()),
            error_buf, static_cast<std::uint32_t>(sizeof(error_buf)));
        if (!module)
            throw std::runtime_error(std::string("WAMR load failed: ") + error_buf);

        InstantiationArgs instantiate_args{};
        instantiate_args.default_stack_size = limits_.stack_bytes;
        instantiate_args.host_managed_heap_size = limits_.host_managed_heap_bytes;

        // V0ID already rejects modules whose declared min/max exceeds the cap.
        // Passing a larger runtime override makes WAMR warn when the module chose
        // a smaller maximum, so leave the override at zero and keep policy in the
        // fail-closed prevalidator.
        instantiate_args.max_memory_pages = 0;

        module_inst = wasm_runtime_instantiate_ex(
            module, &instantiate_args, error_buf,
            static_cast<std::uint32_t>(sizeof(error_buf)));
        if (!module_inst)
            throw std::runtime_error(
                std::string("WAMR instantiate failed: ") + error_buf);

        wasm_runtime_set_custom_data(module_inst, &context);

        const auto function = wasm_runtime_lookup_function(
            module_inst, program.entrypoint.c_str());
        if (!function)
            throw std::runtime_error("MathVM entrypoint export not found");

        if (wasm_func_get_param_count(function, module_inst) != 0)
            throw std::runtime_error(
                "MathVM entrypoint must take zero parameters");
        if (wasm_func_get_result_count(function, module_inst) != 1)
            throw std::runtime_error(
                "MathVM entrypoint must return one value");

        wasm_valkind_t result_type{};
        wasm_func_get_result_types(function, module_inst, &result_type);
        if (result_type != WASM_I64)
            throw std::runtime_error("MathVM entrypoint must return i64");

        exec_env = wasm_runtime_create_exec_env(module_inst, limits_.stack_bytes);
        if (!exec_env)
            throw std::runtime_error(
                "failed to create WAMR execution environment");

        wasm_runtime_set_instruction_count_limit(
            exec_env, limits_.max_wasm_instructions);

        wasm_val_t result{};
        if (!wasm_runtime_call_wasm_a(exec_env, function, 1, &result, 0, nullptr)) {
            const char* exception = wasm_runtime_get_exception(module_inst);
            const std::string reason =
                exception ? exception : "unknown WAMR execution failure";
            throw std::runtime_error("MathVM trapped: " + reason);
        }
        if (result.kind != WASM_I64)
            throw std::runtime_error("MathVM returned unexpected value type");

        ExecutionReport report;
        report.result = static_cast<std::uint64_t>(result.of.i64);
        report.provider_calls = context.provider_calls;
        report.provider_cost = context.provider_cost;
        cleanup();
        return report;
    } catch (...) {
        cleanup();
        throw;
    }
}

} // namespace v0id::mathvm
