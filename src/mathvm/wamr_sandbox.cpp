#include "wamr_sandbox.hpp"

#include "wasm_export.h"

#include <cctype>
#include <cstdint>
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
        if (version64 == 0 ||
            version64 > std::numeric_limits<std::uint32_t>::max())
            throw std::runtime_error("invalid primitive version");

        const auto version = static_cast<std::uint32_t>(version64);
        if (!context->allowed.contains(RequirementKey{tag, version}))
            throw std::runtime_error("Wasm called undeclared primitive");

        const auto& provider = context->registry->require(tag, version);
        const auto descriptor = provider.descriptor();

        if (context->provider_calls >= context->limits->max_provider_calls)
            throw std::runtime_error("MathVM provider call budget exhausted");
        ++context->provider_calls;

        if (descriptor.cost > context->limits->max_provider_cost ||
            context->provider_cost >
                context->limits->max_provider_cost - descriptor.cost)
            throw std::runtime_error("MathVM provider cost budget exhausted");
        context->provider_cost += descriptor.cost;

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

NativeSymbol g_native_symbols[] = {
    {
        "primitive_u64",
        reinterpret_cast<void*>(primitive_u64_native),
        "(IIIIII)I",
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
    // Validate attacker/configuration-controlled sizes before allocating the
    // process-global WAMR memory pool.
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

    // WAMR may modify the supplied byte buffer while loading, so keep a mutable
    // private copy alive until wasm_runtime_unload(). Only portable Wasm bytecode
    // is accepted; native AOT images are intentionally rejected.
    auto wasm_bytes = program.wasm;
    const auto package_type = wasm_runtime_get_file_package_type(
        wasm_bytes.data(), static_cast<std::uint32_t>(wasm_bytes.size()));
    if (package_type != Wasm_Module_Bytecode)
        throw std::runtime_error("MathVM accepts Wasm bytecode only, not AOT/native images");

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
        instantiate_args.max_memory_pages = limits_.max_memory_pages;

        module_inst = wasm_runtime_instantiate_ex(
            module, &instantiate_args, error_buf,
            static_cast<std::uint32_t>(sizeof(error_buf)));
        if (!module_inst)
            throw std::runtime_error(std::string("WAMR instantiate failed: ") + error_buf);

        if (wasm_runtime_is_wasi_mode(module_inst))
            throw std::runtime_error("WASI modules are forbidden by V0ID MathVM");

        wasm_runtime_set_custom_data(module_inst, &context);

        const auto function = wasm_runtime_lookup_function(
            module_inst, program.entrypoint.c_str());
        if (!function)
            throw std::runtime_error("MathVM entrypoint export not found");

        if (wasm_func_get_param_count(function, module_inst) != 0)
            throw std::runtime_error("MathVM v1 entrypoint must take zero parameters");
        if (wasm_func_get_result_count(function, module_inst) != 1)
            throw std::runtime_error("MathVM v1 entrypoint must return one value");

        wasm_valkind_t result_type{};
        wasm_func_get_result_types(function, module_inst, &result_type);
        if (result_type != WASM_I64)
            throw std::runtime_error("MathVM v1 entrypoint must return i64");

        exec_env = wasm_runtime_create_exec_env(module_inst, limits_.stack_bytes);
        if (!exec_env)
            throw std::runtime_error("failed to create WAMR execution environment");

        // WAMR instruction metering is enabled only in classic interpreter mode
        // by the V0ID CMake profile. Native provider work has a separate budget.
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
