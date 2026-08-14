#pragma once

#include "mathvm.hpp"

#include <cstdint>
#include <mutex>
#include <vector>

namespace v0id::mathvm {

// Process-local WAMR runtime wrapper. The current profile intentionally allows
// only one active sandbox instance at a time because WAMR runtime initialization
// is process-global. WAMR executes only portable Wasm bytecode here; AOT/JIT and
// WASI are disabled. ABI v2 exposes typed scalar and bounded-byte host calls.
class WamrMathSandbox {
public:
    explicit WamrMathSandbox(SandboxLimits limits = {});
    ~WamrMathSandbox();

    WamrMathSandbox(const WamrMathSandbox&) = delete;
    WamrMathSandbox& operator=(const WamrMathSandbox&) = delete;
    WamrMathSandbox(WamrMathSandbox&&) = delete;
    WamrMathSandbox& operator=(WamrMathSandbox&&) = delete;

    ExecutionReport execute(const WasmMathProgram& program,
                            const PrimitiveRegistry& registry);

    const SandboxLimits& limits() const noexcept { return limits_; }

private:
    SandboxLimits limits_;
    std::vector<std::uint8_t> runtime_pool_;
    std::mutex execution_mutex_;
    bool initialized_{};
};

} // namespace v0id::mathvm
