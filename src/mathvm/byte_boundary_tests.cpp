#include "mathvm.hpp"
#include "wamr_sandbox.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;
using v0id::mathvm::PrimitiveRequirement;
using v0id::mathvm::SandboxLimits;
using v0id::mathvm::WamrMathSandbox;
using v0id::mathvm::WasmMathProgram;
using v0id::mathvm::make_default_registry;
using v0id::mathvm::PRIMITIVE_SHA3_256_BYTES;

void append_uleb(Bytes& out, std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fu);
        value >>= 7u;
        if (value != 0)
            byte |= 0x80u;
        out.push_back(byte);
    } while (value != 0);
}

void append_sleb_i64(Bytes& out, std::int64_t value) {
    bool more = true;
    while (more) {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        const bool sign_bit = (byte & 0x40u) != 0;
        value >>= 7;
        if ((value == 0 && !sign_bit) || (value == -1 && sign_bit))
            more = false;
        else
            byte |= 0x80u;
        out.push_back(byte);
    }
}

void append_name(Bytes& out, const std::string& value) {
    append_uleb(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void append_section(Bytes& module, std::uint8_t id, const Bytes& payload) {
    module.push_back(id);
    append_uleb(module, payload.size());
    module.insert(module.end(), payload.begin(), payload.end());
}

void append_function_type(Bytes& out,
                          const std::vector<std::uint8_t>& params,
                          const std::vector<std::uint8_t>& results) {
    out.push_back(0x60);
    append_uleb(out, params.size());
    out.insert(out.end(), params.begin(), params.end());
    append_uleb(out, results.size());
    out.insert(out.end(), results.begin(), results.end());
}

Bytes make_byte_call_module(std::uint32_t input_offset,
                            std::uint32_t input_length,
                            std::uint32_t output_offset,
                            std::uint32_t output_capacity,
                            const Bytes& initial_data) {
    Bytes module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};

    Bytes types;
    append_uleb(types, 2);
    append_function_type(types,
                         {0x7e, 0x7e, 0x7f, 0x7f, 0x7f, 0x7f},
                         {0x7f}); // primitive_bytes -> i32 output length
    append_function_type(types, {}, {0x7e}); // v0id_main -> i64
    append_section(module, 1, types);

    Bytes imports;
    append_uleb(imports, 1);
    append_name(imports, "v0id_math");
    append_name(imports, "primitive_bytes");
    imports.push_back(0x00);
    append_uleb(imports, 0);
    append_section(module, 2, imports);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 1);
    append_section(module, 3, functions);

    // Exactly one 64 KiB page. The OOB test deliberately supplies a range that
    // crosses this boundary so WAMR's native argument validation must trap it.
    Bytes memories;
    append_uleb(memories, 1);
    memories.push_back(0x01); // explicit min + max
    append_uleb(memories, 1);
    append_uleb(memories, 1);
    append_section(module, 5, memories);

    Bytes exports;
    append_uleb(exports, 1);
    append_name(exports, "v0id_main");
    exports.push_back(0x00);
    append_uleb(exports, 1); // imported primitive is function index 0
    append_section(module, 7, exports);

    Bytes body;
    append_uleb(body, 0); // no locals
    body.push_back(0x42); // i64.const tag
    append_sleb_i64(body, static_cast<std::int64_t>(PRIMITIVE_SHA3_256_BYTES));
    body.push_back(0x42); // i64.const version
    append_sleb_i64(body, 1);
    body.push_back(0x41); // i32.const input offset
    append_sleb_i64(body, input_offset);
    body.push_back(0x41); // i32.const input length
    append_sleb_i64(body, input_length);
    body.push_back(0x41); // i32.const output offset
    append_sleb_i64(body, output_offset);
    body.push_back(0x41); // i32.const output capacity
    append_sleb_i64(body, output_capacity);
    body.push_back(0x10); // call primitive_bytes
    append_uleb(body, 0);
    body.push_back(0xad); // i64.extend_i32_u
    body.push_back(0x0b);

    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);

    if (!initial_data.empty()) {
        Bytes data;
        append_uleb(data, 1);
        append_uleb(data, 0); // active segment, memory 0
        data.push_back(0x41);  // i32.const 0
        append_sleb_i64(data, 0);
        data.push_back(0x0b);
        append_uleb(data, initial_data.size());
        data.insert(data.end(), initial_data.begin(), initial_data.end());
        append_section(module, 11, data);
    }

    return module;
}

PrimitiveRequirement sha3_requirement() {
    return {
        PRIMITIVE_SHA3_256_BYTES,
        "v0id.crypto.sha3-256",
        1,
    };
}

WasmMathProgram program_from(Bytes wasm) {
    WasmMathProgram program;
    program.wasm = std::move(wasm);
    program.entrypoint = "v0id_main";
    program.required_primitives = {sha3_requirement()};
    return program;
}

struct TestRunner {
    int passed{};
    int failed{};

    void success(const std::string& name) {
        ++passed;
        std::cout << "[PASS] " << name << '\n';
    }

    void failure(const std::string& name, const std::string& reason) {
        ++failed;
        std::cerr << "[FAIL] " << name << ": " << reason << '\n';
    }

    void expect_throw(const std::string& name,
                      const std::function<void()>& function) {
        try {
            function();
            failure(name, "operation unexpectedly succeeded");
        } catch (const std::exception& e) {
            success(name + " -> " + e.what());
        } catch (...) {
            success(name + " -> non-standard exception");
        }
    }
};

} // namespace

int main() try {
    TestRunner tests;
    auto registry = make_default_registry();

    SandboxLimits limits;
    limits.max_module_bytes = 64 * 1024;
    limits.max_memory_pages = 1;
    limits.stack_bytes = 64 * 1024;
    limits.host_managed_heap_bytes = 64 * 1024;
    limits.runtime_pool_bytes = 16 * 1024 * 1024;
    limits.max_wasm_instructions = 10'000;
    limits.max_provider_calls = 4;
    limits.max_provider_cost = 2'000;
    limits.max_provider_input_bytes = 8;
    limits.max_provider_output_bytes = 64;

    WamrMathSandbox sandbox(limits);

    tests.expect_throw("OOB Wasm byte-provider input range rejected", [&] {
        // 65535 is the final byte of a one-page memory. A two-byte range crosses
        // the 65536-byte boundary and must never reach the native provider.
        auto program = program_from(make_byte_call_module(
            65535, 2, 64, 32, Bytes{}));
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("byte-provider input above sandbox cap rejected", [&] {
        auto program = program_from(make_byte_call_module(
            0, 9, 64, 32,
            Bytes{'0', '1', '2', '3', '4', '5', '6', '7', '8'}));
        (void)sandbox.execute(program, registry);
    });

    {
        auto program = program_from(make_byte_call_module(
            0, 3, 64, 32, Bytes{'a', 'b', 'c'}));
        const auto report = sandbox.execute(program, registry);
        if (report.result == 32 && report.provider_calls == 1 &&
            report.provider_cost == 256) {
            tests.success("sandbox recovers after byte-boundary traps");
        } else {
            tests.failure("sandbox recovers after byte-boundary traps",
                          "expected SHA3 result=32, calls=1, cost=256");
        }
    }

    std::cout << "\nV0ID MathVM byte-boundary tests: " << tests.passed
              << " passed, " << tests.failed << " failed\n";

    if (tests.failed != 0)
        return 1;

    std::cout << "OK: MathVM byte-provider pointer/length boundary exercised\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID MathVM byte-boundary test fatal error: "
              << e.what() << '\n';
    return 2;
}
