#include "mathvm.hpp"
#include "wamr_sandbox.hpp"

#include <cstdint>
#include <exception>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;
using v0id::mathvm::FunctionalU64Provider;
using v0id::mathvm::PrimitiveDescriptor;
using v0id::mathvm::PrimitiveRegistry;
using v0id::mathvm::PrimitiveRequirement;
using v0id::mathvm::SandboxLimits;
using v0id::mathvm::WamrMathSandbox;
using v0id::mathvm::WasmMathProgram;

constexpr std::uint64_t TEST_PROVIDER_TAG = 1;
constexpr std::uint32_t TEST_PROVIDER_VERSION = 1;
constexpr const char* TEST_PROVIDER_ID = "v0id.test.add-mod-u64";

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

Bytes module_header() {
    return Bytes{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
}

void append_function_type(Bytes& out,
                          const std::vector<std::uint8_t>& params,
                          const std::vector<std::uint8_t>& results) {
    out.push_back(0x60); // functype
    append_uleb(out, params.size());
    out.insert(out.end(), params.begin(), params.end());
    append_uleb(out, results.size());
    out.insert(out.end(), results.begin(), results.end());
}

void append_export(Bytes& module, std::uint32_t function_index) {
    Bytes exports;
    append_uleb(exports, 1);
    append_name(exports, "v0id_main");
    exports.push_back(0x00); // function export
    append_uleb(exports, function_index);
    append_section(module, 7, exports);
}

Bytes make_const_module(std::int64_t value,
                        std::uint32_t memory_min_pages = 0,
                        std::uint32_t memory_max_pages = 0) {
    Bytes module = module_header();

    Bytes types;
    append_uleb(types, 1);
    append_function_type(types, {}, {0x7e}); // () -> i64
    append_section(module, 1, types);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 0);
    append_section(module, 3, functions);

    if (memory_min_pages != 0 || memory_max_pages != 0) {
        Bytes memories;
        append_uleb(memories, 1);
        memories.push_back(0x01); // min + max
        append_uleb(memories, memory_min_pages);
        append_uleb(memories, memory_max_pages);
        append_section(module, 5, memories);
    }

    append_export(module, 0);

    Bytes body;
    append_uleb(body, 0); // local declarations
    body.push_back(0x42); // i64.const
    append_sleb_i64(body, value);
    body.push_back(0x0b); // end

    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

Bytes make_infinite_loop_module() {
    Bytes module = module_header();

    Bytes types;
    append_uleb(types, 1);
    append_function_type(types, {}, {0x7e});
    append_section(module, 1, types);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 0);
    append_section(module, 3, functions);

    append_export(module, 0);

    Bytes body{
        0x00,       // local declarations
        0x03, 0x40, // loop void
        0x0c, 0x00, // br 0
        0x0b,       // end loop (unreachable)
        0x42, 0x00, // i64.const 0
        0x0b        // end function
    };

    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

Bytes make_provider_module(std::uint64_t tag, std::size_t calls) {
    if (tag > 63)
        throw std::runtime_error("test provider tag must fit one-byte signed LEB");
    if (calls == 0)
        throw std::runtime_error("provider test module needs at least one call");

    Bytes module = module_header();

    Bytes types;
    append_uleb(types, 2);
    append_function_type(types,
                         {0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e},
                         {0x7e}); // primitive_u64
    append_function_type(types, {}, {0x7e}); // v0id_main
    append_section(module, 1, types);

    Bytes imports;
    append_uleb(imports, 1);
    append_name(imports, "v0id_math");
    append_name(imports, "primitive_u64");
    imports.push_back(0x00); // function import
    append_uleb(imports, 0); // type index 0
    append_section(module, 2, imports);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 1); // local function uses type index 1
    append_section(module, 3, functions);

    append_export(module, 1); // imported function is index 0

    Bytes body;
    append_uleb(body, 0); // local declarations
    for (std::size_t i = 0; i < calls; ++i) {
        const std::int64_t args[] = {
            static_cast<std::int64_t>(tag),
            TEST_PROVIDER_VERSION,
            2,
            3,
            5,
            0,
        };
        for (const auto arg : args) {
            body.push_back(0x42); // i64.const
            append_sleb_i64(body, arg);
        }
        body.push_back(0x10); // call
        append_uleb(body, 0);
        if (i + 1 != calls)
            body.push_back(0x1a); // drop all but final result
    }
    body.push_back(0x0b);

    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

Bytes make_wasi_import_module() {
    Bytes module = module_header();

    Bytes types;
    append_uleb(types, 2);
    append_function_type(types,
                         {0x7f, 0x7f, 0x7f, 0x7f},
                         {0x7f}); // fd_write-ish signature
    append_function_type(types, {}, {0x7e});
    append_section(module, 1, types);

    Bytes imports;
    append_uleb(imports, 1);
    append_name(imports, "wasi_snapshot_preview1");
    append_name(imports, "fd_write");
    imports.push_back(0x00); // function import
    append_uleb(imports, 0);
    append_section(module, 2, imports);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 1);
    append_section(module, 3, functions);

    append_export(module, 1);

    Bytes body{0x00, 0x42, 0x00, 0x0b};
    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

PrimitiveRegistry make_test_registry() {
    PrimitiveRegistry registry;
    registry.register_provider(std::make_shared<FunctionalU64Provider>(
        PrimitiveDescriptor{
            TEST_PROVIDER_TAG,
            TEST_PROVIDER_ID,
            TEST_PROVIDER_VERSION,
            7,
            true,
        },
        [](std::uint64_t a,
           std::uint64_t b,
           std::uint64_t modulus,
           std::uint64_t) -> std::uint64_t {
            if (modulus == 0)
                throw std::runtime_error("test modulus is zero");
            return ((a % modulus) + (b % modulus)) % modulus;
        }));
    return registry;
}

PrimitiveRequirement test_requirement() {
    return PrimitiveRequirement{
        TEST_PROVIDER_TAG,
        TEST_PROVIDER_ID,
        TEST_PROVIDER_VERSION,
    };
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

    void expect_true(const std::string& name, bool condition,
                     const std::string& failure_reason) {
        if (condition)
            success(name);
        else
            failure(name, failure_reason);
    }
};

WasmMathProgram program_from(Bytes wasm) {
    WasmMathProgram program;
    program.wasm = std::move(wasm);
    program.entrypoint = "v0id_main";
    return program;
}

} // namespace

int main() try {
    TestRunner tests;
    auto registry = make_test_registry();

    SandboxLimits limits;
    limits.max_module_bytes = 64 * 1024;
    limits.max_memory_pages = 16;
    limits.stack_bytes = 64 * 1024;
    limits.host_managed_heap_bytes = 64 * 1024;
    limits.runtime_pool_bytes = 16 * 1024 * 1024;
    limits.max_wasm_instructions = 10'000;
    limits.max_provider_calls = 1;
    limits.max_provider_cost = 100;

    WamrMathSandbox sandbox(limits);

    {
        auto program = program_from(make_const_module(7));
        const auto report = sandbox.execute(program, registry);
        tests.expect_true("valid Wasm executes",
                          report.result == 7 && report.provider_calls == 0,
                          "expected result=7 and zero provider calls");
    }

    {
        auto program = program_from(make_provider_module(TEST_PROVIDER_TAG, 1));
        program.required_primitives = {test_requirement()};
        const auto report = sandbox.execute(program, registry);
        tests.expect_true("declared provider executes",
                          report.result == 0 && report.provider_calls == 1 &&
                              report.provider_cost == 7,
                          "expected add-mod result=0, calls=1, cost=7");
    }

    tests.expect_throw("manifest id/tag mismatch rejected", [&] {
        (void)registry.require(PrimitiveRequirement{
            TEST_PROVIDER_TAG,
            "wrong-provider-name",
            TEST_PROVIDER_VERSION,
        });
    });

    tests.expect_throw("undeclared provider call rejected", [&] {
        auto program = program_from(make_provider_module(TEST_PROVIDER_TAG, 1));
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("provider call budget enforced", [&] {
        auto program = program_from(make_provider_module(TEST_PROVIDER_TAG, 2));
        program.required_primitives = {test_requirement()};
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("infinite loop hits instruction budget", [&] {
        auto program = program_from(make_infinite_loop_module());
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("oversized module rejected before load", [&] {
        WasmMathProgram program;
        program.wasm.resize(limits.max_module_bytes + 1, 0);
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("module memory minimum above sandbox cap rejected", [&] {
        auto program = program_from(make_const_module(1, 32, 32));
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("non-Wasm/AOT-like input rejected", [&] {
        auto program = program_from(Bytes{0x56, 0x30, 0x49, 0x44, 0xde, 0xad, 0xbe, 0xef});
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("WASI import rejected", [&] {
        auto program = program_from(make_wasi_import_module());
        (void)sandbox.execute(program, registry);
    });

    {
        auto program = program_from(make_const_module(9));
        const auto report = sandbox.execute(program, registry);
        tests.expect_true("sandbox recovers after rejected/trapped jobs",
                          report.result == 9,
                          "expected final recovery result=9");
    }

    std::cout << "\nV0ID MathVM sandbox tests: " << tests.passed
              << " passed, " << tests.failed << " failed\n";

    if (tests.failed != 0)
        return 1;

    std::cout << "OK: local MathVM sandbox rejection boundary exercised\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID MathVM test harness fatal error: " << e.what() << '\n';
    return 2;
}
