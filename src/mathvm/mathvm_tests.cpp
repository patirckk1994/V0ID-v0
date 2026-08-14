#include "mathvm.hpp"
#include "wamr_sandbox.hpp"

#include <openssl/evp.h>

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
using v0id::mathvm::make_default_registry;
using v0id::mathvm::PRIMITIVE_ML_KEM_768_ENCAP_BYTES;
using v0id::mathvm::PRIMITIVE_SHA3_256_BYTES;

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

Bytes make_byte_provider_module(std::uint64_t tag,
                                std::uint32_t output_capacity) {
    Bytes module = module_header();

    Bytes types;
    append_uleb(types, 2);
    append_function_type(types,
                         {0x7e, 0x7e, 0x7f, 0x7f, 0x7f, 0x7f},
                         {0x7f}); // primitive_bytes
    append_function_type(types, {}, {0x7e}); // v0id_main
    append_section(module, 1, types);

    Bytes imports;
    append_uleb(imports, 1);
    append_name(imports, "v0id_math");
    append_name(imports, "primitive_bytes");
    imports.push_back(0x00); // function import
    append_uleb(imports, 0); // type index 0
    append_section(module, 2, imports);

    Bytes functions;
    append_uleb(functions, 1);
    append_uleb(functions, 1);
    append_section(module, 3, functions);

    Bytes memories;
    append_uleb(memories, 1);
    memories.push_back(0x01); // explicit min + max
    append_uleb(memories, 1);
    append_uleb(memories, 1);
    append_section(module, 5, memories);

    append_export(module, 1);

    Bytes body;
    append_uleb(body, 0); // local declarations
    body.push_back(0x42); // i64.const tag
    append_sleb_i64(body, static_cast<std::int64_t>(tag));
    body.push_back(0x42); // i64.const version
    append_sleb_i64(body, 1);
    body.push_back(0x41); // i32.const input offset
    append_sleb_i64(body, 0);
    body.push_back(0x41); // i32.const input length
    append_sleb_i64(body, 3);
    body.push_back(0x41); // i32.const output offset
    append_sleb_i64(body, 64);
    body.push_back(0x41); // i32.const output capacity
    append_sleb_i64(body, output_capacity);
    body.push_back(0x10); // call imported primitive_bytes
    append_uleb(body, 0);
    body.push_back(0xad); // i64.extend_i32_u
    body.push_back(0x0b);

    Bytes code;
    append_uleb(code, 1);
    append_uleb(code, body.size());
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);

    Bytes data;
    append_uleb(data, 1); // one active data segment
    append_uleb(data, 0); // active, implicit memory 0
    data.push_back(0x41);  // i32.const 0
    append_sleb_i64(data, 0);
    data.push_back(0x0b);  // end offset expression
    append_uleb(data, 3);
    data.push_back('a');
    data.push_back('b');
    data.push_back('c');
    append_section(module, 11, data);

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

PrimitiveRequirement sha3_requirement() {
    return PrimitiveRequirement{
        PRIMITIVE_SHA3_256_BYTES,
        "v0id.crypto.sha3-256",
        1,
    };
}

PrimitiveRequirement mlkem_requirement() {
    return PrimitiveRequirement{
        PRIMITIVE_ML_KEM_768_ENCAP_BYTES,
        "v0id.pq.ml-kem-768.encapsulate",
        1,
    };
}

std::uint32_t read_u32_be(const Bytes& bytes, std::size_t offset) {
    if (offset + 4 > bytes.size())
        throw std::runtime_error("truncated u32 field");
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
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

void test_ml_kem_if_available(TestRunner& tests,
                              const PrimitiveRegistry& registry) {
    if (!registry.supports(mlkem_requirement())) {
        tests.success(
            "ML-KEM-768 capability absent on linked OpenSSL (optional provider)");
        return;
    }

    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using CtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    KeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768"),
               EVP_PKEY_free);
    if (!key) {
        tests.failure("ML-KEM-768 provider round trip",
                      "provider advertised but key generation failed");
        return;
    }

    std::size_t public_len = 0;
    if (EVP_PKEY_get_raw_public_key(key.get(), nullptr, &public_len) != 1 ||
        public_len == 0) {
        tests.failure("ML-KEM-768 provider round trip",
                      "raw public-key length query failed");
        return;
    }

    Bytes public_key(public_len);
    if (EVP_PKEY_get_raw_public_key(
            key.get(), public_key.data(), &public_len) != 1) {
        tests.failure("ML-KEM-768 provider round trip",
                      "raw public-key export failed");
        return;
    }
    public_key.resize(public_len);

    const auto& provider = registry.require_bytes(
        PRIMITIVE_ML_KEM_768_ENCAP_BYTES, 1);
    const auto packed = provider.evaluate_bytes(public_key);
    if (packed.size() < 8) {
        tests.failure("ML-KEM-768 provider round trip",
                      "provider returned truncated envelope");
        return;
    }

    const auto ciphertext_len = read_u32_be(packed, 0);
    const auto secret_len = read_u32_be(packed, 4);
    if (packed.size() != 8ull + ciphertext_len + secret_len ||
        ciphertext_len == 0 || secret_len == 0) {
        tests.failure("ML-KEM-768 provider round trip",
                      "provider returned invalid envelope lengths");
        return;
    }

    const auto* ciphertext = packed.data() + 8;
    const auto* provider_secret = ciphertext + ciphertext_len;

    CtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr),
               EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0) {
        tests.failure("ML-KEM-768 provider round trip",
                      "OpenSSL decapsulation init failed");
        return;
    }

    std::size_t recovered_len = 0;
    if (EVP_PKEY_decapsulate(ctx.get(), nullptr, &recovered_len,
                             ciphertext, ciphertext_len) <= 0 ||
        recovered_len == 0) {
        tests.failure("ML-KEM-768 provider round trip",
                      "decapsulation output-size query failed");
        return;
    }

    Bytes recovered(recovered_len);
    if (EVP_PKEY_decapsulate(ctx.get(), recovered.data(), &recovered_len,
                             ciphertext, ciphertext_len) <= 0) {
        tests.failure("ML-KEM-768 provider round trip",
                      "decapsulation failed");
        return;
    }
    recovered.resize(recovered_len);

    const Bytes expected_secret(provider_secret,
                                provider_secret + secret_len);
    tests.expect_true("ML-KEM-768 provider round trip",
                      recovered == expected_secret,
                      "encapsulated and decapsulated secrets differ");
}

} // namespace

int main() try {
    TestRunner tests;
    auto registry = make_test_registry();
    auto default_registry = make_default_registry();

    SandboxLimits limits;
    limits.max_module_bytes = 64 * 1024;
    limits.max_memory_pages = 16;
    limits.stack_bytes = 64 * 1024;
    limits.host_managed_heap_bytes = 64 * 1024;
    limits.runtime_pool_bytes = 16 * 1024 * 1024;
    limits.max_wasm_instructions = 10'000;
    limits.max_provider_calls = 1;
    limits.max_provider_cost = 1'000;
    limits.max_provider_input_bytes = 64 * 1024;
    limits.max_provider_output_bytes = 64 * 1024;

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
        tests.expect_true("declared scalar provider executes",
                          report.result == 0 && report.provider_calls == 1 &&
                              report.provider_cost == 7,
                          "expected add-mod result=0, calls=1, cost=7");
    }

    {
        auto program = program_from(
            make_byte_provider_module(PRIMITIVE_SHA3_256_BYTES, 32));
        program.required_primitives = {sha3_requirement()};
        const auto report = sandbox.execute(program, default_registry);
        tests.expect_true("declared byte provider executes through WAMR",
                          report.result == 32 && report.provider_calls == 1 &&
                              report.provider_cost == 256,
                          "expected SHA3 output length=32, calls=1, cost=256");
    }

    {
        const Bytes abc{'a', 'b', 'c'};
        const Bytes expected{
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
        };
        const auto& provider = default_registry.require_bytes(
            PRIMITIVE_SHA3_256_BYTES, 1);
        tests.expect_true("SHA3-256 provider matches known answer for abc",
                          provider.evaluate_bytes(abc) == expected,
                          "SHA3-256 digest mismatch");
    }

    tests.expect_throw("byte provider rejects undersized Wasm output buffer", [&] {
        auto program = program_from(
            make_byte_provider_module(PRIMITIVE_SHA3_256_BYTES, 8));
        program.required_primitives = {sha3_requirement()};
        (void)sandbox.execute(program, default_registry);
    });

    tests.expect_throw("provider ABI mismatch rejected", [&] {
        auto program = program_from(
            make_provider_module(PRIMITIVE_SHA3_256_BYTES, 1));
        program.required_primitives = {sha3_requirement()};
        (void)sandbox.execute(program, default_registry);
    });

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
        auto program = program_from(
            Bytes{0x56, 0x30, 0x49, 0x44, 0xde, 0xad, 0xbe, 0xef});
        (void)sandbox.execute(program, registry);
    });

    tests.expect_throw("WASI import rejected", [&] {
        auto program = program_from(make_wasi_import_module());
        (void)sandbox.execute(program, registry);
    });

    test_ml_kem_if_available(tests, default_registry);

    {
        auto program = program_from(make_const_module(9));
        const auto report = sandbox.execute(program, registry);
        tests.expect_true("sandbox recovers after rejected/trapped jobs",
                          report.result == 9,
                          "expected final recovery result=9");
    }

    std::cout << "\nV0ID MathVM sandbox/provider tests: " << tests.passed
              << " passed, " << tests.failed << " failed\n";

    if (tests.failed != 0)
        return 1;

    std::cout << "OK: MathVM scalar/byte provider boundary exercised\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID MathVM test harness fatal error: " << e.what() << '\n';
    return 2;
}
