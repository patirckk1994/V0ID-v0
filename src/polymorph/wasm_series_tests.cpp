#include "wasm_series_generator.hpp"

#include "program.hpp"
#include "program_morpher.hpp"

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
using v0id::core::Program;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::SeriesProfile;
using v0id::polymorph::SeriesSeed;
using v0id::polymorph::WasmSeriesGenerator;
using v0id::polymorph::WasmSeriesLimits;

void append_uleb(Bytes& out, std::uint64_t value) {
    do {
        auto byte = static_cast<std::uint8_t>(value & 0x7fu);
        value >>= 7u;
        if (value != 0)
            byte |= 0x80u;
        out.push_back(byte);
    } while (value != 0);
}

void append_sleb(Bytes& out, std::int64_t value) {
    bool more = true;
    while (more) {
        auto byte = static_cast<std::uint8_t>(value & 0x7f);
        const bool sign = (byte & 0x40u) != 0;
        value >>= 7;
        if ((value == 0 && !sign) || (value == -1 && sign))
            more = false;
        else
            byte |= 0x80u;
        out.push_back(byte);
    }
}

void append_name(Bytes& out, const std::string& name) {
    append_uleb(out, name.size());
    out.insert(out.end(), name.begin(), name.end());
}

void append_section(Bytes& module, std::uint8_t id, const Bytes& payload) {
    module.push_back(id);
    append_uleb(module, payload.size());
    module.insert(module.end(), payload.begin(), payload.end());
}

void append_type(Bytes& out,
                 const std::vector<std::uint8_t>& params,
                 const std::vector<std::uint8_t>& results) {
    out.push_back(0x60);
    append_uleb(out, params.size());
    out.insert(out.end(), params.begin(), params.end());
    append_uleb(out, results.size());
    out.insert(out.end(), results.begin(), results.end());
}

void emit_local_get(Bytes& body, std::uint32_t index) {
    body.push_back(0x20);
    append_uleb(body, index);
}

void emit_i32_const(Bytes& body, std::int32_t value) {
    body.push_back(0x41);
    append_sleb(body, value);
}

void emit_output_address(Bytes& body, std::uint32_t offset) {
    emit_local_get(body, 4); // output_ptr
    emit_i32_const(body, static_cast<std::int32_t>(offset));
    body.push_back(0x6a); // i32.add
}

void emit_store8_const(Bytes& body, std::uint32_t offset, std::uint8_t value) {
    emit_output_address(body, offset);
    emit_i32_const(body, value);
    body.push_back(0x3a); // i32.store8
    append_uleb(body, 0); // align
    append_uleb(body, 0); // offset
}

void emit_load8(Bytes& body, std::uint32_t pointer_param,
                std::uint32_t offset = 0) {
    emit_local_get(body, pointer_param);
    if (offset != 0) {
        emit_i32_const(body, static_cast<std::int32_t>(offset));
        body.push_back(0x6a); // i32.add
    }
    body.push_back(0x2d); // i32.load8_u
    append_uleb(body, 0);
    append_uleb(body, 0);
}

enum class GuestMode {
    valid,
    malformed_result,
    infinite_loop,
};

Bytes make_guest(GuestMode mode = GuestMode::valid,
                 std::uint32_t min_pages = 1,
                 std::uint32_t max_pages = 1) {
    Bytes module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};

    Bytes types;
    append_uleb(types, 2);
    append_type(types, {}, {0x7f});
    append_type(types,
                {0x7f, 0x7f, 0x7f, 0x7e, 0x7f, 0x7f},
                {0x7f});
    append_section(module, 1, types);

    Bytes functions;
    append_uleb(functions, 2);
    append_uleb(functions, 0);
    append_uleb(functions, 1);
    append_section(module, 3, functions);

    Bytes memories;
    append_uleb(memories, 1);
    append_uleb(memories, 1); // min+max
    append_uleb(memories, min_pages);
    append_uleb(memories, max_pages);
    append_section(module, 5, memories);

    Bytes exports;
    append_uleb(exports, 2);
    append_name(exports, "v0id_buffer_base");
    exports.push_back(0x00);
    append_uleb(exports, 0);
    append_name(exports, "v0id_polymorph");
    exports.push_back(0x00);
    append_uleb(exports, 1);
    append_section(module, 7, exports);

    Bytes base_body;
    append_uleb(base_body, 0);
    emit_i32_const(base_body, 1024);
    base_body.push_back(0x0b);

    Bytes poly_body;
    append_uleb(poly_body, 0);

    if (mode == GuestMode::infinite_loop) {
        poly_body.push_back(0x03); // loop
        poly_body.push_back(0x40); // void
        poly_body.push_back(0x0c); // br
        append_uleb(poly_body, 0);
        poly_body.push_back(0x0b);
        emit_i32_const(poly_body, 0);
        poly_body.push_back(0x0b);
    }
    else if (mode == GuestMode::malformed_result) {
        emit_i32_const(poly_body, 4);
        poly_body.push_back(0x0b);
    }
    else {
        emit_store8_const(poly_body, 0, 'V');
        emit_store8_const(poly_body, 1, '0');
        emit_store8_const(poly_body, 2, 'P');
        emit_store8_const(poly_body, 3, '1');
        emit_store8_const(poly_body, 7, 1); // u32be series length = 1

        // MorphSeed[0] = seed[0] XOR low(epoch).
        emit_output_address(poly_body, 12);
        emit_load8(poly_body, 0);
        emit_local_get(poly_body, 3);
        poly_body.push_back(0xa7); // i32.wrap_i64
        poly_body.push_back(0x73); // i32.xor
        poly_body.push_back(0x3a); // i32.store8
        append_uleb(poly_body, 0);
        append_uleb(poly_body, 0);

        // series[0] = seed[1] XOR input[0] XOR low(epoch).
        emit_output_address(poly_body, 44);
        emit_load8(poly_body, 0, 1);
        emit_load8(poly_body, 1);
        poly_body.push_back(0x73); // i32.xor
        emit_local_get(poly_body, 3);
        poly_body.push_back(0xa7); // i32.wrap_i64
        poly_body.push_back(0x73); // i32.xor
        poly_body.push_back(0x3a); // i32.store8
        append_uleb(poly_body, 0);
        append_uleb(poly_body, 0);

        emit_i32_const(poly_body, 45);
        poly_body.push_back(0x0b);
    }

    Bytes code;
    append_uleb(code, 2);
    append_uleb(code, base_body.size());
    code.insert(code.end(), base_body.begin(), base_body.end());
    append_uleb(code, poly_body.size());
    code.insert(code.end(), poly_body.begin(), poly_body.end());
    append_section(module, 10, code);

    return module;
}

Bytes make_importing_guest() {
    Bytes module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};

    Bytes types;
    append_uleb(types, 1);
    append_type(types, {}, {});
    append_section(module, 1, types);

    Bytes imports;
    append_uleb(imports, 1);
    append_name(imports, "env");
    append_name(imports, "anything");
    imports.push_back(0x00);
    append_uleb(imports, 0);
    append_section(module, 2, imports);

    Bytes memories;
    append_uleb(memories, 1);
    append_uleb(memories, 1);
    append_uleb(memories, 1);
    append_uleb(memories, 1);
    append_section(module, 5, memories);
    return module;
}

SeriesProfile test_profile() {
    return {"v0id-local-wasm-test", 1, {}};
}

WasmSeriesLimits test_limits() {
    WasmSeriesLimits limits;
    limits.max_module_bytes = 64 * 1024;
    limits.max_memory_pages = 1;
    limits.stack_bytes = 64 * 1024;
    limits.runtime_pool_bytes = 8 * 1024 * 1024;
    limits.max_wasm_instructions = 10'000;
    limits.max_input_bytes = 128;
    limits.max_output_bytes = 1024;
    limits.max_series_bytes = 128;
    limits.max_private_manifest_bytes = 128;
    return limits;
}

SeriesSeed test_seed(std::uint8_t bias = 0) {
    SeriesSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i + bias);
    return seed;
}

std::vector<int> run_plaintext(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t steps) {
    program.validate();
    auto tape = input;
    std::size_t state = initial_state;
    std::size_t head = 0;
    for (std::size_t s = 0; s < steps; ++s) {
        const auto& rule = program.rule(state, tape.at(head));
        tape[head] = rule.write;
        state = rule.next_state;
        if (rule.move < 0 && head > 0)
            --head;
        else if (rule.move > 0 && head + 1 < tape.size())
            ++head;
    }
    return tape;
}

struct TestRunner {
    int passed{};
    int failed{};

    void pass(const std::string& name) {
        ++passed;
        std::cout << "[PASS] " << name << '\n';
    }

    void fail(const std::string& name, const std::string& reason) {
        ++failed;
        std::cerr << "[FAIL] " << name << ": " << reason << '\n';
    }

    void expect(bool condition, const std::string& name,
                const std::string& reason) {
        if (condition)
            pass(name);
        else
            fail(name, reason);
    }

    void expect_throw(const std::string& name,
                      const std::function<void()>& fn) {
        try {
            fn();
            fail(name, "operation unexpectedly succeeded");
        } catch (const std::exception& e) {
            pass(name + " -> " + e.what());
        }
    }
};

} // namespace

int main() try {
    TestRunner tests;
    const Bytes input{1, 2, 3};
    const auto seed = test_seed();

    WasmSeriesGenerator generator(make_guest(), test_profile(), test_limits());
    const auto a = generator.derive(input, seed, 7);
    const auto b = generator.derive(input, seed, 7);

    tests.expect(a.series == b.series &&
                     a.morph_seed == b.morph_seed &&
                     a.private_manifest == b.private_manifest,
                 "same seed/input/epoch is deterministic",
                 "repeated derivation changed output");

    const auto different_epoch = generator.derive(input, seed, 8);
    tests.expect(a.series != different_epoch.series ||
                     a.morph_seed != different_epoch.morph_seed,
                 "changed epoch changes derived morph material",
                 "epoch change did not affect output");

    const auto different_input = generator.derive(Bytes{9, 2, 3}, seed, 7);
    tests.expect(a.series != different_input.series,
                 "changed semantic input changes private series",
                 "input change did not affect series");

    tests.expect(a.series.size() == 1 && a.private_manifest.empty(),
                 "canonical V0P1 envelope decoded",
                 "unexpected synthetic envelope lengths");

    {
        const Program increment{2, {
            {0, 0, 1, 1,  0},
            {0, 1, 0, 0, +1},
            {1, 0, 1, 0,  0},
            {1, 1, 1, 1,  0},
        }};
        const std::vector<int> bits{1,0,1,1,0,0,0,0};
        const std::vector<int> expected{0,1,1,1,0,0,0,0};
        const auto morph = ProgramMorpher::morph(
            increment, 0, 4, a.morph_seed, 4);
        tests.expect(run_plaintext(morph.program, morph.initial_state, bits, 4) == expected,
                     "Wasm-derived MorphSeed preserves ProgramMorpher semantics",
                     "morphed increment program changed semantic result");
    }

    tests.expect_throw("host imports rejected before WAMR execution", [&] {
        WasmSeriesGenerator bad(make_importing_guest(), test_profile(), test_limits());
        (void)bad;
    });

    tests.expect_throw("malformed guest result rejected", [&] {
        WasmSeriesGenerator bad(make_guest(GuestMode::malformed_result),
                                test_profile(), test_limits());
        (void)bad.derive(input, seed, 7);
    });

    tests.expect_throw("instruction budget stops infinite polymorphism guest", [&] {
        auto limits = test_limits();
        limits.max_wasm_instructions = 100;
        WasmSeriesGenerator bad(make_guest(GuestMode::infinite_loop),
                                test_profile(), limits);
        (void)bad.derive(input, seed, 7);
    });

    tests.expect_throw("module memory above local cap rejected", [&] {
        WasmSeriesGenerator bad(make_guest(GuestMode::valid, 2, 2),
                                test_profile(), test_limits());
        (void)bad;
    });

    tests.expect_throw("semantic input above local cap rejected", [&] {
        Bytes too_large(test_limits().max_input_bytes + 1, 0x41);
        (void)generator.derive(too_large, seed, 7);
    });

    std::cout << "\nV0ID local Wasm polymorphism tests: "
              << tests.passed << " passed, " << tests.failed << " failed\n";
    if (tests.failed != 0)
        return 1;

    std::cout << "OK: client-only Wasm derived bounded morph material and trusted C++ applied it\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID local Wasm polymorphism test harness fatal error: "
              << e.what() << '\n';
    return 2;
}
