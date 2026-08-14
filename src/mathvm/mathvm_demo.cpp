#include "mathvm.hpp"
#include "wamr_sandbox.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<std::uint8_t> read_binary(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot open Wasm module: " + path);

    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void print_usage(const char* argv0) {
    std::cerr
        << "usage: " << argv0 << " <module.wasm> [series|sha3]\n\n"
        << "The default profile is 'series' for backward compatibility.\n\n"
        << "Series demo:\n"
        << "  clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry "
           "-Wl,--allow-undefined -Wl,--export=v0id_main "
           "-Wl,--initial-memory=131072 -Wl,--max-memory=1048576 "
           "examples/mathvm/series_math.c -o build/series_math.wasm\n"
        << "  " << argv0 << " build/series_math.wasm series\n\n"
        << "SHA3 byte-provider demo:\n"
        << "  clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry "
           "-Wl,--allow-undefined -Wl,--export=v0id_main "
           "-Wl,--initial-memory=131072 -Wl,--max-memory=1048576 "
           "examples/mathvm/sha3_bytes.c -o build/sha3_bytes.wasm\n"
        << "  " << argv0 << " build/sha3_bytes.wasm sha3\n";
}

void configure_series_profile(v0id::mathvm::WasmMathProgram& program,
                              std::uint64_t& expected_result,
                              std::uint64_t& expected_calls) {
    program.required_primitives = {
        {
            v0id::mathvm::PRIMITIVE_ADD_MOD_U64,
            "v0id.math.add-mod-u64",
            1,
        },
        {
            v0id::mathvm::PRIMITIVE_MUL_MOD_U64,
            "v0id.math.mul-mod-u64",
            1,
        },
        {
            v0id::mathvm::PRIMITIVE_TOY_LWE_AFFINE_U64,
            "v0id.experimental.toy-lwe-affine-u64",
            1,
        },
    };
    expected_result = 1596;
    expected_calls = 3;
}

void configure_sha3_profile(v0id::mathvm::WasmMathProgram& program,
                            std::uint64_t& expected_result,
                            std::uint64_t& expected_calls) {
    program.required_primitives = {
        {
            v0id::mathvm::PRIMITIVE_SHA3_256_BYTES,
            "v0id.crypto.sha3-256",
            1,
        },
    };
    expected_result = 32;
    expected_calls = 1;
}

} // namespace

int main(int argc, char** argv) try {
    if (argc < 2 || argc > 3) {
        print_usage(argv[0]);
        return 2;
    }

    const std::string profile = argc == 3 ? argv[2] : "series";
    auto registry = v0id::mathvm::make_default_registry();

    v0id::mathvm::WasmMathProgram program;
    program.wasm = read_binary(argv[1]);
    program.entrypoint = "v0id_main";

    std::uint64_t expected_result = 0;
    std::uint64_t expected_calls = 0;
    if (profile == "series")
        configure_series_profile(program, expected_result, expected_calls);
    else if (profile == "sha3")
        configure_sha3_profile(program, expected_result, expected_calls);
    else
        throw std::runtime_error("unknown MathVM demo profile: " + profile);

    std::cout << "V0ID MathVM ABI      : v" << v0id::mathvm::MATHVM_ABI_VERSION << '\n'
              << "demo profile         : " << profile << '\n'
              << "runtime              : WAMR classic interpreter\n"
              << "WASI                 : disabled\n"
              << "AOT/JIT              : disabled\n"
              << "module bytes         : " << program.wasm.size() << '\n'
              << "declared primitives  :\n";

    for (const auto& requirement : program.required_primitives) {
        const auto descriptor = registry.require(requirement).descriptor();
        std::cout << "  - " << descriptor.id << "/v" << descriptor.version
                  << " ["
                  << (descriptor.abi == v0id::mathvm::PrimitiveAbi::bytes
                          ? "bytes"
                          : "u64")
                  << ']';
        if (descriptor.experimental)
            std::cout << " [EXPERIMENTAL / NO SECURITY CLAIM]";
        std::cout << '\n';
    }

    std::cout << "installed capabilities:\n";
    for (const auto& descriptor : registry.descriptors()) {
        std::cout << "  - " << descriptor.id << "/v" << descriptor.version
                  << " ["
                  << (descriptor.abi == v0id::mathvm::PrimitiveAbi::bytes
                          ? "bytes"
                          : "u64")
                  << ']';
        if (descriptor.experimental)
            std::cout << " [EXPERIMENTAL]";
        std::cout << '\n';
    }

    v0id::mathvm::WamrMathSandbox sandbox;
    const auto report = sandbox.execute(program, registry);

    std::cout << "result               : " << report.result << '\n'
              << "provider calls       : " << report.provider_calls << '\n'
              << "provider cost        : " << report.provider_cost << '\n';

    if (report.result != expected_result)
        throw std::runtime_error("unexpected MathVM demo result");
    if (report.provider_calls != expected_calls)
        throw std::runtime_error("unexpected MathVM provider call count");

    std::cout << "OK: sandboxed Wasm used locally installed MathVM providers\n"
                 "    + scalar and bounded byte-provider ABIs are separate\n"
                 "    + no WASI/filesystem/network host surface\n"
                 "    + portable Wasm bytecode only\n"
                 "    + explicit primitive manifest enforced\n"
                 "    + instruction and native-provider budgets enforced\n"
                 "    + no peer-supplied native plugin loading\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID MathVM error: " << e.what() << '\n';
    return 1;
}
