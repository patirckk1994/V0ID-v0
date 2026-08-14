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
        << "usage: " << argv0 << " <module.wasm>\n\n"
        << "Build the bundled no-WASI guest with clang, for example:\n"
        << "  clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry "
           "-Wl,--allow-undefined -Wl,--export=v0id_main "
           "-Wl,--initial-memory=65536 -Wl,--max-memory=1048576 "
           "examples/mathvm/series_math.c -o build/series_math.wasm\n";
}

} // namespace

int main(int argc, char** argv) try {
    if (argc != 2) {
        print_usage(argv[0]);
        return 2;
    }

    auto registry = v0id::mathvm::make_default_registry();

    v0id::mathvm::WasmMathProgram program;
    program.wasm = read_binary(argv[1]);
    program.entrypoint = "v0id_main";
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

    std::cout << "V0ID MathVM ABI      : v" << v0id::mathvm::MATHVM_ABI_VERSION << '\n'
              << "runtime              : WAMR classic interpreter\n"
              << "WASI                 : disabled\n"
              << "AOT/JIT              : disabled\n"
              << "module bytes         : " << program.wasm.size() << '\n'
              << "declared primitives  :\n";

    for (const auto& requirement : program.required_primitives) {
        const auto descriptor = registry.require(requirement).descriptor();
        std::cout << "  - " << descriptor.id << "/v" << descriptor.version;
        if (descriptor.experimental)
            std::cout << " [EXPERIMENTAL / NO SECURITY CLAIM]";
        std::cout << '\n';
    }

    v0id::mathvm::WamrMathSandbox sandbox;
    const auto report = sandbox.execute(program, registry);

    std::cout << "result               : " << report.result << '\n'
              << "provider calls       : " << report.provider_calls << '\n'
              << "provider cost        : " << report.provider_cost << '\n';

    if (report.result != 1596)
        throw std::runtime_error("unexpected MathVM demo result");
    if (report.provider_calls != 3)
        throw std::runtime_error("unexpected MathVM provider call count");

    std::cout << "OK: sandboxed Wasm composed locally installed math/PQ-test providers\n"
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
