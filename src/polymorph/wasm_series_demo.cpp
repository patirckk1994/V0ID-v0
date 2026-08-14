#include "wasm_series_generator.hpp"

#include "program.hpp"
#include "program_morpher.hpp"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::polymorph::ProgramMorpher;
using v0id::polymorph::SeriesProfile;
using v0id::polymorph::SeriesSeed;
using v0id::polymorph::WasmSeriesGenerator;

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        throw std::runtime_error("cannot open Wasm file: " + path);
    return std::vector<std::uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>());
}

std::vector<int> run_plaintext(const Program& program,
                               std::size_t initial_state,
                               const std::vector<int>& input,
                               std::size_t steps) {
    program.validate();
    auto tape = input;
    std::size_t state = initial_state;
    std::size_t head = 0;
    for (std::size_t step = 0; step < steps; ++step) {
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

void print_bits_msb(const std::vector<int>& bits) {
    for (auto it = bits.rbegin(); it != bits.rend(); ++it)
        std::cout << *it;
}

} // namespace

int main(int argc, char** argv) try {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <polymorphism.wasm>\n";
        return 1;
    }

    const auto wasm = read_file(argv[1]);
    const SeriesProfile profile{
        "v0id-local-wasm-series-mixer",
        1,
        {},
    };
    WasmSeriesGenerator generator(wasm, profile);

    const Program increment{2, {
        {0, 0, 1, 1,  0},
        {0, 1, 0, 0, +1},
        {1, 0, 1, 0,  0},
        {1, 1, 1, 1,  0},
    }};
    const std::vector<int> input{1,0,1,1,0,0,0,0};
    const std::vector<int> expected{0,1,1,1,0,0,0,0};

    std::vector<std::uint8_t> semantic_input;
    semantic_input.reserve(input.size());
    for (const auto bit : input)
        semantic_input.push_back(static_cast<std::uint8_t>(bit & 1));

    SeriesSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(i);

    const auto derived = generator.derive(semantic_input, seed, 1);
    const auto morph = ProgramMorpher::morph(
        increment, 0, 4, derived.morph_seed, 4);
    const auto result = run_plaintext(morph.program, morph.initial_state, input, 4);

    std::cout << "V0ID local Wasm polymorphism\n"
              << "runtime              : WAMR classic interpreter\n"
              << "WASI/imports         : forbidden\n"
              << "module bytes         : " << generator.module_bytes() << '\n'
              << "profile              : " << profile.generator_id
              << "/v" << profile.version << '\n'
              << "private series bytes : " << derived.series.size() << '\n'
              << "private manifest     : " << derived.private_manifest.size() << " bytes\n"
              << "MorphSeed prefix     : ";

    std::cout << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < 8; ++i)
        std::cout << std::setw(2)
                  << static_cast<unsigned>(derived.morph_seed[i]);
    std::cout << std::dec << "...\n";

    std::cout << "state map            : ";
    for (std::size_t i = 0; i < morph.manifest.base_to_morphed.size(); ++i) {
        if (i) std::cout << ", ";
        std::cout << i << "->" << morph.manifest.base_to_morphed[i];
    }
    std::cout << "\nplaintext check      : ";
    print_bits_msb(input);
    std::cout << " -> ";
    print_bits_msb(result);
    std::cout << '\n';

    if (result != expected)
        throw std::runtime_error("Wasm-derived ProgramMorpher semantic check failed");

    std::cout << "OK: local Wasm derived private morph material; trusted ProgramMorpher preserved semantics\n"
                 "    + Wasm was not transmitted anywhere\n"
                 "    + Wasm never received the Program transition table\n"
                 "    + trusted C++ remained responsible for machine rewriting\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID local Wasm polymorphism demo error: " << e.what() << '\n';
    return 2;
}
