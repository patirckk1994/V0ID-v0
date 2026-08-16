#include "boolean_program_image_mutator.hpp"
#include "keccak_program_image.hpp"
#include "remote_machine_codec.hpp"
#include "sha3_512_ir.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::integrity::BooleanMutationSeed;

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

std::vector<std::uint8_t> openssl_sha3_512(
    const std::vector<std::uint8_t>& message) {
    using Ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Ctx ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha3_512(), nullptr) != 1)
        throw std::runtime_error("EVP SHA3-512 init failed");
    if (EVP_DigestUpdate(ctx.get(), message.data(), message.size()) != 1)
        throw std::runtime_error("EVP SHA3-512 update failed");
    std::vector<std::uint8_t> out(64);
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &n) != 1 || n != out.size())
        throw std::runtime_error("EVP SHA3-512 final failed");
    return out;
}

std::vector<std::uint8_t> boolean_ir_sha3_512(
    const std::vector<std::uint8_t>& message) {
    const auto built = v0id::integrity::build_sha3_512_ir(message.size());
    const auto bits = v0id::integrity::bytes_to_lsb_bits(message);
    return v0id::integrity::lsb_bits_to_bytes(built.ir.evaluate(bits));
}

std::vector<std::uint8_t> image_digest(
    const v0id::integrity::BooleanProgramImage& program,
    const std::vector<std::uint8_t>& message) {
    const auto words = v0id::integrity::sha3_512_program_input_words(message);
    const auto exec = v0id::integrity::evaluate_boolean_program_image(program, words);
    require(exec.output_words.size() == 8, "image digest expected eight lanes");
    std::vector<std::uint8_t> out;
    out.reserve(64);
    for (const auto word : exec.output_words) {
        for (std::size_t i = 0; i < 8; ++i)
            out.push_back(static_cast<std::uint8_t>((word >> (8 * i)) & 0xffu));
    }
    return out;
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    for (const std::size_t n : {std::size_t{0}, std::size_t{3}, std::size_t{71},
                                std::size_t{72}, std::size_t{73}}) {
        std::vector<std::uint8_t> message(n);
        for (std::size_t i = 0; i < n; ++i)
            message[i] = static_cast<std::uint8_t>((i * 53u + 17u) & 0xffu);
        if (n == 3)
            message = {'a', 'b', 'c'};

        const auto image = v0id::integrity::build_sha3_512_program_image(n);
        const auto digest = v0id::integrity::evaluate_sha3_512_program_image(image, message);
        pass(digest == openssl_sha3_512(message),
             "compact SHA3-512 program image matches OpenSSL");
        pass(digest == boolean_ir_sha3_512(message),
             "compact SHA3-512 program image matches BooleanIR");
    }

    const std::vector<std::uint8_t> abc{'a','b','c'};
    const auto base = v0id::integrity::build_sha3_512_program_image(abc.size());
    const auto base_bits = v0id::integrity::serialize_boolean_program_image_bits(base.program);

    BooleanMutationSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<unsigned char>(0x3du ^ (i * 29u));
    v0id::integrity::BooleanProgramMutationStats stats;
    const auto mutated = v0id::integrity::mutate_boolean_program_image(
        base.program, seed, 8, &stats);
    const auto mutated_bits =
        v0id::integrity::serialize_boolean_program_image_bits(mutated);

    pass(image_digest(mutated, abc) == openssl_sha3_512(abc),
         "seeded compact-program mutation preserves SHA3-512 output");
    pass(mutated_bits != base_bits,
         "seeded compact-program mutation changes encrypted image bits");
    pass(stats.permuted_registers == base.program.register_count &&
             stats.identity_instructions_inserted == 8,
         "compact-program mutation reports register and identity transforms");

    const auto words = v0id::integrity::sha3_512_program_input_words(abc);
    const auto tape = v0id::integrity::pack_boolean_program_tape(base.program, words);
    pass(tape.bits.size() <= v0id::fhe::remote_detail::MAX_TAPE_CELLS,
         "one-block SHA3 image plus registers/input fits current RMJ3 tape cap");

    std::vector<std::uint8_t> two_block(72, 0x42);
    const auto two = v0id::integrity::build_sha3_512_program_image(two_block.size());
    const auto two_words = v0id::integrity::sha3_512_program_input_words(two_block);
    const auto two_tape = v0id::integrity::pack_boolean_program_tape(two.program, two_words);
    pass(two_tape.bits.size() > v0id::fhe::remote_detail::MAX_TAPE_CELLS,
         "two-block image exposes need for reusable permutation loop before RMJ3");

    std::cout << "sha3-image tests passed: " << passed << '\n';
    return 0;
} catch (const std::exception& e) {
    std::cerr << "sha3-image tests FAILED: " << e.what() << '\n';
    return 1;
}
