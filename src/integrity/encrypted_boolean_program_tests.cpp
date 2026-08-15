#include "encrypted_boolean_program.hpp"
#include "keccak_program_image.hpp"

#include "binfhecontext.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& what) {
    if (!condition)
        throw std::runtime_error(what);
}

std::uint64_t decrypt_word(lbcrypto::BinFHEContext& cc,
                           lbcrypto::ConstLWEPrivateKey& sk,
                           const v0id::fhe::EncryptedBooleanWord& word) {
    std::uint64_t out = 0;
    for (std::size_t bit = 0; bit < word.size(); ++bit) {
        lbcrypto::LWEPlaintext value = 0;
        cc.Decrypt(sk, word[bit], &value);
        out |= static_cast<std::uint64_t>(value & 1u) << bit;
    }
    return out;
}

v0id::integrity::BooleanProgramImage tiny_image() {
    using namespace v0id::integrity;

    BooleanProgramImage image;
    image.register_count = 2;
    image.input_word_count = 0;

    BooleanProgramInstruction ins;
    ins.op = BooleanProgramOpcode::XorConst;
    ins.dst = 1;
    ins.a = 0;
    ins.immediate = 0x0123456789abcdefull;
    image.instructions.push_back(ins);
    image.output_registers = {1};
    image.validate();
    return image;
}

} // namespace

int main() try {
    int passed = 0;
    auto pass = [&](bool ok, const char* label) {
        require(ok, label);
        ++passed;
        std::cout << "[PASS] " << label << '\n';
    };

    const auto compact_sha3 = v0id::integrity::build_sha3_512_program_image(3);
    const auto fixed_bits =
        v0id::fhe::encrypted_boolean_program_logical_bits(compact_sha3.program);
    pass(fixed_bits ==
             compact_sha3.program.instructions.size() *
                 v0id::fhe::kEncryptedBooleanInstructionLogicalBits +
             compact_sha3.program.output_registers.size() *
                 v0id::fhe::kEncryptedBooleanRegisterIdBits,
         "fixed-width encrypted image accounts for every hidden instruction field");
    std::cout << "[INFO] one-block SHA3 encrypted instruction logical bits: "
              << fixed_bits << '\n';

    const auto plain = tiny_image();
    const auto expected = v0id::integrity::evaluate_boolean_program_image(plain, {});

    lbcrypto::BinFHEContext cc;
    cc.GenerateBinFHEContext(lbcrypto::TOY);
    auto sk = cc.KeyGen();
    cc.BTKeyGen(sk);

    auto encrypted = v0id::fhe::encrypt_boolean_program_image(cc, sk, plain);
    auto encrypted_inputs =
        v0id::fhe::encrypt_boolean_program_input_words(cc, sk, {});
    auto encrypted_zero = cc.Encrypt(sk, 0);

    v0id::fhe::RemoteEncryptedBooleanProgram remote(
        cc, std::move(encrypted), std::move(encrypted_inputs), encrypted_zero);
    remote.run_fixed();
    const auto result = remote.result();

    pass(remote.completed_instructions() == plain.instructions.size(),
         "fixed-path encrypted evaluator consumes the public instruction count");
    require(result.output_words.size() == expected.output_words.size(),
            "encrypted evaluator output count mismatch");

    std::vector<std::uint64_t> decrypted;
    decrypted.reserve(result.output_words.size());
    for (const auto& word : result.output_words)
        decrypted.push_back(decrypt_word(cc, sk, word));

    pass(decrypted == expected.output_words,
         "encrypted opcode/register selection matches plaintext compact-image semantics");

    std::cout << "encrypted-boolean-program tests passed: " << passed << '\n';
    return 0;
} catch (const std::exception& e) {
    std::cerr << "encrypted-boolean-program tests FAILED: " << e.what() << '\n';
    return 1;
}
