#pragma once

#include "boolean_program_image.hpp"
#include "gpu_fhe_backend.hpp"

#include "binfhecontext.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace v0id::fhe {

inline constexpr std::size_t kEncryptedBooleanWordBits = 64;
inline constexpr std::size_t kEncryptedBooleanOpcodeBits = 3;
inline constexpr std::size_t kEncryptedBooleanRegisterIdBits = 6;
inline constexpr std::size_t kEncryptedBooleanInputIndexBits = 16;
inline constexpr std::size_t kEncryptedBooleanRotateBits = 6;

// Every encrypted instruction carries every field, including fields unused by a
// particular opcode. This is deliberate: evaluator-visible slot length must not
// identify the encrypted opcode.
inline constexpr std::size_t kEncryptedBooleanInstructionLogicalBits =
    kEncryptedBooleanOpcodeBits +
    6 * kEncryptedBooleanRegisterIdBits + // dst + a..e
    kEncryptedBooleanInputIndexBits +
    kEncryptedBooleanRotateBits +
    kEncryptedBooleanWordBits;

using EncryptedBooleanWord =
    std::array<lbcrypto::LWECiphertext, kEncryptedBooleanWordBits>;
using EncryptedBooleanOpcode =
    std::array<lbcrypto::LWECiphertext, kEncryptedBooleanOpcodeBits>;
using EncryptedBooleanRegisterId =
    std::array<lbcrypto::LWECiphertext, kEncryptedBooleanRegisterIdBits>;
using EncryptedBooleanInputIndex =
    std::array<lbcrypto::LWECiphertext, kEncryptedBooleanInputIndexBits>;
using EncryptedBooleanRotate =
    std::array<lbcrypto::LWECiphertext, kEncryptedBooleanRotateBits>;

struct EncryptedBooleanProgramInstruction {
    EncryptedBooleanOpcode opcode;
    EncryptedBooleanRegisterId dst;
    EncryptedBooleanRegisterId a;
    EncryptedBooleanRegisterId b;
    EncryptedBooleanRegisterId c;
    EncryptedBooleanRegisterId d;
    EncryptedBooleanRegisterId e;
    EncryptedBooleanInputIndex input_index;
    EncryptedBooleanRotate rotate;
    EncryptedBooleanWord immediate;
};

struct EncryptedBooleanProgramImage {
    std::size_t register_count{};
    std::size_t input_word_count{};
    std::vector<EncryptedBooleanProgramInstruction> instructions;
    std::vector<EncryptedBooleanRegisterId> output_registers;

    // Structural validation only. Encrypted field values are intentionally not
    // decrypted or semantically inspected by the evaluator.
    void validate_shape() const;
};

struct EncryptedBooleanProgramExecution {
    std::vector<EncryptedBooleanWord> registers;
    std::vector<EncryptedBooleanWord> output_words;
};

// Number of plaintext logical bits represented by the fixed-width encrypted
// instruction slots and encrypted output-register selectors. This is not a wire
// byte size: serialized BinFHE ciphertexts are much larger than one byte/bit.
std::size_t encrypted_boolean_program_logical_bits(
    const v0id::integrity::BooleanProgramImage& image);

// Trusted client-side construction helpers. Unused instruction fields are still
// encrypted as ordinary zero-valued fields, so the remote side receives one
// fixed-width shape for every instruction slot.
EncryptedBooleanProgramImage encrypt_boolean_program_image(
    lbcrypto::BinFHEContext& cc,
    lbcrypto::ConstLWEPrivateKey& sk,
    const v0id::integrity::BooleanProgramImage& image);

std::vector<EncryptedBooleanWord> encrypt_boolean_program_input_words(
    lbcrypto::BinFHEContext& cc,
    lbcrypto::ConstLWEPrivateKey& sk,
    const std::vector<std::uint64_t>& words);

// Fixed-path evaluator for the compact private Boolean program image. It owns no
// secret key and never branches on encrypted opcode/register/index values. Each
// instruction evaluates every supported operation and selects the active result
// homomorphically, then updates the encrypted destination register through an
// encrypted register-id selector.
//
// When V0ID_GPU_FHE_ENABLED is defined this class intentionally remains the CPU
// reference implementation until the TFHE-CUDA adapter is linked. The compile-
// time hook lives in gpu_fhe_backend.hpp so GPU-specific code can be introduced
// behind the same public Boolean-program image boundary without changing callers.
class RemoteEncryptedBooleanProgram {
public:
    RemoteEncryptedBooleanProgram(
        lbcrypto::BinFHEContext& cc,
        EncryptedBooleanProgramImage image,
        std::vector<EncryptedBooleanWord> input_words,
        lbcrypto::LWECiphertext encrypted_zero);

    void step();
    void run_fixed();

    std::size_t completed_instructions() const { return instruction_index_; }
    const std::vector<EncryptedBooleanWord>& registers() const { return registers_; }

    // Call after run_fixed()/all step() calls. Selecting encrypted output-register
    // ids is itself homomorphic work, so the result is produced explicitly.
    EncryptedBooleanProgramExecution result();

private:
    lbcrypto::LWECiphertext And(const lbcrypto::LWECiphertext& a,
                                const lbcrypto::LWECiphertext& b);
    lbcrypto::LWECiphertext Or(const lbcrypto::LWECiphertext& a,
                               const lbcrypto::LWECiphertext& b);
    lbcrypto::LWECiphertext Xor(const lbcrypto::LWECiphertext& a,
                                const lbcrypto::LWECiphertext& b);
    lbcrypto::LWECiphertext Not(const lbcrypto::LWECiphertext& a);
    lbcrypto::LWECiphertext Mux(const lbcrypto::LWECiphertext& select,
                                const lbcrypto::LWECiphertext& when_true,
                                const lbcrypto::LWECiphertext& when_false);

    EncryptedBooleanWord select_register(const EncryptedBooleanRegisterId& id);
    EncryptedBooleanWord select_input(const EncryptedBooleanInputIndex& id);
    EncryptedBooleanWord rotate_selected(const EncryptedBooleanWord& word,
                                         const EncryptedBooleanRotate& rotate);
    EncryptedBooleanWord rotate_fixed(const EncryptedBooleanWord& word,
                                      std::size_t rotate) const;

    EncryptedBooleanWord word_xor(const EncryptedBooleanWord& a,
                                  const EncryptedBooleanWord& b);
    EncryptedBooleanWord word_xor5(const EncryptedBooleanWord& a,
                                   const EncryptedBooleanWord& b,
                                   const EncryptedBooleanWord& c,
                                   const EncryptedBooleanWord& d,
                                   const EncryptedBooleanWord& e);
    EncryptedBooleanWord word_chi(const EncryptedBooleanWord& a,
                                  const EncryptedBooleanWord& b,
                                  const EncryptedBooleanWord& c);

    void write_register(const EncryptedBooleanRegisterId& dst,
                        const EncryptedBooleanWord& value,
                        const lbcrypto::LWECiphertext& active);

    lbcrypto::BinFHEContext& cc_;
    EncryptedBooleanProgramImage image_;
    std::vector<EncryptedBooleanWord> inputs_;
    std::vector<EncryptedBooleanWord> registers_;
    lbcrypto::LWECiphertext zero_;
    lbcrypto::LWECiphertext one_;
    std::size_t instruction_index_{};
};

} // namespace v0id::fhe
