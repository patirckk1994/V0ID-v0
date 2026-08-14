#pragma once

#include "program.hpp"
#include "binfhecontext.h"

#include <array>
#include <cstdint>
#include <vector>

namespace v0id::integrity {

using EncryptedDigest32 = std::array<lbcrypto::LWECiphertext, 32>;
inline constexpr std::uint32_t TOY_FINGERPRINT_INITIAL_STATE = 0x56304944u; // "V0ID"

// Canonical semantic bit layout shared by the plaintext reference and encrypted
// evaluator: for each public (state, read) row, append next-state one-hot bits,
// write bit, then move-left/stay/right one-hot bits.
std::vector<int> canonical_program_bits(const v0id::core::Program& program);

// Test-only 32-bit Boolean mixer. This deliberately is NOT a cryptographic hash;
// it exists to prove the self-fingerprint/morph-manifest plumbing before a real
// Keccak/KMAC circuit is attempted under BinFHE.
std::uint32_t toy_fingerprint32_plain(const v0id::core::Program& program,
                                      const std::vector<int>& initial_tape,
                                      std::uint32_t nonce);

std::vector<lbcrypto::LWECiphertext>
encrypt_plain_bits(lbcrypto::BinFHEContext& cc,
                   const lbcrypto::LWEPrivateKey& sk,
                   const std::vector<int>& bits);

EncryptedDigest32 encrypt_u32_bits(lbcrypto::BinFHEContext& cc,
                                   const lbcrypto::LWEPrivateKey& sk,
                                   std::uint32_t value);

// Evaluator-side fingerprint. No secret key is required. The client supplies 32
// independently encrypted mixer-state bits because OpenFHE BinFHE rejects a gate
// whose two operands are the same ciphertext object. The evaluator then runs the
// same Boolean mixer over encrypted program semantics, input and nonce.
EncryptedDigest32 toy_fingerprint32_fhe(
    lbcrypto::BinFHEContext& cc,
    const std::vector<lbcrypto::LWECiphertext>& encrypted_program_bits,
    const std::vector<lbcrypto::LWECiphertext>& encrypted_initial_tape,
    const EncryptedDigest32& encrypted_nonce_bits,
    const EncryptedDigest32& encrypted_initial_state_bits);

EncryptedDigest32 mask_digest_fhe(lbcrypto::BinFHEContext& cc,
                                  const EncryptedDigest32& digest,
                                  const EncryptedDigest32& encrypted_mask_bits);

std::uint32_t decrypt_u32_bits(lbcrypto::BinFHEContext& cc,
                               const lbcrypto::LWEPrivateKey& sk,
                               const EncryptedDigest32& bits);

} // namespace v0id::integrity
