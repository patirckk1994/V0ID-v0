#pragma once

#include "program.hpp"
#include "remote_machine_codec.hpp"

#include "binfhecontext.h"

#include <cstddef>
#include <vector>

namespace v0id::fhe {

// Canonical client-side transition encoding consumed by RemoteEncryptedMachine:
// for each public (state, read) row, append next-state one-hot bits, write bit,
// then move-left/stay/right one-hot bits.
std::vector<int> canonical_remote_program_bits(
    const v0id::core::Program& program);

// Encrypt a binary vector as independently encrypted BinFHE ciphertexts. This is
// generic remote-machine client plumbing, not an integrity/fingerprint primitive.
std::vector<lbcrypto::LWECiphertext> encrypt_remote_bits(
    lbcrypto::BinFHEContext& cc,
    const lbcrypto::LWEPrivateKey& sk,
    const std::vector<int>& bits);

// Fixed-path evaluator for a fully encrypted machine image received from a
// remote client. It owns no secret key and never branches on encrypted program
// semantics. Tape is kept in logical order in V0.4; distributed/remapped
// physical placement is the next layer.
//
// program_bits may contain either one transition table (legacy/stable morph) or
// exactly shape.rounds concatenated tables (round-polymorphic execution-bound
// schedule). In schedule mode step() consumes the next encrypted table on every
// call. The evaluator still learns only the public dimensions/table count; the
// state-label meaning of each table remains encrypted.
class RemoteEncryptedMachine {
public:
    RemoteEncryptedMachine(lbcrypto::BinFHEContext& cc,
                           const PublicMachineShape& shape,
                           std::vector<lbcrypto::LWECiphertext> program_bits,
                           std::vector<lbcrypto::LWECiphertext> state_bits,
                           std::vector<lbcrypto::LWECiphertext> head_bits,
                           std::vector<lbcrypto::LWECiphertext> tape_bits,
                           lbcrypto::LWECiphertext encrypted_zero);

    void step();
    void run_fixed();

    const std::vector<lbcrypto::LWECiphertext>& state_bits() const { return state_; }
    const std::vector<lbcrypto::LWECiphertext>& head_bits() const { return head_; }
    const std::vector<lbcrypto::LWECiphertext>& tape_bits() const { return tape_; }
    const std::vector<lbcrypto::LWECiphertext>& program_bits() const { return program_bits_; }
    std::size_t completed_rounds() const { return round_index_; }
    bool uses_round_schedule() const { return program_table_count_ > 1; }

private:
    std::size_t row_offset(std::size_t state, int read) const;

    const lbcrypto::LWECiphertext& next_state_selector(std::size_t state,
                                                       int read,
                                                       std::size_t next_state) const;
    const lbcrypto::LWECiphertext& write_one_selector(std::size_t state, int read) const;
    const lbcrypto::LWECiphertext& move_left_selector(std::size_t state, int read) const;
    const lbcrypto::LWECiphertext& move_stay_selector(std::size_t state, int read) const;
    const lbcrypto::LWECiphertext& move_right_selector(std::size_t state, int read) const;

    lbcrypto::LWECiphertext And(const lbcrypto::LWECiphertext& a,
                                const lbcrypto::LWECiphertext& b);
    lbcrypto::LWECiphertext Or(const lbcrypto::LWECiphertext& a,
                               const lbcrypto::LWECiphertext& b);

    lbcrypto::BinFHEContext& cc_;
    PublicMachineShape shape_;
    std::size_t states_{};
    std::size_t tape_cells_{};
    std::size_t program_table_bits_{};
    std::size_t program_table_count_{1};
    std::size_t round_index_{};
    std::vector<lbcrypto::LWECiphertext> program_bits_;
    std::vector<lbcrypto::LWECiphertext> state_;
    std::vector<lbcrypto::LWECiphertext> head_;
    std::vector<lbcrypto::LWECiphertext> tape_;
    lbcrypto::LWECiphertext zero_;
};

} // namespace v0id::fhe
