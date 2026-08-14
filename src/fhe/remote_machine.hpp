#pragma once

#include "remote_machine_codec.hpp"

#include "binfhecontext.h"

#include <cstddef>
#include <vector>

namespace v0id::fhe {

// Fixed-path evaluator for a fully encrypted machine image received from a
// remote client. It owns no secret key and never branches on encrypted program
// semantics. Tape is kept in logical order in V0.4; distributed/remapped
// physical placement is the next layer.
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
    std::vector<lbcrypto::LWECiphertext> program_bits_;
    std::vector<lbcrypto::LWECiphertext> state_;
    std::vector<lbcrypto::LWECiphertext> head_;
    std::vector<lbcrypto::LWECiphertext> tape_;
    lbcrypto::LWECiphertext zero_;
};

} // namespace v0id::fhe
