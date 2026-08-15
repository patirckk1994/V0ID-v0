#include "remote_machine.hpp"

#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace v0id::fhe {

RemoteEncryptedMachine::RemoteEncryptedMachine(
    lbcrypto::BinFHEContext& cc,
    const PublicMachineShape& shape,
    std::vector<lbcrypto::LWECiphertext> program_bits,
    std::vector<lbcrypto::LWECiphertext> state_bits,
    std::vector<lbcrypto::LWECiphertext> head_bits,
    std::vector<lbcrypto::LWECiphertext> tape_bits,
    lbcrypto::LWECiphertext encrypted_zero)
    : cc_(cc),
      shape_(shape),
      states_(remote_detail::checked_size(shape.states, "state count overflow")),
      tape_cells_(remote_detail::checked_size(shape.tape_cells, "tape count overflow")),
      program_bits_(std::move(program_bits)),
      state_(std::move(state_bits)),
      head_(std::move(head_bits)),
      tape_(std::move(tape_bits)),
      zero_(std::move(encrypted_zero)) {

    remote_detail::validate_shape(shape_);
    if (!zero_)
        throw std::runtime_error("remote machine encrypted zero is empty");

    program_table_bits_ = remote_detail::program_bit_count(shape_);
    if (program_bits_.size() == program_table_bits_) {
        program_table_count_ = 1;
    } else {
        const auto rounds = remote_detail::checked_size(shape_.rounds, "round count overflow");
        if (rounds == 0 ||
            program_table_bits_ > std::numeric_limits<std::size_t>::max() / rounds ||
            program_bits_.size() != program_table_bits_ * rounds) {
            throw std::runtime_error(
                "remote machine program bit count mismatch (expected one table or one table per round)");
        }
        program_table_count_ = rounds;
    }

    if (state_.size() != states_)
        throw std::runtime_error("remote machine state bit count mismatch");
    if (head_.size() != tape_cells_)
        throw std::runtime_error("remote machine head bit count mismatch");
    if (tape_.size() != tape_cells_)
        throw std::runtime_error("remote machine tape bit count mismatch");
}

std::size_t RemoteEncryptedMachine::row_offset(std::size_t state, int read) const {
    if (state >= states_ || (read != 0 && read != 1))
        throw std::runtime_error("remote machine transition index out of range");

    std::size_t table_base = 0;
    if (program_table_count_ > 1) {
        if (round_index_ >= program_table_count_)
            throw std::runtime_error("remote machine round schedule exhausted");
        table_base = round_index_ * program_table_bits_;
    }

    return table_base +
           (state * 2 + static_cast<std::size_t>(read)) * (states_ + 4);
}

const lbcrypto::LWECiphertext& RemoteEncryptedMachine::next_state_selector(
    std::size_t state, int read, std::size_t next_state) const {
    if (next_state >= states_)
        throw std::runtime_error("remote machine next state index out of range");
    return program_bits_.at(row_offset(state, read) + next_state);
}

const lbcrypto::LWECiphertext& RemoteEncryptedMachine::write_one_selector(
    std::size_t state, int read) const {
    return program_bits_.at(row_offset(state, read) + states_);
}

const lbcrypto::LWECiphertext& RemoteEncryptedMachine::move_left_selector(
    std::size_t state, int read) const {
    return program_bits_.at(row_offset(state, read) + states_ + 1);
}

const lbcrypto::LWECiphertext& RemoteEncryptedMachine::move_stay_selector(
    std::size_t state, int read) const {
    return program_bits_.at(row_offset(state, read) + states_ + 2);
}

const lbcrypto::LWECiphertext& RemoteEncryptedMachine::move_right_selector(
    std::size_t state, int read) const {
    return program_bits_.at(row_offset(state, read) + states_ + 3);
}

lbcrypto::LWECiphertext RemoteEncryptedMachine::And(
    const lbcrypto::LWECiphertext& a,
    const lbcrypto::LWECiphertext& b) {
    return cc_.EvalBinGate(lbcrypto::AND, a, b);
}

lbcrypto::LWECiphertext RemoteEncryptedMachine::Or(
    const lbcrypto::LWECiphertext& a,
    const lbcrypto::LWECiphertext& b) {
    return cc_.EvalBinGate(lbcrypto::OR, a, b);
}

void RemoteEncryptedMachine::step() {
    const auto requested_rounds =
        remote_detail::checked_size(shape_.rounds, "round count overflow");
    if (round_index_ >= requested_rounds)
        throw std::runtime_error("remote machine requested round budget exhausted");

    std::vector<lbcrypto::LWECiphertext> next_state(states_, zero_);
    std::vector<lbcrypto::LWECiphertext> next_head(tape_cells_, zero_);
    std::vector<lbcrypto::LWECiphertext> write_any(tape_cells_, zero_);
    std::vector<lbcrypto::LWECiphertext> write_one(tape_cells_, zero_);
    std::vector<lbcrypto::LWECiphertext> not_tape(tape_cells_);

    for (std::size_t i = 0; i < tape_cells_; ++i)
        not_tape[i] = cc_.EvalNOT(tape_[i]);

    for (std::size_t i = 0; i < tape_cells_; ++i) {
        for (std::size_t q = 0; q < states_; ++q) {
            for (int read = 0; read <= 1; ++read) {
                auto active = And(state_[q], head_[i]);
                active = And(active, read ? tape_[i] : not_tape[i]);

                for (std::size_t q2 = 0; q2 < states_; ++q2) {
                    auto selected = And(active, next_state_selector(q, read, q2));
                    next_state[q2] = Or(next_state[q2], selected);
                }

                write_any[i] = Or(write_any[i], active);
                write_one[i] = Or(write_one[i], And(active, write_one_selector(q, read)));

                const std::size_t left = i > 0 ? i - 1 : i;
                const std::size_t right = i + 1 < tape_cells_ ? i + 1 : i;

                next_head[left] = Or(next_head[left], And(active, move_left_selector(q, read)));
                next_head[i] = Or(next_head[i], And(active, move_stay_selector(q, read)));
                next_head[right] = Or(next_head[right], And(active, move_right_selector(q, read)));
            }
        }
    }

    std::vector<lbcrypto::LWECiphertext> next_tape(tape_cells_);
    for (std::size_t i = 0; i < tape_cells_; ++i) {
        auto keep_old = And(cc_.EvalNOT(write_any[i]), tape_[i]);
        next_tape[i] = Or(write_one[i], keep_old);
    }

    state_ = std::move(next_state);
    head_ = std::move(next_head);
    tape_ = std::move(next_tape);
    ++round_index_;
}

void RemoteEncryptedMachine::run_fixed() {
    while (round_index_ < shape_.rounds)
        step();
}

} // namespace v0id::fhe
