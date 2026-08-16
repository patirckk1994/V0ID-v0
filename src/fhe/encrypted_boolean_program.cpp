#include "encrypted_boolean_program.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace v0id::fhe {
namespace {

using Cipher = lbcrypto::LWECiphertext;

template <std::size_t N>
void require_field(const std::array<Cipher, N>& field, const char* what) {
    for (const auto& bit : field) {
        if (!bit)
            throw std::runtime_error(what);
}
}

template <std::size_t N>
std::array<Cipher, N> encrypt_field(lbcrypto::BinFHEContext& cc,
                                    lbcrypto::ConstLWEPrivateKey& sk,
                                    std::uint64_t value) {
    std::array<Cipher, N> out;
    for (std::size_t i = 0; i < N; ++i) {
        const auto bit = static_cast<lbcrypto::LWEPlaintext>((value >> i) & 1u);
        out[i] = cc.Encrypt(sk, bit);
    }
    return out;
}

template <std::size_t N>
Cipher equal_field(lbcrypto::BinFHEContext& cc,
                   const std::array<Cipher, N>& field,
                   std::uint64_t value,
                   const Cipher& encrypted_one) {
    auto equal = encrypted_one;
    for (std::size_t i = 0; i < N; ++i) {
        auto term = ((value >> i) & 1u) != 0 ? field[i] : cc.EvalNOT(field[i]);
        equal = cc.EvalBinGate(lbcrypto::AND, equal, term);
    }
    return equal;
}

void require_word(const EncryptedBooleanWord& word, const char* what) {
    require_field(word, what);
}

} // namespace

void EncryptedBooleanProgramImage::validate_shape() const {
    if (register_count == 0 || register_count > 64)
        throw std::runtime_error("encrypted boolean program register count must be in [1,64]");
    if (input_word_count > std::numeric_limits<std::uint16_t>::max())
        throw std::runtime_error("encrypted boolean program input count exceeds v1 range");
    if (instructions.empty())
        throw std::runtime_error("encrypted boolean program has no instructions");
    if (instructions.size() > std::numeric_limits<std::uint16_t>::max())
        throw std::runtime_error("encrypted boolean program instruction count exceeds v1 range");
    if (output_registers.empty() || output_registers.size() > 64)
        throw std::runtime_error("encrypted boolean program output count invalid");

    for (const auto& out : output_registers)
        require_field(out, "encrypted boolean program output selector is empty");

    for (const auto& ins : instructions) {
        require_field(ins.opcode, "encrypted boolean program opcode field is empty");
        require_field(ins.dst, "encrypted boolean program destination field is empty");
        require_field(ins.a, "encrypted boolean program operand a field is empty");
        require_field(ins.b, "encrypted boolean program operand b field is empty");
        require_field(ins.c, "encrypted boolean program operand c field is empty");
        require_field(ins.d, "encrypted boolean program operand d field is empty");
        require_field(ins.e, "encrypted boolean program operand e field is empty");
        require_field(ins.input_index, "encrypted boolean program input-index field is empty");
        require_field(ins.rotate, "encrypted boolean program rotate field is empty");
        require_word(ins.immediate, "encrypted boolean program immediate field is empty");
    }
}

std::size_t encrypted_boolean_program_logical_bits(
    const v0id::integrity::BooleanProgramImage& image) {
    image.validate();
    const auto max = std::numeric_limits<std::size_t>::max();
    if (image.instructions.size() >
        (max - image.output_registers.size() * kEncryptedBooleanRegisterIdBits) /
            kEncryptedBooleanInstructionLogicalBits) {
        throw std::runtime_error("encrypted boolean program logical-bit count overflow");
    }
    return image.instructions.size() * kEncryptedBooleanInstructionLogicalBits +
           image.output_registers.size() * kEncryptedBooleanRegisterIdBits;
}

EncryptedBooleanProgramImage encrypt_boolean_program_image(
    lbcrypto::BinFHEContext& cc,
    lbcrypto::ConstLWEPrivateKey& sk,
    const v0id::integrity::BooleanProgramImage& image) {
    image.validate();

    EncryptedBooleanProgramImage out;
    out.register_count = image.register_count;
    out.input_word_count = image.input_word_count;
    out.instructions.reserve(image.instructions.size());
    out.output_registers.reserve(image.output_registers.size());

    for (const auto& ins : image.instructions) {
        EncryptedBooleanProgramInstruction enc;
        enc.opcode = encrypt_field<kEncryptedBooleanOpcodeBits>(
            cc, sk, static_cast<std::uint8_t>(ins.op));
        enc.dst = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.dst);
        enc.a = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.a);
        enc.b = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.b);
        enc.c = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.c);
        enc.d = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.d);
        enc.e = encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, ins.e);
        enc.input_index = encrypt_field<kEncryptedBooleanInputIndexBits>(
            cc, sk, ins.input_index);
        enc.rotate = encrypt_field<kEncryptedBooleanRotateBits>(cc, sk, ins.rotate);
        enc.immediate = encrypt_field<kEncryptedBooleanWordBits>(cc, sk, ins.immediate);
        out.instructions.push_back(std::move(enc));
    }

    for (const auto reg : image.output_registers) {
        out.output_registers.push_back(
            encrypt_field<kEncryptedBooleanRegisterIdBits>(cc, sk, reg));
    }

    out.validate_shape();
    return out;
}

std::vector<EncryptedBooleanWord> encrypt_boolean_program_input_words(
    lbcrypto::BinFHEContext& cc,
    lbcrypto::ConstLWEPrivateKey& sk,
    const std::vector<std::uint64_t>& words) {
    std::vector<EncryptedBooleanWord> out;
    out.reserve(words.size());
    for (const auto word : words)
        out.push_back(encrypt_field<kEncryptedBooleanWordBits>(cc, sk, word));
    return out;
}

RemoteEncryptedBooleanProgram::RemoteEncryptedBooleanProgram(
    lbcrypto::BinFHEContext& cc,
    EncryptedBooleanProgramImage image,
    std::vector<EncryptedBooleanWord> input_words,
    lbcrypto::LWECiphertext encrypted_zero)
    : cc_(cc),
      image_(std::move(image)),
      inputs_(std::move(input_words)),
      zero_(std::move(encrypted_zero)) {
    image_.validate_shape();
    if (!zero_)
        throw std::runtime_error("encrypted boolean program zero ciphertext is empty");
    if (inputs_.size() != image_.input_word_count)
        throw std::runtime_error("encrypted boolean program input word count mismatch");
    for (const auto& word : inputs_)
        require_word(word, "encrypted boolean program input word is empty");

    one_ = cc_.EvalNOT(zero_);
    registers_.resize(image_.register_count);
    for (auto& word : registers_)
        word.fill(zero_);
}

lbcrypto::LWECiphertext RemoteEncryptedBooleanProgram::And(
    const lbcrypto::LWECiphertext& a,
    const lbcrypto::LWECiphertext& b) {
    return cc_.EvalBinGate(lbcrypto::AND, a, b);
}

lbcrypto::LWECiphertext RemoteEncryptedBooleanProgram::Or(
    const lbcrypto::LWECiphertext& a,
    const lbcrypto::LWECiphertext& b) {
    return cc_.EvalBinGate(lbcrypto::OR, a, b);
}

lbcrypto::LWECiphertext RemoteEncryptedBooleanProgram::Xor(
    const lbcrypto::LWECiphertext& a,
    const lbcrypto::LWECiphertext& b) {
    return cc_.EvalBinGate(lbcrypto::XOR, a, b);
}

lbcrypto::LWECiphertext RemoteEncryptedBooleanProgram::Not(
    const lbcrypto::LWECiphertext& a) {
    return cc_.EvalNOT(a);
}

lbcrypto::LWECiphertext RemoteEncryptedBooleanProgram::Mux(
    const lbcrypto::LWECiphertext& select,
    const lbcrypto::LWECiphertext& when_true,
    const lbcrypto::LWECiphertext& when_false) {
    return Or(And(select, when_true), And(Not(select), when_false));
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::select_register(
    const EncryptedBooleanRegisterId& id) {
    std::vector<Cipher> selectors;
    selectors.reserve(registers_.size());
    for (std::size_t r = 0; r < registers_.size(); ++r)
        selectors.push_back(equal_field(cc_, id, r, one_));

    EncryptedBooleanWord out;
    out.fill(zero_);
    for (std::size_t r = 0; r < registers_.size(); ++r) {
        for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
            out[bit] = Or(out[bit], And(selectors[r], registers_[r][bit]));
    }
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::select_input(
    const EncryptedBooleanInputIndex& id) {
    std::vector<Cipher> selectors;
    selectors.reserve(inputs_.size());
    for (std::size_t i = 0; i < inputs_.size(); ++i)
        selectors.push_back(equal_field(cc_, id, i, one_));

    EncryptedBooleanWord out;
    out.fill(zero_);
    for (std::size_t i = 0; i < inputs_.size(); ++i) {
        for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
            out[bit] = Or(out[bit], And(selectors[i], inputs_[i][bit]));
    }
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::rotate_fixed(
    const EncryptedBooleanWord& word,
    std::size_t rotate) const {
    EncryptedBooleanWord out;
    rotate %= kEncryptedBooleanWordBits;
    for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit) {
        out[bit] = word[(bit + kEncryptedBooleanWordBits - rotate) %
                        kEncryptedBooleanWordBits];
    }
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::rotate_selected(
    const EncryptedBooleanWord& word,
    const EncryptedBooleanRotate& rotate) {
    // Six-stage encrypted barrel rotator: each encrypted rotate bit chooses
    // whether to apply the corresponding 1/2/4/8/16/32-bit left rotation.
    // This is fixed-path and much cheaper than selecting among 64 full rotations.
    auto out = word;
    for (std::size_t stage = 0; stage < kEncryptedBooleanRotateBits; ++stage) {
        const auto shifted = rotate_fixed(out, std::size_t{1} << stage);
        EncryptedBooleanWord next;
        for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
            next[bit] = Mux(rotate[stage], shifted[bit], out[bit]);
        out = std::move(next);
    }
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::word_xor(
    const EncryptedBooleanWord& a,
    const EncryptedBooleanWord& b) {
    EncryptedBooleanWord out;
    for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
        out[bit] = Xor(a[bit], b[bit]);
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::word_xor5(
    const EncryptedBooleanWord& a,
    const EncryptedBooleanWord& b,
    const EncryptedBooleanWord& c,
    const EncryptedBooleanWord& d,
    const EncryptedBooleanWord& e) {
    EncryptedBooleanWord out;
    for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit) {
        auto x = Xor(a[bit], b[bit]);
        x = Xor(x, c[bit]);
        x = Xor(x, d[bit]);
        out[bit] = Xor(x, e[bit]);
    }
    return out;
}

EncryptedBooleanWord RemoteEncryptedBooleanProgram::word_chi(
    const EncryptedBooleanWord& a,
    const EncryptedBooleanWord& b,
    const EncryptedBooleanWord& c) {
    EncryptedBooleanWord out;
    for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
        out[bit] = Xor(a[bit], And(Not(b[bit]), c[bit]));
    return out;
}

void RemoteEncryptedBooleanProgram::write_register(
    const EncryptedBooleanRegisterId& dst,
    const EncryptedBooleanWord& value,
    const lbcrypto::LWECiphertext& active) {
    for (std::size_t r = 0; r < registers_.size(); ++r) {
        auto selected = equal_field(cc_, dst, r, one_);
        selected = And(active, selected);
        for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit)
            registers_[r][bit] = Mux(selected, value[bit], registers_[r][bit]);
    }
}

void RemoteEncryptedBooleanProgram::step() {
    if (instruction_index_ >= image_.instructions.size())
        throw std::runtime_error("encrypted boolean program instruction budget exhausted");

    const auto& ins = image_.instructions[instruction_index_];

    // All selectors and all candidate operations are evaluated for every slot.
    // No C++ branch below depends on encrypted opcode/operand contents.
    const auto a = select_register(ins.a);
    const auto b = select_register(ins.b);
    const auto c = select_register(ins.c);
    const auto d = select_register(ins.d);
    const auto e = select_register(ins.e);
    const auto input = select_input(ins.input_index);

    std::array<EncryptedBooleanWord, 7> candidates;
    candidates[0] = word_xor(a, b);
    candidates[1] = word_xor5(a, b, c, d, e);
    candidates[2] = word_xor(a, rotate_fixed(b, 1));
    candidates[3] = rotate_selected(a, ins.rotate);
    candidates[4] = word_chi(a, b, c);
    candidates[5] = word_xor(a, input);
    candidates[6] = word_xor(a, ins.immediate);

    std::array<Cipher, 7> opcode_selectors;
    auto valid = zero_;
    for (std::size_t op = 0; op < opcode_selectors.size(); ++op) {
        opcode_selectors[op] = equal_field(cc_, ins.opcode, op, one_);
        valid = Or(valid, opcode_selectors[op]);
    }

    EncryptedBooleanWord selected;
    selected.fill(zero_);
    for (std::size_t op = 0; op < candidates.size(); ++op) {
        for (std::size_t bit = 0; bit < kEncryptedBooleanWordBits; ++bit) {
            selected[bit] = Or(
                selected[bit], And(opcode_selectors[op], candidates[op][bit]));
        }
    }

    // Invalid encrypted opcodes become a no-op instead of corrupting a register.
    write_register(ins.dst, selected, valid);
    ++instruction_index_;
}

void RemoteEncryptedBooleanProgram::run_fixed() {
    while (instruction_index_ < image_.instructions.size())
        step();
}

EncryptedBooleanProgramExecution RemoteEncryptedBooleanProgram::result() {
    if (instruction_index_ != image_.instructions.size())
        throw std::runtime_error("encrypted boolean program result requested before completion");

    EncryptedBooleanProgramExecution out;
    out.registers = registers_;
    out.output_words.reserve(image_.output_registers.size());
    for (const auto& selector : image_.output_registers)
        out.output_words.push_back(select_register(selector));
    return out;
}

} // namespace v0id::fhe
