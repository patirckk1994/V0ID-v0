#include "series_generator.hpp"

#include <z3++.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::SeriesSeed;

constexpr int OP_XOR = 0;
constexpr int OP_AND = 1;
constexpr int OP_ADD = 2;
constexpr int OP_NOT = 3;
constexpr int OP_SHL = 4;
constexpr int OP_SHR = 5;
constexpr int OP_ROTL = 6;
constexpr int OP_ROTR = 7;
constexpr int OP_XORI = 8;
constexpr int OP_ADDI = 9;
constexpr int OP_ANDI = 10;
constexpr int OP_COUNT = 11;

struct Config {
    std::size_t steps{3};
    std::size_t input_bytes{4};
    unsigned timeout_ms{5000};
    std::size_t initial_examples{32};
    std::size_t counterexample_batch{64};
    std::size_t max_cegis_rounds{12};
    int root_bit{-1}; // -1 = all 8 reduced-root bits
};

struct ConcreteInstruction {
    int op{};
    int src_a{};
    int src_b{};
    std::uint8_t imm{};
};

struct ConcreteProgram {
    std::vector<ConcreteInstruction> instructions;
    int output_reg{};
    int output_bit{};
    int secret_bit{};
};

struct SymbolicSketch {
    std::vector<z3::expr> op;
    std::vector<z3::expr> src_a;
    std::vector<z3::expr> src_b;
    std::vector<z3::expr> imm;
    z3::expr output_reg;
    z3::expr output_bit;

    SymbolicSketch(z3::context& ctx, std::size_t steps)
        : output_reg(ctx.int_const("output_reg")),
          output_bit(ctx.int_const("output_bit")) {
        op.reserve(steps);
        src_a.reserve(steps);
        src_b.reserve(steps);
        imm.reserve(steps);
        for (std::size_t i = 0; i < steps; ++i) {
            op.push_back(ctx.int_const(("op_" + std::to_string(i)).c_str()));
            src_a.push_back(ctx.int_const(("src_a_" + std::to_string(i)).c_str()));
            src_b.push_back(ctx.int_const(("src_b_" + std::to_string(i)).c_str()));
            imm.push_back(ctx.bv_const(("imm_" + std::to_string(i)).c_str(), 8));
        }
    }
};

SeriesSeed reduced_root(std::uint8_t x) {
    SeriesSeed root{};
    root[0] = x;
    constexpr char marker[] = "V0ID-BV-AUDIT";
    for (std::size_t i = 0; i < sizeof(marker) - 1 && i + 1 < root.size(); ++i)
        root[i + 1] = static_cast<unsigned char>(marker[i]);
    return root;
}

std::uint8_t rotl8(std::uint8_t x, unsigned amount) {
    amount &= 7u;
    if (amount == 0) amount = 1;
    return static_cast<std::uint8_t>(
        static_cast<unsigned>((x << amount) | (x >> (8u - amount))) & 0xffu);
}

std::uint8_t rotr8(std::uint8_t x, unsigned amount) {
    amount &= 7u;
    if (amount == 0) amount = 1;
    return static_cast<std::uint8_t>(
        static_cast<unsigned>((x >> amount) | (x << (8u - amount))) & 0xffu);
}

std::uint8_t eval_instruction(const ConcreteInstruction& ins,
                              std::uint8_t a,
                              std::uint8_t b) {
    const unsigned amount = (ins.imm & 7u) == 0 ? 1u : (ins.imm & 7u);
    switch (ins.op) {
        case OP_XOR:  return static_cast<std::uint8_t>(a ^ b);
        case OP_AND:  return static_cast<std::uint8_t>(a & b);
        case OP_ADD:  return static_cast<std::uint8_t>(a + b);
        case OP_NOT:  return static_cast<std::uint8_t>(~a);
        case OP_SHL:  return static_cast<std::uint8_t>(a << amount);
        case OP_SHR:  return static_cast<std::uint8_t>(a >> amount);
        case OP_ROTL: return rotl8(a, amount);
        case OP_ROTR: return rotr8(a, amount);
        case OP_XORI: return static_cast<std::uint8_t>(a ^ ins.imm);
        case OP_ADDI: return static_cast<std::uint8_t>(a + ins.imm);
        case OP_ANDI: return static_cast<std::uint8_t>(a & ins.imm);
        default: throw std::runtime_error("invalid concrete bitvector opcode");
    }
}

bool candidate_recovers(const ConcreteProgram& program,
                        const std::vector<std::uint8_t>& image,
                        std::uint8_t secret,
                        std::size_t input_bytes) {
    std::vector<std::uint8_t> regs;
    regs.reserve(input_bytes + program.instructions.size());
    for (std::size_t i = 0; i < input_bytes; ++i)
        regs.push_back(image.at(i));

    for (const auto& ins : program.instructions) {
        if (ins.src_a < 0 || ins.src_b < 0 ||
            static_cast<std::size_t>(ins.src_a) >= regs.size() ||
            static_cast<std::size_t>(ins.src_b) >= regs.size())
            return false;
        const auto a = regs[static_cast<std::size_t>(ins.src_a)];
        const auto b = regs[static_cast<std::size_t>(ins.src_b)];
        regs.push_back(eval_instruction(ins, a, b));
    }

    if (program.output_reg < 0 || program.output_bit < 0 || program.output_bit > 7 ||
        program.secret_bit < 0 || program.secret_bit > 7 ||
        static_cast<std::size_t>(program.output_reg) >= regs.size())
        return false;

    const bool observed =
        ((regs[static_cast<std::size_t>(program.output_reg)] >> program.output_bit) & 1u) != 0;
    const bool target = ((secret >> program.secret_bit) & 1u) != 0;
    return observed == target;
}

z3::expr select_reg(z3::context& ctx,
                    const z3::expr& selector,
                    const std::vector<z3::expr>& regs) {
    if (regs.empty()) throw std::runtime_error("empty symbolic register bank");
    z3::expr out = regs.front();
    for (std::size_t i = 1; i < regs.size(); ++i)
        out = z3::ite(selector == ctx.int_val(static_cast<int>(i)), regs[i], out);
    return out;
}

// Use the stable Z3 C API for bit-vector extraction/shifts and wrap the result
// back into the C++ expr type. Older distro z3++.h versions do not provide the
// newer namespace-level extract helper or expr<<expr overload used upstream.
z3::expr bv_extract(z3::context& ctx,
                    unsigned high,
                    unsigned low,
                    const z3::expr& value) {
    return z3::to_expr(ctx, Z3_mk_extract(ctx, high, low, value));
}

z3::expr bv_shl(z3::context& ctx,
                const z3::expr& value,
                const z3::expr& amount) {
    return z3::to_expr(ctx, Z3_mk_bvshl(ctx, value, amount));
}

z3::expr bv_lshr(z3::context& ctx,
                 const z3::expr& value,
                 const z3::expr& amount) {
    return z3::to_expr(ctx, Z3_mk_bvlshr(ctx, value, amount));
}

z3::expr select_bit(z3::context& ctx,
                    const z3::expr& selector,
                    const z3::expr& word) {
    z3::expr out = bv_extract(ctx, 0, 0, word);
    for (unsigned bit = 1; bit < 8; ++bit)
        out = z3::ite(selector == ctx.int_val(static_cast<int>(bit)),
                      bv_extract(ctx, bit, bit, word), out);
    return out;
}

z3::expr shift_family(z3::context& ctx,
                      const z3::expr& a,
                      const z3::expr& imm,
                      int kind) {
    const z3::expr low = bv_extract(ctx, 2, 0, imm);

    auto apply = [&](unsigned k) -> z3::expr {
        const auto sh = ctx.bv_val(k, 8);
        const auto inv = ctx.bv_val(8u - k, 8);
        switch (kind) {
            case OP_SHL:  return bv_shl(ctx, a, sh);
            case OP_SHR:  return bv_lshr(ctx, a, sh);
            case OP_ROTL: return bv_shl(ctx, a, sh) | bv_lshr(ctx, a, inv);
            case OP_ROTR: return bv_lshr(ctx, a, sh) | bv_shl(ctx, a, inv);
            default: throw std::runtime_error("invalid shift-family opcode");
        }
    };

    z3::expr out = apply(1);
    for (unsigned k = 2; k <= 7; ++k)
        out = z3::ite(low == ctx.bv_val(k, 3), apply(k), out);
    return out;
}

z3::expr apply_symbolic_op(z3::context& ctx,
                           const z3::expr& op,
                           const z3::expr& a,
                           const z3::expr& b,
                           const z3::expr& imm) {
    z3::expr out = a ^ b;
    out = z3::ite(op == ctx.int_val(OP_AND), a & b, out);
    out = z3::ite(op == ctx.int_val(OP_ADD), a + b, out);
    out = z3::ite(op == ctx.int_val(OP_NOT), ~a, out);
    out = z3::ite(op == ctx.int_val(OP_SHL), shift_family(ctx, a, imm, OP_SHL), out);
    out = z3::ite(op == ctx.int_val(OP_SHR), shift_family(ctx, a, imm, OP_SHR), out);
    out = z3::ite(op == ctx.int_val(OP_ROTL), shift_family(ctx, a, imm, OP_ROTL), out);
    out = z3::ite(op == ctx.int_val(OP_ROTR), shift_family(ctx, a, imm, OP_ROTR), out);
    out = z3::ite(op == ctx.int_val(OP_XORI), a ^ imm, out);
    out = z3::ite(op == ctx.int_val(OP_ADDI), a + imm, out);
    out = z3::ite(op == ctx.int_val(OP_ANDI), a & imm, out);
    return out;
}

z3::expr op_is(z3::context& ctx, const z3::expr& op, int value) {
    return op == ctx.int_val(value);
}

void constrain_sketch(z3::context& ctx,
                      z3::solver& solver,
                      const SymbolicSketch& sketch,
                      const Config& cfg) {
    for (std::size_t i = 0; i < cfg.steps; ++i) {
        const int available = static_cast<int>(cfg.input_bytes + i);
        solver.add(sketch.op[i] >= 0 && sketch.op[i] < OP_COUNT);
        solver.add(sketch.src_a[i] >= 0 && sketch.src_a[i] < available);
        solver.add(sketch.src_b[i] >= 0 && sketch.src_b[i] < available);

        const auto is_xor = op_is(ctx, sketch.op[i], OP_XOR);
        const auto is_and = op_is(ctx, sketch.op[i], OP_AND);
        const auto is_add = op_is(ctx, sketch.op[i], OP_ADD);
        const auto is_not = op_is(ctx, sketch.op[i], OP_NOT);
        const auto is_shl = op_is(ctx, sketch.op[i], OP_SHL);
        const auto is_shr = op_is(ctx, sketch.op[i], OP_SHR);
        const auto is_rotl = op_is(ctx, sketch.op[i], OP_ROTL);
        const auto is_rotr = op_is(ctx, sketch.op[i], OP_ROTR);
        const auto is_xori = op_is(ctx, sketch.op[i], OP_XORI);
        const auto is_addi = op_is(ctx, sketch.op[i], OP_ADDI);
        const auto is_andi = op_is(ctx, sketch.op[i], OP_ANDI);

        const auto is_commutative = is_xor || is_and || is_add;
        const auto is_shift = is_shl || is_shr || is_rotl || is_rotr;
        const auto is_immediate = is_xori || is_addi || is_andi;
        const auto is_unary = is_not || is_shift || is_immediate;
        const auto no_immediate = is_commutative || is_not;

        // Symmetry breaking only: these constraints retain one representative
        // of every distinct <=N-step computation in the DSL.
        solver.add(!is_commutative || sketch.src_a[i] <= sketch.src_b[i]);
        solver.add(!is_unary || sketch.src_b[i] == sketch.src_a[i]);
        solver.add(!no_immediate || sketch.imm[i] == ctx.bv_val(0, 8));

        z3::expr legal_shift = sketch.imm[i] == ctx.bv_val(1, 8);
        for (unsigned k = 2; k <= 7; ++k)
            legal_shift = legal_shift || sketch.imm[i] == ctx.bv_val(k, 8);
        solver.add(!is_shift || legal_shift);

        // Remove exact duplicate spellings while preserving the same functions:
        // XORI x,0 remains the canonical identity used to pad shorter programs.
        solver.add(!is_xori || sketch.imm[i] != ctx.bv_val(0xff, 8)); // NOT x
        solver.add(!is_addi || sketch.imm[i] != ctx.bv_val(0x00, 8)); // identity
        solver.add(!is_andi || sketch.imm[i] != ctx.bv_val(0xff, 8)); // identity
    }

    // Normalize an "up to N steps" breaker to exactly N symbolic instructions by
    // requiring the last produced register as the observation source. Any shorter
    // breaker can be padded with XORI(x,0), which remains in the grammar.
    const int last_reg = static_cast<int>(cfg.input_bytes + cfg.steps - 1);
    solver.add(sketch.output_reg == last_reg);
    solver.add(sketch.output_bit >= 0 && sketch.output_bit < 8);

    // Dead-code elimination as symmetry breaking. Every non-final generated
    // register must feed some later instruction. Any breaker can first have dead
    // instructions removed and then be identity-padded back to N steps.
    for (std::size_t i = 0; i + 1 < cfg.steps; ++i) {
        const int produced_reg = static_cast<int>(cfg.input_bytes + i);
        z3::expr used = (sketch.src_a[i + 1] == produced_reg) ||
                        (sketch.src_b[i + 1] == produced_reg);
        for (std::size_t j = i + 2; j < cfg.steps; ++j) {
            used = used || (sketch.src_a[j] == produced_reg) ||
                   (sketch.src_b[j] == produced_reg);
        }
        solver.add(used);
    }
}

void add_example(z3::context& ctx,
                 z3::solver& solver,
                 const SymbolicSketch& sketch,
                 const Config& cfg,
                 const std::vector<std::uint8_t>& image,
                 std::uint8_t secret,
                 unsigned secret_bit) {
    std::vector<z3::expr> regs;
    regs.reserve(cfg.input_bytes + cfg.steps);
    for (std::size_t i = 0; i < cfg.input_bytes; ++i)
        regs.push_back(ctx.bv_val(image.at(i), 8));

    for (std::size_t i = 0; i < cfg.steps; ++i) {
        const auto a = select_reg(ctx, sketch.src_a[i], regs);
        const auto b = select_reg(ctx, sketch.src_b[i], regs);
        regs.push_back(apply_symbolic_op(ctx, sketch.op[i], a, b, sketch.imm[i]));
    }

    const auto observed_word = select_reg(ctx, sketch.output_reg, regs);
    const auto observed_bit = select_bit(ctx, sketch.output_bit, observed_word);
    const auto target_bit = ctx.bv_val((secret >> secret_bit) & 1u, 1);
    solver.add(observed_bit == target_bit);
}

std::uint64_t bv_uint64(z3::context& ctx, const z3::expr& value) {
    std::uint64_t out = 0;
    const z3::expr simplified = value.simplify();
    if (!Z3_get_numeral_uint64(ctx, simplified, &out))
        throw std::runtime_error("Z3 model returned non-numeral bit-vector");
    return out;
}

ConcreteProgram decode_program(z3::context& ctx,
                               const z3::model& model,
                               const SymbolicSketch& sketch,
                               const Config& cfg,
                               unsigned secret_bit) {
    ConcreteProgram out;
    out.instructions.reserve(cfg.steps);
    for (std::size_t i = 0; i < cfg.steps; ++i) {
        ConcreteInstruction ins;
        ins.op = model.eval(sketch.op[i], true).get_numeral_int();
        ins.src_a = model.eval(sketch.src_a[i], true).get_numeral_int();
        ins.src_b = model.eval(sketch.src_b[i], true).get_numeral_int();
        ins.imm = static_cast<std::uint8_t>(
            bv_uint64(ctx, model.eval(sketch.imm[i], true)) & 0xffu);
        out.instructions.push_back(ins);
    }
    out.output_reg = model.eval(sketch.output_reg, true).get_numeral_int();
    out.output_bit = model.eval(sketch.output_bit, true).get_numeral_int();
    out.secret_bit = static_cast<int>(secret_bit);
    return out;
}

const char* op_name(int op) {
    switch (op) {
        case OP_XOR: return "XOR";
        case OP_AND: return "AND";
        case OP_ADD: return "ADD";
        case OP_NOT: return "NOT";
        case OP_SHL: return "SHL";
        case OP_SHR: return "SHR";
        case OP_ROTL: return "ROTL";
        case OP_ROTR: return "ROTR";
        case OP_XORI: return "XORI";
        case OP_ADDI: return "ADDI";
        case OP_ANDI: return "ANDI";
        default: return "?";
    }
}

std::string reg_name(int index, std::size_t input_bytes) {
    if (index < 0) return "?";
    if (static_cast<std::size_t>(index) < input_bytes)
        return "s" + std::to_string(index);
    return "r" + std::to_string(static_cast<std::size_t>(index) - input_bytes);
}

void print_candidate(const ConcreteProgram& program, const Config& cfg) {
    std::cout << "candidate breaker:\n";
    for (std::size_t i = 0; i < program.instructions.size(); ++i) {
        const auto& ins = program.instructions[i];
        std::cout << "  r" << i << " = " << op_name(ins.op)
                  << '(' << reg_name(ins.src_a, cfg.input_bytes);
        if (ins.op == OP_XOR || ins.op == OP_AND || ins.op == OP_ADD)
            std::cout << ", " << reg_name(ins.src_b, cfg.input_bytes);
        else if (ins.op == OP_XORI || ins.op == OP_ADDI || ins.op == OP_ANDI)
            std::cout << ", 0x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned>(ins.imm) << std::dec << std::setfill(' ');
        else if (ins.op == OP_SHL || ins.op == OP_SHR ||
                 ins.op == OP_ROTL || ins.op == OP_ROTR)
            std::cout << ", " << static_cast<unsigned>(ins.imm & 7u);
        std::cout << ")\n";
    }
    std::cout << "  observe bit " << program.output_bit << " of "
              << reg_name(program.output_reg, cfg.input_bytes)
              << " -> reduced-root bit " << program.secret_bit << '\n';
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + arg);
            return argv[++i];
        };
        if (arg == "--steps") cfg.steps = std::stoul(require_value());
        else if (arg == "--inputs") cfg.input_bytes = std::stoul(require_value());
        else if (arg == "--timeout-ms") cfg.timeout_ms =
            static_cast<unsigned>(std::stoul(require_value()));
        else if (arg == "--root-bit") {
            const auto value = require_value();
            if (value == "all") cfg.root_bit = -1;
            else cfg.root_bit = std::stoi(value);
        } else if (arg == "--initial-examples") {
            cfg.initial_examples = std::stoul(require_value());
        } else if (arg == "--cex-batch") {
            cfg.counterexample_batch = std::stoul(require_value());
        } else if (arg == "--max-rounds") {
            cfg.max_cegis_rounds = std::stoul(require_value());
        } else if (arg == "--help") {
            std::cout << "usage: " << argv[0]
                      << " [--steps N] [--inputs N] [--timeout-ms N]"
                         " [--root-bit all|0..7] [--initial-examples N]"
                         " [--cex-batch N] [--max-rounds N]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }
    if (cfg.steps == 0 || cfg.steps > 6)
        throw std::runtime_error("--steps must be in 1..6");
    if (cfg.input_bytes == 0 || cfg.input_bytes > 16)
        throw std::runtime_error("--inputs must be in 1..16");
    if (cfg.timeout_ms == 0)
        throw std::runtime_error("--timeout-ms must be positive");
    if (cfg.root_bit < -1 || cfg.root_bit > 7)
        throw std::runtime_error("--root-bit must be all or 0..7");
    if (cfg.initial_examples == 0 || cfg.initial_examples > 256)
        throw std::runtime_error("--initial-examples must be in 1..256");
    if (cfg.counterexample_batch == 0 || cfg.counterexample_batch > 256)
        throw std::runtime_error("--cex-batch must be in 1..256");
    if (cfg.max_cegis_rounds == 0)
        throw std::runtime_error("--max-rounds must be positive");
    return cfg;
}

enum class BitStatus {
    unsat,
    breaker,
    inconclusive,
};

struct BitResult {
    BitStatus status{BitStatus::inconclusive};
    std::string reason;
};

BitResult audit_secret_bit(unsigned secret_bit,
                           const Config& cfg,
                           const std::vector<std::vector<std::uint8_t>>& images) {
    constexpr std::size_t DOMAIN = 256;

    std::array<bool, DOMAIN> included{};
    std::vector<std::size_t> examples;
    examples.reserve(DOMAIN);
    for (std::size_t i = 0; i < cfg.initial_examples && i < DOMAIN; ++i) {
        const std::size_t x = (i * 73u + 19u) & 0xffu;
        if (!included[x]) {
            included[x] = true;
            examples.push_back(x);
        }
    }

    for (std::size_t round = 0; round < cfg.max_cegis_rounds; ++round) {
        std::cout << "[RUN ] root bit " << secret_bit
                  << ", CEGIS round " << (round + 1)
                  << ", " << examples.size() << " constrained roots... "
                  << std::flush;

        z3::context ctx;
        z3::solver solver(ctx);
        z3::params params(ctx);
        params.set("timeout", cfg.timeout_ms);
        solver.set(params);

        SymbolicSketch sketch(ctx, cfg.steps);
        constrain_sketch(ctx, solver, sketch, cfg);
        for (const auto x : examples)
            add_example(ctx, solver, sketch, cfg, images[x],
                        static_cast<std::uint8_t>(x), secret_bit);

        const auto result = solver.check();
        if (result == z3::unsat) {
            std::cout << "PASS (UNSAT)\n";
            return {BitStatus::unsat, {}};
        }
        if (result == z3::unknown) {
            const std::string why = solver.reason_unknown();
            std::cout << "INCONCLUSIVE (Z3 unknown: " << why << ")\n";
            return {BitStatus::inconclusive, why};
        }

        const auto candidate =
            decode_program(ctx, solver.get_model(), sketch, cfg, secret_bit);
        std::vector<std::size_t> counterexamples;
        counterexamples.reserve(cfg.counterexample_batch);
        for (std::size_t x = 0; x < DOMAIN; ++x) {
            if (!candidate_recovers(candidate, images[x],
                                    static_cast<std::uint8_t>(x),
                                    cfg.input_bytes)) {
                counterexamples.push_back(x);
                if (counterexamples.size() >= cfg.counterexample_batch)
                    break;
            }
        }

        if (counterexamples.empty()) {
            std::cout << "FAIL (generic breaker found)\n";
            print_candidate(candidate, cfg);
            return {BitStatus::breaker, {}};
        }

        std::size_t added = 0;
        for (const auto x : counterexamples) {
            if (!included[x]) {
                included[x] = true;
                examples.push_back(x);
                ++added;
            }
        }
        std::cout << "      SAT on sample; rejected by "
                  << counterexamples.size()
                  << " full-domain counterexamples, added " << added << '\n';

        if (added == 0)
            throw std::runtime_error(
                "CEGIS made no progress despite concrete counterexamples");
    }

    return {BitStatus::inconclusive, "CEGIS round limit reached"};
}

} // namespace

int main(int argc, char** argv) try {
    const Config cfg = parse_args(argc, argv);

    constexpr std::size_t DOMAIN = 256;
    KmacSeriesGenerator generator(16);
    const std::vector<std::uint8_t> semantic_input{1,0,1,1,0,0,0,0};

    std::vector<std::vector<std::uint8_t>> images;
    images.reserve(DOMAIN);
    for (std::size_t x = 0; x < DOMAIN; ++x)
        images.push_back(generator.derive(
            semantic_input, reduced_root(static_cast<std::uint8_t>(x)), 19).series);

    if (cfg.input_bytes > images.front().size())
        throw std::runtime_error(
            "requested observable bytes exceed generated series");

    std::cout << "V0ID bounded bitvector attacker audit\n"
              << "  reduced roots      : 256 exhaustive values\n"
              << "  observed series    : first " << cfg.input_bytes << " bytes\n"
              << "  step budget        : <= " << cfg.steps
              << " (normalized to " << cfg.steps << " with XORI(x,0) padding)\n"
              << "  operations         : XOR AND ADD NOT SHL SHR ROTL ROTR XORI ADDI ANDI\n"
              << "  target root bits   : "
              << (cfg.root_bit < 0 ? "all 0..7" : std::to_string(cfg.root_bit)) << '\n'
              << "  output             : any bit of normalized final register\n"
              << "  symmetry breaking  : commutative order, canonical unused fields,"
                 " live instructions\n"
              << "  oracle tables      : forbidden by bounded shared-program sketch\n"
              << "  solver timeout     : " << cfg.timeout_ms << " ms/root-bit check\n\n";

    std::vector<unsigned> target_bits;
    if (cfg.root_bit >= 0) {
        target_bits.push_back(static_cast<unsigned>(cfg.root_bit));
    } else {
        for (unsigned bit = 0; bit < 8; ++bit)
            target_bits.push_back(bit);
    }

    bool saw_inconclusive = false;
    std::vector<unsigned> unsat_bits;
    std::vector<unsigned> unknown_bits;

    for (const auto bit : target_bits) {
        const auto result = audit_secret_bit(bit, cfg, images);
        if (result.status == BitStatus::breaker) {
            std::cout << "\nV0ID bitvector series audit: FAIL\n"
                      << "The printed shared program replayed successfully across all "
                         "256 reduced roots.\n"
                      << "Treat it as a structural cryptanalytic lead, not a benchmark artifact.\n";
            return 1;
        }
        if (result.status == BitStatus::unsat) {
            unsat_bits.push_back(bit);
        } else {
            saw_inconclusive = true;
            unknown_bits.push_back(bit);
        }
    }

    if (saw_inconclusive) {
        std::cout << "\nV0ID bitvector series audit: INCONCLUSIVE\n";
        if (!unsat_bits.empty()) {
            std::cout << "Exact UNSAT within this normalized <= " << cfg.steps
                      << "-step DSL for root bits:";
            for (const auto bit : unsat_bits) std::cout << ' ' << bit;
            std::cout << '\n';
        }
        std::cout << "Unresolved root bits:";
        for (const auto bit : unknown_bits) std::cout << ' ' << bit;
        std::cout << "\nUNKNOWN/round-limit is never PASS. Increase --timeout-ms,"
                     " reduce the bound, or run one bit with --root-bit N.\n";
        return 2;
    }

    std::cout << "\nV0ID bitvector series audit: PASS\n"
              << "UNSAT for every requested root bit in the normalized <= "
              << cfg.steps << "-step attacker DSL.\n"
              << "Because commutative ordering, unused-field normalization, dead-code"
                 " removal and XORI(x,0) padding preserve every <=N-step computation,"
                 " these symmetry constraints do not weaken the stated attacker class.\n"
              << "UNSAT on each constrained subset is sufficient: a full-domain breaker"
                 " would also have to satisfy that subset.\n"
              << "This closes only this reduced-domain/bounded DSL, not arbitrary programs"
                 " or future quantum algorithms.\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID bitvector series audit fatal error: " << e.what() << '\n';
    return 3;
}
