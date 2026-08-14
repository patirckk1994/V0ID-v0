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
    z3::expr secret_bit;

    SymbolicSketch(z3::context& ctx, std::size_t steps)
        : output_reg(ctx.int_const("output_reg")),
          output_bit(ctx.int_const("output_bit")),
          secret_bit(ctx.int_const("secret_bit")) {
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

z3::expr select_bit(z3::context& ctx,
                    const z3::expr& selector,
                    const z3::expr& word) {
    z3::expr out = z3::extract(0, 0, word);
    for (unsigned bit = 1; bit < 8; ++bit)
        out = z3::ite(selector == ctx.int_val(static_cast<int>(bit)),
                      z3::extract(bit, bit, word), out);
    return out;
}

z3::expr select_secret_bit(z3::context& ctx,
                           const z3::expr& selector,
                           std::uint8_t secret) {
    z3::expr out = ctx.bv_val(secret & 1u, 1);
    for (unsigned bit = 1; bit < 8; ++bit)
        out = z3::ite(selector == ctx.int_val(static_cast<int>(bit)),
                      ctx.bv_val((secret >> bit) & 1u, 1), out);
    return out;
}

z3::expr shift_family(z3::context& ctx,
                      const z3::expr& a,
                      const z3::expr& imm,
                      int kind) {
    const z3::expr low = z3::extract(2, 0, imm);

    auto apply = [&](unsigned k) -> z3::expr {
        const auto sh = ctx.bv_val(k, 8);
        const auto inv = ctx.bv_val(8u - k, 8);
        switch (kind) {
            case OP_SHL:  return a << sh;
            case OP_SHR:  return z3::lshr(a, sh);
            case OP_ROTL: return (a << sh) | z3::lshr(a, inv);
            case OP_ROTR: return z3::lshr(a, sh) | (a << inv);
            default: throw std::runtime_error("invalid shift-family opcode");
        }
    };

    // Immediate low bits 0 and 1 both mean shift/rotate by one. This keeps the
    // search grammar free of undefined shift counts while still allowing 1..7.
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

void constrain_sketch(z3::context& ctx,
                      z3::solver& solver,
                      const SymbolicSketch& sketch,
                      const Config& cfg) {
    for (std::size_t i = 0; i < cfg.steps; ++i) {
        const int available = static_cast<int>(cfg.input_bytes + i);
        solver.add(sketch.op[i] >= 0 && sketch.op[i] < OP_COUNT);
        solver.add(sketch.src_a[i] >= 0 && sketch.src_a[i] < available);
        solver.add(sketch.src_b[i] >= 0 && sketch.src_b[i] < available);
    }
    solver.add(sketch.output_reg >= 0 &&
               sketch.output_reg < static_cast<int>(cfg.input_bytes + cfg.steps));
    solver.add(sketch.output_bit >= 0 && sketch.output_bit < 8);
    solver.add(sketch.secret_bit >= 0 && sketch.secret_bit < 8);
}

void add_example(z3::context& ctx,
                 z3::solver& solver,
                 const SymbolicSketch& sketch,
                 const Config& cfg,
                 const std::vector<std::uint8_t>& image,
                 std::uint8_t secret) {
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
    const auto target_bit = select_secret_bit(ctx, sketch.secret_bit, secret);
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
                               const Config& cfg) {
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
    out.secret_bit = model.eval(sketch.secret_bit, true).get_numeral_int();
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
            std::cout << ", " << static_cast<unsigned>((ins.imm & 7u) == 0 ? 1u : (ins.imm & 7u));
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
        else if (arg == "--help") {
            std::cout << "usage: " << argv[0]
                      << " [--steps N] [--inputs N] [--timeout-ms N]\n";
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
    return cfg;
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
        throw std::runtime_error("requested observable bytes exceed generated series");

    std::cout << "V0ID bounded bitvector attacker audit\n"
              << "  reduced roots      : 256 exhaustive values\n"
              << "  observed series    : first " << cfg.input_bytes << " bytes\n"
              << "  straight-line steps: " << cfg.steps << '\n'
              << "  operations         : XOR AND ADD NOT SHL SHR ROTL ROTR XORI ADDI ANDI\n"
              << "  objective          : recover ANY one root bit from ANY output bit/register\n"
              << "  oracle tables      : forbidden by bounded shared-program sketch\n"
              << "  solver timeout     : " << cfg.timeout_ms << " ms/check\n\n";

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
        std::cout << "[RUN ] CEGIS round " << (round + 1)
                  << " with " << examples.size() << " constrained roots... "
                  << std::flush;

        z3::context ctx;
        z3::solver solver(ctx);
        z3::params params(ctx);
        params.set("timeout", cfg.timeout_ms);
        solver.set(params);

        SymbolicSketch sketch(ctx, cfg.steps);
        constrain_sketch(ctx, solver, sketch, cfg);
        for (const auto x : examples)
            add_example(ctx, solver, sketch, cfg, images[x], static_cast<std::uint8_t>(x));

        const auto result = solver.check();
        if (result == z3::unsat) {
            std::cout << "PASS (UNSAT)\n\n"
                      << "V0ID bitvector series audit: PASS\n"
                      << "No shared " << cfg.steps << "-step program in this exact DSL can recover\n"
                      << "any reduced-root bit from any bit/register of the first "
                      << cfg.input_bytes << " series bytes.\n"
                      << "UNSAT on a subset is sufficient here: any full-domain breaker would also\n"
                      << "have to satisfy that subset. This closes only this bounded attacker class.\n";
            return 0;
        }
        if (result == z3::unknown) {
            std::cout << "INCONCLUSIVE (Z3 unknown: " << solver.reason_unknown() << ")\n\n"
                      << "V0ID bitvector series audit: INCONCLUSIVE\n"
                      << "Increase --timeout-ms or reduce --steps/--inputs. UNKNOWN is never PASS.\n";
            return 2;
        }

        const auto candidate = decode_program(ctx, solver.get_model(), sketch, cfg);
        std::vector<std::size_t> counterexamples;
        counterexamples.reserve(cfg.counterexample_batch);
        for (std::size_t x = 0; x < DOMAIN; ++x) {
            if (!candidate_recovers(candidate, images[x], static_cast<std::uint8_t>(x),
                                    cfg.input_bytes)) {
                counterexamples.push_back(x);
                if (counterexamples.size() >= cfg.counterexample_batch)
                    break;
            }
        }

        if (counterexamples.empty()) {
            std::cout << "FAIL (generic breaker found)\n";
            print_candidate(candidate, cfg);
            std::cout << "\nV0ID bitvector series audit: FAIL\n"
                      << "The printed program generalized across all 256 reduced roots.\n"
                      << "Treat this as a structural cryptanalytic lead, not as a benchmark artifact.\n";
            return 1;
        }

        std::size_t added = 0;
        for (const auto x : counterexamples) {
            if (!included[x]) {
                included[x] = true;
                examples.push_back(x);
                ++added;
            }
        }
        std::cout << "SAT on sample; rejected by " << counterexamples.size()
                  << " full-domain counterexamples, added " << added << "\n";

        if (added == 0)
            throw std::runtime_error("CEGIS made no progress despite counterexamples");
    }

    std::cout << "\nV0ID bitvector series audit: INCONCLUSIVE\n"
              << "CEGIS round limit reached without a generic breaker or UNSAT proof.\n";
    return 2;
} catch (const std::exception& e) {
    std::cerr << "V0ID bitvector series audit fatal error: " << e.what() << '\n';
    return 3;
}
