#include "boolean_ir_to_program.hpp"

#include <array>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace v0id::integrity {
namespace {

using v0id::core::Program;
using v0id::core::Rule;

std::size_t dist(std::size_t a, std::size_t b) {
    return a > b ? a - b : b - a;
}

std::size_t sat_add(std::size_t a, std::size_t b) {
    const auto max = std::numeric_limits<std::size_t>::max();
    if (b > max - a) return max;
    return a + b;
}

std::size_t sat_mul(std::size_t a, std::size_t b) {
    const auto max = std::numeric_limits<std::size_t>::max();
    if (a != 0 && b > max / a) return max;
    return a * b;
}

enum class ActionKind { Write0, Write1, Copy, Not, Xor, And };

struct Action {
    ActionKind kind{};
    std::size_t start_head{};
    std::size_t dest{};
    std::size_t a{};
    std::size_t b{};
};

struct ActionList {
    std::vector<Action> actions;
    std::vector<std::size_t> output_cells;
    std::size_t tape_cells{};
};

ActionList make_actions(const BooleanIR& ir, const BooleanIRLoweringPlan& plan) {
    validate_boolean_ir_lowering_plan(ir, plan);

    ActionList out;
    std::size_t head = plan.initial_head;
    for (const auto wire : plan.evaluation_order) {
        const auto& n = ir.nodes()[wire];
        Action a;
        a.start_head = head;
        a.dest = wire;
        a.a = n.a;
        a.b = n.b;
        switch (n.op) {
        case BoolOp::Input:
            throw std::runtime_error("input unexpectedly scheduled for lowering");
        case BoolOp::Const0: a.kind = ActionKind::Write0; break;
        case BoolOp::Const1: a.kind = ActionKind::Write1; break;
        case BoolOp::Not:    a.kind = ActionKind::Not; break;
        case BoolOp::Xor:    a.kind = ActionKind::Xor; break;
        case BoolOp::And:    a.kind = ActionKind::And; break;
        }
        out.actions.push_back(a);
        head = wire;
    }

    out.tape_cells = ir.nodes().size();
    if (plan.append_output_bank) {
        out.output_cells.reserve(ir.outputs().size());
        for (std::size_t i = 0; i < ir.outputs().size(); ++i) {
            const std::size_t dest = ir.nodes().size() + i;
            out.actions.push_back(Action{ActionKind::Copy, head, dest,
                                         ir.outputs()[i], 0});
            out.output_cells.push_back(dest);
            head = dest;
        }
        out.tape_cells += ir.outputs().size();
    } else {
        out.output_cells.assign(ir.outputs().begin(), ir.outputs().end());
    }
    return out;
}

std::size_t action_states(const Action& a) {
    switch (a.kind) {
    case ActionKind::Write0:
    case ActionKind::Write1:
        return sat_add(dist(a.start_head, a.dest), 1);
    case ActionKind::Copy:
    case ActionKind::Not: {
        // Move to source, branch on one bit, then each branch owns its own
        // move-to-destination and write state.
        auto n = dist(a.start_head, a.a);
        n = sat_add(n, 1);
        n = sat_add(n, sat_mul(2, dist(a.a, a.dest)));
        n = sat_add(n, 2);
        return n;
    }
    case ActionKind::Xor:
    case ActionKind::And: {
        // Branch on a, branch on b, then each of the four (a,b) cases owns
        // its own move-to-destination and write state.
        auto n = dist(a.start_head, a.a);
        n = sat_add(n, 1);
        n = sat_add(n, sat_mul(2, dist(a.a, a.b)));
        n = sat_add(n, 2);
        n = sat_add(n, sat_mul(4, dist(a.b, a.dest)));
        n = sat_add(n, 4);
        return n;
    }
    }
    return std::numeric_limits<std::size_t>::max();
}

std::size_t action_rounds(const Action& a) {
    switch (a.kind) {
    case ActionKind::Write0:
    case ActionKind::Write1:
        return sat_add(dist(a.start_head, a.dest), 1);
    case ActionKind::Copy:
    case ActionKind::Not: {
        auto n = dist(a.start_head, a.a);
        n = sat_add(n, 1);
        n = sat_add(n, dist(a.a, a.dest));
        return sat_add(n, 1);
    }
    case ActionKind::Xor:
    case ActionKind::And: {
        auto n = dist(a.start_head, a.a);
        n = sat_add(n, 1);
        n = sat_add(n, dist(a.a, a.b));
        n = sat_add(n, 1);
        n = sat_add(n, dist(a.b, a.dest));
        return sat_add(n, 1);
    }
    }
    return std::numeric_limits<std::size_t>::max();
}

class ProgramBuilder {
public:
    std::size_t add_state() {
        rows_.push_back({std::nullopt, std::nullopt});
        return rows_.size() - 1;
    }

    void set(std::size_t state, int read, std::size_t next,
             int write, int move) {
        if (state >= rows_.size() || next >= rows_.size() || read < 0 || read > 1)
            throw std::runtime_error("reference TM builder state out of range");
        auto& slot = rows_[state][static_cast<std::size_t>(read)];
        if (slot.has_value())
            throw std::runtime_error("reference TM builder duplicate rule");
        slot = Rule{state, read, next, write, move};
    }

    Program finish() const {
        Program p;
        p.states = rows_.size();
        p.rules.resize(p.states * 2);
        for (std::size_t q = 0; q < rows_.size(); ++q) {
            for (int bit = 0; bit <= 1; ++bit) {
                const auto& slot = rows_[q][static_cast<std::size_t>(bit)];
                if (!slot.has_value())
                    throw std::runtime_error("reference TM builder missing rule");
                p.rules[q * 2 + static_cast<std::size_t>(bit)] = *slot;
            }
        }
        p.validate();
        return p;
    }

private:
    std::vector<std::array<std::optional<Rule>, 2>> rows_;
};

std::size_t make_move_chain(ProgramBuilder& b, std::size_t from,
                            std::size_t to, std::size_t next) {
    const int move = to > from ? +1 : -1;
    std::size_t entry = next;
    for (std::size_t i = 0; i < dist(from, to); ++i) {
        const auto q = b.add_state();
        b.set(q, 0, entry, 0, move);
        b.set(q, 1, entry, 1, move);
        entry = q;
    }
    return entry;
}

std::size_t make_write(ProgramBuilder& b, int value, std::size_t next) {
    const auto q = b.add_state();
    b.set(q, 0, next, value, 0);
    b.set(q, 1, next, value, 0);
    return q;
}

std::size_t make_read_branch(ProgramBuilder& b,
                             std::size_t zero_next,
                             std::size_t one_next) {
    const auto q = b.add_state();
    b.set(q, 0, zero_next, 0, 0);
    b.set(q, 1, one_next, 1, 0);
    return q;
}

std::size_t build_unary(ProgramBuilder& b, const Action& a,
                        std::size_t continuation, bool invert) {
    const auto w0 = make_write(b, invert ? 1 : 0, continuation);
    const auto w1 = make_write(b, invert ? 0 : 1, continuation);
    const auto p0 = make_move_chain(b, a.a, a.dest, w0);
    const auto p1 = make_move_chain(b, a.a, a.dest, w1);
    const auto read = make_read_branch(b, p0, p1);
    return make_move_chain(b, a.start_head, a.a, read);
}

int binary_value(ActionKind kind, int a, int b) {
    if (kind == ActionKind::Xor) return a ^ b;
    if (kind == ActionKind::And) return a & b;
    throw std::runtime_error("non-binary action passed to binary_value");
}

std::size_t build_binary(ProgramBuilder& b, const Action& a,
                         std::size_t continuation) {
    std::array<std::size_t, 2> after_a{};
    for (int av = 0; av <= 1; ++av) {
        std::array<std::size_t, 2> after_b{};
        for (int bv = 0; bv <= 1; ++bv) {
            const auto write = make_write(
                b, binary_value(a.kind, av, bv), continuation);
            after_b[static_cast<std::size_t>(bv)] =
                make_move_chain(b, a.b, a.dest, write);
        }
        const auto read_b = make_read_branch(b, after_b[0], after_b[1]);
        after_a[static_cast<std::size_t>(av)] =
            make_move_chain(b, a.a, a.b, read_b);
    }
    const auto read_a = make_read_branch(b, after_a[0], after_a[1]);
    return make_move_chain(b, a.start_head, a.a, read_a);
}

std::size_t build_action(ProgramBuilder& b, const Action& a,
                         std::size_t continuation) {
    switch (a.kind) {
    case ActionKind::Write0: {
        const auto write = make_write(b, 0, continuation);
        return make_move_chain(b, a.start_head, a.dest, write);
    }
    case ActionKind::Write1: {
        const auto write = make_write(b, 1, continuation);
        return make_move_chain(b, a.start_head, a.dest, write);
    }
    case ActionKind::Copy:
        return build_unary(b, a, continuation, false);
    case ActionKind::Not:
        return build_unary(b, a, continuation, true);
    case ActionKind::Xor:
    case ActionKind::And:
        return build_binary(b, a, continuation);
    }
    throw std::runtime_error("unknown BooleanIR lowering action");
}

} // namespace

std::size_t estimate_reference_tm_states(
    const BooleanIR& ir,
    const BooleanIRLoweringPlan& plan) {
    const auto list = make_actions(ir, plan);
    std::size_t states = 1; // final no-op sink
    for (const auto& action : list.actions)
        states = sat_add(states, action_states(action));
    return states;
}

LoweredBooleanProgram lower_boolean_ir_to_program(
    const BooleanIR& ir,
    const BooleanIRLoweringPlan& plan) {
    const auto list = make_actions(ir, plan);
    const auto estimated = estimate_reference_tm_states(ir, plan);
    if (estimated > plan.max_states)
        throw std::runtime_error("reference BooleanIR TM lowering exceeds max_states");

    ProgramBuilder builder;
    const auto sink = builder.add_state();
    builder.set(sink, 0, sink, 0, 0);
    builder.set(sink, 1, sink, 1, 0);

    std::size_t entry = sink;
    for (auto it = list.actions.rbegin(); it != list.actions.rend(); ++it)
        entry = build_action(builder, *it, entry);

    LoweredBooleanProgram out;
    out.program = builder.finish();
    out.initial_state = entry;
    out.required_initial_head = plan.initial_head;
    out.tape_cells = list.tape_cells;
    out.output_cells = list.output_cells;
    out.input_cells.resize(ir.input_count());
    for (std::size_t i = 0; i < ir.input_count(); ++i)
        out.input_cells[i] = i;

    for (const auto& action : list.actions)
        out.execution_rounds = sat_add(out.execution_rounds,
                                       action_rounds(action));
    return out;
}

} // namespace v0id::integrity
