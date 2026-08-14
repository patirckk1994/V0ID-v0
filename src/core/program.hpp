#pragma once

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace v0id::core {

struct Rule {
    std::size_t state{};
    int read{};
    std::size_t next_state{};
    int write{};
    int move{}; // -1, 0, +1
};

struct Program {
    std::size_t states{};
    std::vector<Rule> rules;

    void validate() const {
        if (states == 0)
            throw std::runtime_error("program has no states");

        std::vector<int> seen(states * 2, 0);
        for (const auto& r : rules) {
            if (r.state >= states || r.next_state >= states ||
                (r.read != 0 && r.read != 1) ||
                (r.write != 0 && r.write != 1) ||
                r.move < -1 || r.move > 1)
                throw std::runtime_error("invalid transition rule");
            ++seen[r.state * 2 + static_cast<std::size_t>(r.read)];
        }

        for (int n : seen)
            if (n != 1)
                throw std::runtime_error("need exactly one rule per (state, bit)");
    }

    const Rule& rule(std::size_t state, int read) const {
        if (state >= states || (read != 0 && read != 1))
            throw std::runtime_error("program transition index out of range");

        for (const auto& r : rules)
            if (r.state == state && r.read == read)
                return r;

        throw std::runtime_error("missing transition rule");
    }
};

} // namespace v0id::core
