#include "program_morpher.hpp"

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using v0id::core::Program;
using v0id::core::Rule;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;

constexpr std::size_t FAMILY_COUNT = 4;
constexpr std::size_t PUBLIC_STATES = 24;
constexpr std::size_t PUBLIC_TAPE_CELLS = 64;
constexpr std::size_t PUBLIC_ROUNDS = 32;
constexpr std::size_t PUBLIC_INTEGRITY_SLOTS = 4;

struct Sample {
    std::size_t family{};
    std::size_t ordinal{};
    std::vector<double> evaluator_features;
    std::vector<double> plaintext_features;
};

std::uint64_t splitmix64(std::uint64_t& x) {
    x += 0x9e3779b97f4a7c15ULL;
    std::uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

MorphSeed benchmark_seed(std::size_t family, std::size_t ordinal) {
    MorphSeed seed{};
    std::uint64_t state = 0x563049442d444953ULL ^
                          (static_cast<std::uint64_t>(family) << 40) ^
                          static_cast<std::uint64_t>(ordinal);
    for (std::size_t word = 0; word < 4; ++word) {
        const auto value = splitmix64(state);
        for (std::size_t byte = 0; byte < 8; ++byte)
            seed[word * 8 + byte] = static_cast<unsigned char>(
                (value >> (8 * byte)) & 0xffu);
    }
    return seed;
}

Program make_family(std::size_t family) {
    Program p;
    p.states = 4;
    p.rules.reserve(p.states * 2);

    for (std::size_t state = 0; state < p.states; ++state) {
        for (int read = 0; read <= 1; ++read) {
            Rule r;
            r.state = state;
            r.read = read;

            switch (family) {
                case 0: // right-moving ring, value preserving
                    r.next_state = (state + 1) % p.states;
                    r.write = read;
                    r.move = +1;
                    break;
                case 1: // left-moving ring, value flipping
                    r.next_state = (state + 1) % p.states;
                    r.write = 1 - read;
                    r.move = -1;
                    break;
                case 2: // mixed stay/self-loop and right-moving path
                    if (read == 0) {
                        r.next_state = state;
                        r.write = 0;
                        r.move = 0;
                    } else {
                        r.next_state = (state + 1) % p.states;
                        r.write = 1;
                        r.move = +1;
                    }
                    break;
                case 3: // different transition/move/write aggregate profile
                    if (read == 0) {
                        r.next_state = (state + 2) % p.states;
                        r.write = 1;
                        r.move = 0;
                    } else {
                        r.next_state = (state + 3) % p.states;
                        r.write = 0;
                        r.move = -1;
                    }
                    break;
                default:
                    throw std::runtime_error("invalid benchmark family");
            }
            p.rules.push_back(r);
        }
    }

    p.validate();
    return p;
}

std::vector<double> evaluator_visible_features(const Program& morphed) {
    // Phase-1 evaluator view: only deliberately public fixed dimensions. The
    // encrypted transition values are not plaintext evaluator features.
    const auto states = static_cast<double>(morphed.states);
    const auto rules = static_cast<double>(morphed.rules.size());
    const auto encrypted_program_bits =
        static_cast<double>(morphed.states * 2 * (morphed.states + 4));

    return {
        states,
        rules,
        encrypted_program_bits,
        static_cast<double>(PUBLIC_TAPE_CELLS),
        static_cast<double>(PUBLIC_ROUNDS),
        static_cast<double>(PUBLIC_INTEGRITY_SLOTS),
    };
}

std::vector<double> plaintext_diagnostic_features(const Program& morphed) {
    // Stronger-than-evaluator diagnostic. These aggregate plaintext semantics
    // are hidden by BinFHE in the remote protocol, but they tell us how much the
    // ProgramMorpher itself hides independently of encryption.
    std::size_t self_loops = 0;
    std::size_t write_flips = 0;
    std::size_t write_zero = 0;
    std::size_t write_one = 0;
    std::size_t move_left = 0;
    std::size_t move_stay = 0;
    std::size_t move_right = 0;

    for (const auto& r : morphed.rules) {
        if (r.next_state == r.state) ++self_loops;
        if (r.write != r.read) ++write_flips;
        if (r.write == 0) ++write_zero; else ++write_one;
        if (r.move < 0) ++move_left;
        else if (r.move > 0) ++move_right;
        else ++move_stay;
    }

    return {
        static_cast<double>(self_loops),
        static_cast<double>(write_flips),
        static_cast<double>(write_zero),
        static_cast<double>(write_one),
        static_cast<double>(move_left),
        static_cast<double>(move_stay),
        static_cast<double>(move_right),
    };
}

using Centroids = std::array<std::vector<double>, FAMILY_COUNT>;

Centroids train_centroids(const std::vector<Sample>& samples,
                          bool evaluator_view) {
    Centroids sums;
    std::array<std::size_t, FAMILY_COUNT> counts{};

    for (const auto& sample : samples) {
        if (sample.ordinal % 4 == 0) continue; // held-out 25%
        const auto& f = evaluator_view ? sample.evaluator_features
                                       : sample.plaintext_features;
        if (sums[sample.family].empty()) sums[sample.family].assign(f.size(), 0.0);
        if (sums[sample.family].size() != f.size())
            throw std::runtime_error("feature width mismatch");
        for (std::size_t i = 0; i < f.size(); ++i)
            sums[sample.family][i] += f[i];
        ++counts[sample.family];
    }

    for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
        if (counts[family] == 0)
            throw std::runtime_error("empty training class");
        for (auto& value : sums[family])
            value /= static_cast<double>(counts[family]);
    }
    return sums;
}

std::size_t classify(const std::vector<double>& features,
                     const Centroids& centroids) {
    double best = std::numeric_limits<double>::infinity();
    std::size_t best_family = 0;
    for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
        if (centroids[family].size() != features.size())
            throw std::runtime_error("centroid feature width mismatch");
        double d2 = 0.0;
        for (std::size_t i = 0; i < features.size(); ++i) {
            const double d = features[i] - centroids[family][i];
            d2 += d * d;
        }
        if (d2 < best) {
            best = d2;
            best_family = family;
        }
    }
    return best_family;
}

struct Evaluation {
    double accuracy{};
    std::array<std::array<std::size_t, FAMILY_COUNT>, FAMILY_COUNT> confusion{};
};

Evaluation evaluate(const std::vector<Sample>& samples, bool evaluator_view) {
    const auto centroids = train_centroids(samples, evaluator_view);
    Evaluation out;
    std::size_t correct = 0;
    std::size_t total = 0;

    for (const auto& sample : samples) {
        if (sample.ordinal % 4 != 0) continue;
        const auto& f = evaluator_view ? sample.evaluator_features
                                       : sample.plaintext_features;
        const auto predicted = classify(f, centroids);
        ++out.confusion[sample.family][predicted];
        correct += predicted == sample.family ? 1u : 0u;
        ++total;
    }

    if (total == 0) throw std::runtime_error("empty test set");
    out.accuracy = static_cast<double>(correct) / static_cast<double>(total);
    return out;
}

void print_confusion(const Evaluation& result) {
    std::cout << "      predicted:  0    1    2    3\n";
    for (std::size_t actual = 0; actual < FAMILY_COUNT; ++actual) {
        std::cout << "      actual " << actual << ":";
        for (std::size_t predicted = 0; predicted < FAMILY_COUNT; ++predicted)
            std::cout << ' ' << std::setw(4) << result.confusion[actual][predicted];
        std::cout << '\n';
    }
}

} // namespace

int main(int argc, char** argv) try {
    std::size_t samples_per_family = 256;
    if (argc == 3 && std::string(argv[1]) == "--samples") {
        samples_per_family = std::stoul(argv[2]);
    } else if (argc != 1) {
        throw std::runtime_error("usage: v0id-polymorphism-distinguisher [--samples N]");
    }
    if (samples_per_family < 8)
        throw std::runtime_error("--samples must be at least 8 per family");

    std::array<Program, FAMILY_COUNT> bases{
        make_family(0), make_family(1), make_family(2), make_family(3)};

    std::vector<Sample> dataset;
    dataset.reserve(FAMILY_COUNT * samples_per_family);
    for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
        for (std::size_t ordinal = 0; ordinal < samples_per_family; ++ordinal) {
            const auto morphed = ProgramMorpher::morph(
                bases[family], 0, PUBLIC_STATES,
                benchmark_seed(family, ordinal), PUBLIC_INTEGRITY_SLOTS);

            Sample sample;
            sample.family = family;
            sample.ordinal = ordinal;
            sample.evaluator_features = evaluator_visible_features(morphed.program);
            sample.plaintext_features = plaintext_diagnostic_features(morphed.program);
            dataset.push_back(std::move(sample));
        }
    }

    const auto evaluator = evaluate(dataset, true);
    const auto plaintext = evaluate(dataset, false);
    constexpr double chance = 1.0 / static_cast<double>(FAMILY_COUNT);

    std::cout << "V0ID polymorphism distinguisher benchmark\n"
              << "  semantic families       : " << FAMILY_COUNT << '\n'
              << "  morphs/family           : " << samples_per_family << '\n'
              << "  public states           : " << PUBLIC_STATES << '\n'
              << "  held-out split          : 25% (ordinal mod 4 == 0)\n"
              << "  classifier              : nearest class centroid\n"
              << "  random-class baseline   : " << std::fixed << std::setprecision(2)
              << chance * 100.0 << "%\n\n";

    std::cout << "[VIEW 1] evaluator-visible fixed public shape\n"
              << "  accuracy                : " << evaluator.accuracy * 100.0 << "%\n";
    print_confusion(evaluator);

    std::cout << "\n[VIEW 2] stronger plaintext morph diagnostic (NOT server-visible under BinFHE)\n"
              << "  accuracy                : " << plaintext.accuracy * 100.0 << "%\n";
    print_confusion(plaintext);

    const bool public_shape_at_baseline = evaluator.accuracy <= chance + 1e-12;
    std::cout << "\n"
              << (public_shape_at_baseline ? "[PASS] " : "[FAIL] ")
              << "fixed public-shape features do not beat the balanced-class baseline\n";

    if (plaintext.accuracy > chance + 0.10) {
        std::cout << "[DIAGNOSTIC] plaintext aggregate transition semantics still identify"
                     " source families.\n"
                  << "             This is not evaluator leakage in the current BinFHE"
                     " protocol; it shows\n"
                  << "             ProgramMorpher alone is state relabeling/padding, not"
                     " standalone obfuscation.\n";
    } else {
        std::cout << "[DIAGNOSTIC] this plaintext feature set did not distinguish the"
                     " morphed families.\n";
    }

    std::cout << "\nScope: this phase measures fixed public-shape leakage and a"
                 " stronger-than-evaluator plaintext diagnostic.\n"
              << "It does NOT yet measure ciphertext serialization sizes, evaluator"
                 " timing, bootstrapping traces, or network metadata.\n";

    return public_shape_at_baseline ? 0 : 1;
} catch (const std::exception& e) {
    std::cerr << "V0ID polymorphism distinguisher fatal error: " << e.what() << '\n';
    return 2;
}
