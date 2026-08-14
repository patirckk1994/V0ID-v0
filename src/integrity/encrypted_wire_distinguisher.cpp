#include "fhe_codec.hpp"
#include "program_morpher.hpp"
#include "remote_machine_codec.hpp"
#include "toy_fingerprint.hpp"

#include "binfhecontext.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace lbcrypto;
using v0id::core::Program;
using v0id::core::Rule;
using v0id::fhe::ByteBlob;
using v0id::fhe::CryptoProfileId;
using v0id::fhe::DigestBlob32;
using v0id::fhe::EvaluatorSessionId;
using v0id::fhe::PublicMachineShape;
using v0id::fhe::RemoteMachineBundle;
using v0id::integrity::EncryptedDigest32;
using v0id::polymorph::MorphSeed;
using v0id::polymorph::ProgramMorpher;

constexpr std::size_t FAMILY_COUNT = 4;
constexpr std::size_t PUBLIC_STATES = 8;
constexpr std::size_t PUBLIC_TAPE_CELLS = 8;
constexpr std::size_t PUBLIC_ROUNDS = 4;
constexpr std::size_t PUBLIC_INTEGRITY_SLOTS = 4;

struct Config {
    std::size_t sessions{8};
    std::size_t morphs_per_family_per_session{2};
};

struct Sample {
    std::size_t family{};
    std::size_t session{};
    std::size_t morph{};
    bool test{};
    std::vector<double> size_features;
    std::vector<double> byte_features;
};

std::uint64_t splitmix64(std::uint64_t& x) {
    x += 0x9e3779b97f4a7c15ULL;
    std::uint64_t z = x;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

MorphSeed morph_seed(std::size_t session, std::size_t morph) {
    // Deliberately independent of family: all four semantic families receive the
    // same state-layout randomness for a matched (session,morph) pair.
    MorphSeed seed{};
    std::uint64_t state = 0x563049442d574952ULL ^
                          (static_cast<std::uint64_t>(session) << 32) ^
                          static_cast<std::uint64_t>(morph);
    for (std::size_t word = 0; word < 4; ++word) {
        const auto value = splitmix64(state);
        for (std::size_t byte = 0; byte < 8; ++byte) {
            seed[word * 8 + byte] = static_cast<unsigned char>(
                (value >> (8 * byte)) & 0xffu);
        }
    }
    return seed;
}

EvaluatorSessionId session_id(std::size_t session) {
    EvaluatorSessionId id{};
    std::uint64_t state = 0x563049442d534553ULL ^
                          static_cast<std::uint64_t>(session);
    for (std::size_t word = 0; word < 4; ++word) {
        const auto value = splitmix64(state);
        for (std::size_t byte = 0; byte < 8; ++byte) {
            id[word * 8 + byte] = static_cast<std::uint8_t>(
                (value >> (8 * byte)) & 0xffu);
        }
    }
    if (std::all_of(id.begin(), id.end(), [](std::uint8_t b) { return b == 0; }))
        id[0] = 1;
    return id;
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
                case 0:
                    r.next_state = (state + 1) % p.states;
                    r.write = read;
                    r.move = +1;
                    break;
                case 1:
                    r.next_state = (state + 1) % p.states;
                    r.write = 1 - read;
                    r.move = -1;
                    break;
                case 2:
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
                case 3:
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
                    throw std::runtime_error("invalid wire benchmark family");
            }
            p.rules.push_back(r);
        }
    }
    p.validate();
    return p;
}

PublicMachineShape shape() {
    return PublicMachineShape{
        PUBLIC_STATES,
        PUBLIC_TAPE_CELLS,
        PUBLIC_ROUNDS,
        PUBLIC_INTEGRITY_SLOTS,
    };
}

CryptoProfileId profile() {
    return CryptoProfileId{
        "openfhe-binfhe",
        "STD128Q",
        "v0id-remote-machine-v3",
        "toy-fingerprint32-v1+quine-sha3-512-client-v1",
        "kmacxof256",
        1,
    };
}

std::vector<ByteBlob> serialize_ciphertexts(
    const std::vector<LWECiphertext>& ciphertexts) {
    std::vector<ByteBlob> out;
    out.reserve(ciphertexts.size());
    for (const auto& ct : ciphertexts)
        out.push_back(v0id::fhe::serialize_binary(ct));
    return out;
}

DigestBlob32 serialize_digest(const EncryptedDigest32& digest) {
    DigestBlob32 out;
    for (std::size_t i = 0; i < out.size(); ++i)
        out[i] = v0id::fhe::serialize_binary(digest[i]);
    return out;
}

std::vector<ByteBlob> flatten_integrity_blobs(const RemoteMachineBundle& bundle) {
    std::vector<ByteBlob> out;
    out.reserve(64 + bundle.integrity_mask_bits.size() * 32);
    for (const auto& blob : bundle.nonce_bits) out.push_back(blob);
    for (const auto& blob : bundle.fingerprint_initial_state_bits) out.push_back(blob);
    for (const auto& digest : bundle.integrity_mask_bits)
        for (const auto& blob : digest) out.push_back(blob);
    return out;
}

void append_size_stats(std::vector<double>& features,
                       const std::vector<ByteBlob>& blobs) {
    if (blobs.empty()) {
        features.insert(features.end(), 6, 0.0);
        return;
    }

    std::size_t total = 0;
    std::size_t min_size = std::numeric_limits<std::size_t>::max();
    std::size_t max_size = 0;
    for (const auto& blob : blobs) {
        total += blob.size();
        min_size = std::min(min_size, blob.size());
        max_size = std::max(max_size, blob.size());
    }
    const double mean = static_cast<double>(total) /
                        static_cast<double>(blobs.size());
    double variance = 0.0;
    for (const auto& blob : blobs) {
        const double d = static_cast<double>(blob.size()) - mean;
        variance += d * d;
    }
    variance /= static_cast<double>(blobs.size());

    features.push_back(static_cast<double>(blobs.size()));
    features.push_back(static_cast<double>(total));
    features.push_back(static_cast<double>(min_size));
    features.push_back(static_cast<double>(max_size));
    features.push_back(mean);
    features.push_back(std::sqrt(variance));
}

std::vector<double> size_features(const RemoteMachineBundle& bundle,
                                  const ByteBlob& wire) {
    std::vector<double> out;
    out.reserve(1 + 5 * 6);
    out.push_back(static_cast<double>(wire.size()));
    append_size_stats(out, bundle.program_bits);
    append_size_stats(out, bundle.state_bits);
    append_size_stats(out, bundle.head_bits);
    append_size_stats(out, bundle.tape_bits);
    append_size_stats(out, flatten_integrity_blobs(bundle));
    return out;
}

void append_byte_stats(std::vector<double>& out,
                       const std::vector<ByteBlob>& blobs) {
    std::array<std::uint64_t, 16> bins{};
    std::uint64_t count = 0;
    std::uint64_t zeros = 0;
    std::uint64_t ffs = 0;
    std::uint64_t repeats = 0;
    long double sum = 0.0L;
    long double sumsq = 0.0L;
    bool have_prev = false;
    std::uint8_t prev = 0;

    for (const auto& blob : blobs) {
        for (const auto byte : blob) {
            ++count;
            ++bins[byte >> 4];
            zeros += byte == 0 ? 1u : 0u;
            ffs += byte == 0xff ? 1u : 0u;
            if (have_prev && byte == prev) ++repeats;
            have_prev = true;
            prev = byte;
            sum += static_cast<long double>(byte);
            sumsq += static_cast<long double>(byte) *
                     static_cast<long double>(byte);
        }
    }

    if (count == 0) {
        out.insert(out.end(), 21, 0.0);
        return;
    }

    const long double denom = static_cast<long double>(count);
    const long double mean = sum / denom;
    const long double variance = std::max(
        0.0L, sumsq / denom - mean * mean);

    for (const auto bin : bins)
        out.push_back(static_cast<double>(static_cast<long double>(bin) / denom));
    out.push_back(static_cast<double>(mean / 255.0L));
    out.push_back(static_cast<double>(std::sqrt(variance) / 255.0L));
    out.push_back(static_cast<double>(static_cast<long double>(zeros) / denom));
    out.push_back(static_cast<double>(static_cast<long double>(ffs) / denom));
    out.push_back(count > 1
        ? static_cast<double>(static_cast<long double>(repeats) /
                              static_cast<long double>(count - 1))
        : 0.0);
}

std::vector<double> byte_features(const RemoteMachineBundle& bundle,
                                  const ByteBlob& wire) {
    std::vector<double> out;
    out.reserve(42);
    append_byte_stats(out, bundle.program_bits);
    append_byte_stats(out, std::vector<ByteBlob>{wire});
    return out;
}

RemoteMachineBundle build_bundle(BinFHEContext& cc,
                                 const LWEPrivateKey& sk,
                                 std::size_t session,
                                 const v0id::polymorph::MorphedProgram& morph) {
    const auto plain_program_bits =
        v0id::integrity::canonical_program_bits(morph.program);
    const auto encrypted_program_bits =
        v0id::integrity::encrypt_plain_bits(cc, sk, plain_program_bits);

    std::vector<int> initial_state(PUBLIC_STATES, 0);
    initial_state.at(morph.initial_state) = 1;
    const auto encrypted_state =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_state);

    std::vector<int> initial_head(PUBLIC_TAPE_CELLS, 0);
    initial_head[0] = 1;
    const auto encrypted_head =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_head);

    const std::vector<int> initial_tape{1, 0, 1, 1, 0, 0, 0, 0};
    const auto encrypted_tape =
        v0id::integrity::encrypt_plain_bits(cc, sk, initial_tape);

    const auto encrypted_nonce = v0id::integrity::encrypt_u32_bits(
        cc, sk, morph.manifest.integrity_nonce);
    const auto encrypted_fingerprint_state = v0id::integrity::encrypt_u32_bits(
        cc, sk, v0id::integrity::TOY_FINGERPRINT_INITIAL_STATE);

    std::vector<EncryptedDigest32> encrypted_masks;
    encrypted_masks.reserve(morph.manifest.integrity_output_masks.size());
    for (const auto mask : morph.manifest.integrity_output_masks)
        encrypted_masks.push_back(
            v0id::integrity::encrypt_u32_bits(cc, sk, mask));

    RemoteMachineBundle bundle;
    bundle.session_id = session_id(session);
    bundle.shape = shape();
    bundle.profile = profile();
    bundle.encrypted_zero = v0id::fhe::serialize_binary(cc.Encrypt(sk, 0));
    bundle.program_bits = serialize_ciphertexts(encrypted_program_bits);
    bundle.state_bits = serialize_ciphertexts(encrypted_state);
    bundle.head_bits = serialize_ciphertexts(encrypted_head);
    bundle.tape_bits = serialize_ciphertexts(encrypted_tape);
    bundle.nonce_bits = serialize_digest(encrypted_nonce);
    bundle.fingerprint_initial_state_bits =
        serialize_digest(encrypted_fingerprint_state);
    bundle.integrity_mask_bits.reserve(encrypted_masks.size());
    for (const auto& digest : encrypted_masks)
        bundle.integrity_mask_bits.push_back(serialize_digest(digest));
    return bundle;
}

enum class FeatureView {
    sizes,
    bytes,
};

const std::vector<double>& features_of(const Sample& sample, FeatureView view) {
    return view == FeatureView::sizes ? sample.size_features : sample.byte_features;
}

struct Standardizer {
    std::vector<double> mean;
    std::vector<double> scale;
};

Standardizer fit_standardizer(const std::vector<Sample>& samples,
                              FeatureView view) {
    Standardizer out;
    std::size_t count = 0;
    for (const auto& sample : samples) {
        if (sample.test) continue;
        const auto& f = features_of(sample, view);
        if (out.mean.empty()) out.mean.assign(f.size(), 0.0);
        if (f.size() != out.mean.size())
            throw std::runtime_error("wire feature width mismatch");
        for (std::size_t i = 0; i < f.size(); ++i) out.mean[i] += f[i];
        ++count;
    }
    if (count == 0) throw std::runtime_error("wire benchmark has no training samples");
    for (auto& x : out.mean) x /= static_cast<double>(count);

    out.scale.assign(out.mean.size(), 0.0);
    for (const auto& sample : samples) {
        if (sample.test) continue;
        const auto& f = features_of(sample, view);
        for (std::size_t i = 0; i < f.size(); ++i) {
            const double d = f[i] - out.mean[i];
            out.scale[i] += d * d;
        }
    }
    for (auto& x : out.scale) {
        x = std::sqrt(x / static_cast<double>(count));
        if (x < 1e-12) x = 1.0;
    }
    return out;
}

std::vector<double> standardized(const std::vector<double>& f,
                                 const Standardizer& s) {
    if (f.size() != s.mean.size())
        throw std::runtime_error("wire standardizer feature width mismatch");
    std::vector<double> out(f.size());
    for (std::size_t i = 0; i < f.size(); ++i)
        out[i] = (f[i] - s.mean[i]) / s.scale[i];
    return out;
}

using Centroids = std::array<std::vector<double>, FAMILY_COUNT>;

Centroids train_centroids(const std::vector<Sample>& samples,
                          FeatureView view,
                          const Standardizer& s) {
    Centroids sums;
    std::array<std::size_t, FAMILY_COUNT> counts{};
    for (const auto& sample : samples) {
        if (sample.test) continue;
        const auto f = standardized(features_of(sample, view), s);
        if (sums[sample.family].empty()) sums[sample.family].assign(f.size(), 0.0);
        for (std::size_t i = 0; i < f.size(); ++i)
            sums[sample.family][i] += f[i];
        ++counts[sample.family];
    }
    for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
        if (counts[family] == 0)
            throw std::runtime_error("wire benchmark has empty training class");
        for (auto& x : sums[family])
            x /= static_cast<double>(counts[family]);
    }
    return sums;
}

std::size_t classify(const std::vector<double>& raw,
                     const Standardizer& s,
                     const Centroids& centroids) {
    const auto f = standardized(raw, s);
    double best = std::numeric_limits<double>::infinity();
    std::size_t best_family = 0;
    for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
        double d2 = 0.0;
        for (std::size_t i = 0; i < f.size(); ++i) {
            const double d = f[i] - centroids[family][i];
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
    std::size_t correct{};
    std::size_t total{};
    double accuracy{};
    long double chance_tail{};
    std::array<std::array<std::size_t, FAMILY_COUNT>, FAMILY_COUNT> confusion{};
};

long double binomial_upper_tail(std::size_t n,
                                std::size_t k,
                                long double p) {
    if (k > n) return 0.0L;
    long double tail = 0.0L;
    for (std::size_t i = k; i <= n; ++i) {
        const long double log_term =
            std::lgamma(static_cast<long double>(n) + 1.0L) -
            std::lgamma(static_cast<long double>(i) + 1.0L) -
            std::lgamma(static_cast<long double>(n - i) + 1.0L) +
            static_cast<long double>(i) * std::log(p) +
            static_cast<long double>(n - i) * std::log(1.0L - p);
        tail += std::exp(log_term);
    }
    return std::min(1.0L, tail);
}

Evaluation evaluate(const std::vector<Sample>& samples, FeatureView view) {
    const auto standardizer = fit_standardizer(samples, view);
    const auto centroids = train_centroids(samples, view, standardizer);
    Evaluation out;

    for (const auto& sample : samples) {
        if (!sample.test) continue;
        const auto predicted = classify(features_of(sample, view),
                                        standardizer, centroids);
        ++out.confusion[sample.family][predicted];
        out.correct += predicted == sample.family ? 1u : 0u;
        ++out.total;
    }
    if (out.total == 0)
        throw std::runtime_error("wire benchmark has no test samples");
    out.accuracy = static_cast<double>(out.correct) /
                   static_cast<double>(out.total);
    out.chance_tail = binomial_upper_tail(
        out.total, out.correct, 1.0L / static_cast<long double>(FAMILY_COUNT));
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

void print_view(const char* title, const Evaluation& result) {
    const bool significant = result.chance_tail < 0.005L;
    std::cout << title << '\n'
              << "  accuracy                : " << std::fixed << std::setprecision(2)
              << result.accuracy * 100.0 << "% (" << result.correct << '/'
              << result.total << ")\n"
              << "  P[X >= observed | p=.25]: " << std::scientific
              << std::setprecision(3) << static_cast<double>(result.chance_tail)
              << std::fixed << '\n';
    print_confusion(result);
    std::cout << (significant ? "  [ALERT] " : "  [PASS] ")
              << (significant
                    ? "classifier signal exceeds the conservative chance threshold\n"
                    : "no statistically strong family signal in this feature view\n");
}

Config parse_args(int argc, char** argv) {
    Config cfg;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + arg);
            return argv[++i];
        };
        if (arg == "--sessions") cfg.sessions = std::stoul(value());
        else if (arg == "--morphs")
            cfg.morphs_per_family_per_session = std::stoul(value());
        else if (arg == "--help") {
            std::cout << "usage: " << argv[0]
                      << " [--sessions N] [--morphs N]\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown argument: " + arg);
        }
    }
    if (cfg.sessions < 4)
        throw std::runtime_error("--sessions must be at least 4");
    if (cfg.morphs_per_family_per_session == 0)
        throw std::runtime_error("--morphs must be positive");
    return cfg;
}

} // namespace

int main(int argc, char** argv) try {
    const Config cfg = parse_args(argc, argv);

    std::array<Program, FAMILY_COUNT> bases{
        make_family(0), make_family(1), make_family(2), make_family(3)};

    BinFHEContext cc;
    cc.GenerateBinFHEContext(STD128Q);

    std::vector<Sample> dataset;
    dataset.reserve(cfg.sessions * cfg.morphs_per_family_per_session *
                    FAMILY_COUNT);

    std::size_t train_sessions = 0;
    std::size_t test_sessions = 0;
    for (std::size_t session = 0; session < cfg.sessions; ++session) {
        const bool test = (session % 4) == 0;
        if (test) ++test_sessions; else ++train_sessions;

        // Fresh LWE secret key for every session. Each key is shared across all
        // four labels inside that session, so key identity cannot become a class
        // label. Test sessions/keys are never present in training.
        const auto sk = cc.KeyGen();

        for (std::size_t morph_index = 0;
             morph_index < cfg.morphs_per_family_per_session;
             ++morph_index) {
            const auto seed = morph_seed(session, morph_index);
            for (std::size_t family = 0; family < FAMILY_COUNT; ++family) {
                const auto morph = ProgramMorpher::morph(
                    bases[family], 0, PUBLIC_STATES, seed,
                    PUBLIC_INTEGRITY_SLOTS);
                const auto bundle = build_bundle(cc, sk, session, morph);
                const auto wire = v0id::fhe::pack_remote_machine_bundle(bundle);

                Sample sample;
                sample.family = family;
                sample.session = session;
                sample.morph = morph_index;
                sample.test = test;
                sample.size_features = size_features(bundle, wire);
                sample.byte_features = byte_features(bundle, wire);
                dataset.push_back(std::move(sample));
            }
        }
    }

    const auto sizes = evaluate(dataset, FeatureView::sizes);
    const auto bytes = evaluate(dataset, FeatureView::bytes);

    std::cout << "V0ID encrypted-wire polymorphism distinguisher\n"
              << "  semantic families       : " << FAMILY_COUNT << '\n'
              << "  public states           : " << PUBLIC_STATES << '\n'
              << "  sessions                : " << cfg.sessions
              << " (train=" << train_sessions << ", test=" << test_sessions << ")\n"
              << "  morphs/family/session   : "
              << cfg.morphs_per_family_per_session << '\n'
              << "  FHE profile             : OpenFHE BinFHE STD128Q\n"
              << "  session keys            : fresh; test keys unseen in training\n"
              << "  morph seeds             : matched across families; test seeds unseen\n"
              << "  classifier              : z-scored nearest class centroid\n"
              << "  random-class baseline   : 25.00%\n"
              << "  alert threshold         : one-sided binomial p < 0.005/view\n\n";

    print_view("[VIEW 1] RMJ3/ciphertext serialized-size features", sizes);
    std::cout << '\n';
    print_view("[VIEW 2] encrypted-program + whole-wire byte statistics", bytes);

    const bool alert = sizes.chance_tail < 0.005L || bytes.chance_tail < 0.005L;
    std::cout << "\nScope: this benchmark uses real randomized BinFHE encryption and the"
                 " actual RMJ3 packer.\n"
              << "It measures passive serialized-wire distinguishability only. It does"
                 " NOT yet measure\n"
              << "wall-clock evaluator timing, per-gate/bootstrap traces, transport"
                 " packetization, or active cheating.\n";

    if (alert) {
        std::cout << "V0ID encrypted-wire distinguisher: ALERT\n"
                  << "At least one passive wire feature view carries statistically"
                     " strong family signal.\n";
        return 1;
    }

    std::cout << "V0ID encrypted-wire distinguisher: NO STRONG SIGNAL\n"
              << "This is empirical evidence for these features/samples, not a proof"
                 " of indistinguishability.\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "V0ID encrypted-wire distinguisher fatal error: "
              << e.what() << '\n';
    return 2;
}
