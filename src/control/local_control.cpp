#include "local_control.hpp"

#include "module_sync.hpp"
#include "series_first_stack.hpp"
#include "series_generator.hpp"

#ifdef V0ID_CONTROL_HAVE_MATHVM
#include "mathvm.hpp"
#include "wamr_sandbox.hpp"
#include "wasm_series_generator.hpp"
#endif

#include <nlohmann/json.hpp>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace v0id::control {
namespace {

using json = nlohmann::json;
using v0id::crypto::SeriesFirstStackContext;
using v0id::crypto::StackPurpose;
using v0id::net::ModuleDescriptor;
using v0id::net::ModuleDigest512;
using v0id::net::ModuleKind;
using v0id::net::ModuleVisibility;
using v0id::polymorph::DerivedSeries;
using v0id::polymorph::KmacSeriesGenerator;
using v0id::polymorph::SeriesProfile;
using v0id::polymorph::SeriesSeed;

constexpr std::size_t MAX_MODULE_BYTES = 1024 * 1024;
constexpr std::size_t MAX_CONTROL_INPUT_BYTES = 256 * 1024;
constexpr std::size_t MAX_CONTROL_SERIES_BYTES = 1024 * 1024;
constexpr std::size_t MAX_COMMAND_BYTES = 1024 * 1024;
constexpr auto POLL_INTERVAL = std::chrono::milliseconds(200);

struct PrimitiveRequirementRecord {
    std::uint64_t tag{};
    std::string id;
    std::uint32_t version{};
};

struct ModuleRecord {
    ModuleDescriptor descriptor;
    std::string storage_file;
    std::string entrypoint{"v0id_main"};
    std::vector<PrimitiveRequirementRecord> required_primitives;
};

std::uint64_t unix_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return value;
}

ModuleKind parse_module_kind(std::string value) {
    value = uppercase(std::move(value));
    if (value == "STRATEGY_WASM") return ModuleKind::strategy_wasm;
    if (value == "MATHVM_WASM") return ModuleKind::mathvm_wasm;
    if (value == "POLYMORPHISM_WASM") return ModuleKind::polymorphism_wasm;
    if (value == "NEURAL_WASM") return ModuleKind::neural_wasm;
    throw std::runtime_error("unknown control-plane module kind");
}

ModuleVisibility parse_module_visibility(std::string value) {
    value = uppercase(std::move(value));
    if (value == "PRIVATE_LOCAL") return ModuleVisibility::private_local;
    if (value == "SHARED_SYNC") return ModuleVisibility::shared_sync;
    throw std::runtime_error("unknown control-plane module visibility");
}

std::string module_key(const ModuleDescriptor& descriptor) {
    return v0id::net::to_string(descriptor.kind) + ":" + descriptor.module_id +
           ":v" + std::to_string(descriptor.module_version);
}

bool safe_staging_name(const std::string& name) {
    if (name.empty() || name.size() > 160 || name == "." || name == "..")
        return false;
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '.' || c == '_' || c == '-';
    });
}

std::vector<std::uint8_t> read_binary(const std::filesystem::path& path,
                                      std::size_t max_bytes,
                                      const char* what) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in)
        throw std::runtime_error(std::string("cannot open ") + what + ": " + path.string());
    const auto end = in.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > max_bytes)
        throw std::runtime_error(std::string(what) + " size outside control-plane limit");
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(end));
    in.seekg(0, std::ios::beg);
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in)
        throw std::runtime_error(std::string("failed reading ") + what);
    return bytes;
}

std::string read_text(const std::filesystem::path& path, std::size_t max_bytes) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in)
        throw std::runtime_error("cannot open local control JSON: " + path.string());
    const auto end = in.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > max_bytes)
        throw std::runtime_error("local control JSON exceeds size limit");
    std::string text(static_cast<std::size_t>(end), '\0');
    in.seekg(0, std::ios::beg);
    if (!text.empty()) in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (!in && !text.empty())
        throw std::runtime_error("failed reading local control JSON");
    return text;
}

void write_binary_if_missing(const std::filesystem::path& path,
                             const std::vector<std::uint8_t>& bytes) {
    if (std::filesystem::exists(path)) return;
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create verified module file");
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!out) throw std::runtime_error("failed writing verified module file");
    }
    std::filesystem::rename(tmp, path);
}

void atomic_write_json(const std::filesystem::path& path, const json& value) {
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create local control JSON temp file");
        out << value.dump(2) << '\n';
        if (!out) throw std::runtime_error("failed writing local control JSON");
    }
    std::filesystem::rename(tmp, path);
}

std::vector<std::uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> from_hex(std::string_view text,
                                   std::size_t max_bytes,
                                   const char* what) {
    if ((text.size() & 1u) != 0)
        throw std::runtime_error(std::string(what) + " must contain an even number of hex digits");
    if (text.size() / 2 > max_bytes)
        throw std::runtime_error(std::string(what) + " exceeds control-plane limit");
    std::vector<std::uint8_t> out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = hex_nibble(text[2 * i]);
        const int lo = hex_nibble(text[2 * i + 1]);
        if (hi < 0 || lo < 0)
            throw std::runtime_error(std::string(what) + " contains non-hex characters");
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

template <typename It>
std::string to_hex(It begin, It end) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (auto it = begin; it != end; ++it)
        out << std::setw(2) << static_cast<unsigned>(*it);
    return out.str();
}

template <typename Container>
std::string to_hex(const Container& value) {
    return to_hex(value.begin(), value.end());
}

std::array<std::uint8_t, 32> random_session_id() {
    std::array<std::uint8_t, 32> id{};
    do {
        if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1)
            throw std::runtime_error("RAND_bytes failed for local Series-First session id");
    } while (std::all_of(id.begin(), id.end(), [](auto b) { return b == 0; }));
    return id;
}

ModuleDigest512 sha3_512(const std::vector<std::uint8_t>& bytes) {
    return v0id::net::module_digest512(bytes);
}

json digest_json(const ModuleDigest512& digest) {
    return to_hex(digest);
}

json profile_json(const SeriesProfile& profile) {
    return json{
        {"generator_id", profile.generator_id},
        {"version", profile.version},
        {"parameters_hex", to_hex(profile.parameters)},
    };
}

ModuleDigest512 profile_binding(const SeriesProfile& profile) {
    // This local administrative adapter needs a stable commitment for the
    // SeriesFirstStackContext::generator_binding field. The protocol field itself
    // intentionally does not prescribe how a generator profile is represented.
    const auto canonical = profile_json(profile).dump();
    return sha3_512(bytes_of(canonical));
}

json primitive_requirements_json(
    const std::vector<PrimitiveRequirementRecord>& requirements) {
    json out = json::array();
    for (const auto& requirement : requirements) {
        out.push_back({
            {"tag", requirement.tag},
            {"id", requirement.id},
            {"version", requirement.version},
        });
    }
    return out;
}

std::vector<PrimitiveRequirementRecord> parse_primitive_requirements(const json& value) {
    std::vector<PrimitiveRequirementRecord> out;
    if (value.is_null()) return out;
    if (!value.is_array())
        throw std::runtime_error("required_primitives must be a JSON array");
    if (value.size() > 128)
        throw std::runtime_error("too many MathVM primitive requirements");
    for (const auto& item : value) {
        PrimitiveRequirementRecord requirement;
        requirement.tag = item.at("tag").get<std::uint64_t>();
        requirement.id = item.at("id").get<std::string>();
        requirement.version = item.at("version").get<std::uint32_t>();
        if (requirement.tag == 0 || requirement.id.empty() || requirement.version == 0)
            throw std::runtime_error("invalid MathVM primitive requirement");
        out.push_back(std::move(requirement));
    }
    return out;
}

json module_record_json(const ModuleRecord& record) {
    return json{
        {"key", module_key(record.descriptor)},
        {"kind", v0id::net::to_string(record.descriptor.kind)},
        {"visibility", v0id::net::to_string(record.descriptor.visibility)},
        {"module_id", record.descriptor.module_id},
        {"module_version", record.descriptor.module_version},
        {"byte_size", record.descriptor.byte_size},
        {"digest_sha3_512", v0id::net::module_digest_hex(record.descriptor.digest)},
        {"storage_file", record.storage_file},
        {"entrypoint", record.entrypoint},
        {"required_primitives", primitive_requirements_json(record.required_primitives)},
    };
}

StackPurpose parse_stack_purpose(const std::string& value) {
    if (value == "machine-layout") return StackPurpose::machine_layout;
    if (value == "polymorphism") return StackPurpose::polymorphism;
    if (value == "quine-challenge") return StackPurpose::quine_challenge;
    if (value == "strategy-plugin") return StackPurpose::strategy_plugin;
    if (value == "execution-integrity") return StackPurpose::execution_integrity;
    if (value == "application-auth") return StackPurpose::application_auth;
    if (value == "job-receipt") return StackPurpose::job_receipt;
    throw std::runtime_error("unknown Series-First stack purpose");
}

bool all_zero(const ModuleDigest512& digest) {
    return std::all_of(digest.begin(), digest.end(), [](auto b) { return b == 0; });
}

} // namespace

struct LocalControlPlane::Impl {
    explicit Impl(std::filesystem::path root)
        : root_(std::move(root)) {}

    std::filesystem::path root_;
    std::filesystem::path commands_dir_;
    std::filesystem::path processing_dir_;
    std::filesystem::path responses_dir_;
    std::filesystem::path uploads_dir_;
    std::filesystem::path modules_dir_;
    std::filesystem::path state_path_;
    std::filesystem::path registry_path_;

    std::map<std::string, ModuleRecord> modules_;
    std::map<std::string, std::string> bindings_;
    std::string series_mode_{"kmacxof256"};
    std::size_t series_bytes_{64};
    SeriesSeed private_root_{};

    json computation_ = {
        {"job_id", ""},
        {"type", ""},
        {"state", "idle"},
        {"stage", "idle"},
        {"current", 0},
        {"total", 0},
        {"percent", 0.0},
        {"message", ""},
        {"started_unix_ms", 0},
        {"updated_unix_ms", 0},
        {"result", json::object()},
    };

    std::uint64_t revision_{};
    std::string last_error_;
    json last_command_ = json::object();
    std::atomic_bool stop_requested_{false};
    bool initialized_{};

    void ensure_initialized() const {
        if (!initialized_)
            throw std::runtime_error("local control plane is not initialized");
    }

    ModuleRecord& require_module(const std::string& key) {
        const auto it = modules_.find(key);
        if (it == modules_.end())
            throw std::runtime_error("unknown local module key: " + key);
        return it->second;
    }

    const ModuleRecord& require_module(const std::string& key) const {
        const auto it = modules_.find(key);
        if (it == modules_.end())
            throw std::runtime_error("unknown local module key: " + key);
        return it->second;
    }

    std::vector<std::uint8_t> module_bytes(const ModuleRecord& record) const {
        if (!safe_staging_name(record.storage_file))
            throw std::runtime_error("invalid persisted module storage filename");
        auto bytes = read_binary(modules_dir_ / record.storage_file,
                                 MAX_MODULE_BYTES, "verified module");
        const auto descriptor = v0id::net::describe_module(
            record.descriptor.kind,
            record.descriptor.visibility,
            record.descriptor.module_id,
            record.descriptor.module_version,
            bytes);
        if (descriptor.digest != record.descriptor.digest ||
            descriptor.byte_size != record.descriptor.byte_size)
            throw std::runtime_error("persisted module bytes no longer match descriptor");
        return bytes;
    }

    SeriesProfile selected_series_profile() const {
        if (series_mode_ == "kmacxof256") {
            return KmacSeriesGenerator(series_bytes_).profile();
        }
        if (series_mode_ == "module") {
            const auto binding = bindings_.find("series_generator");
            if (binding == bindings_.end())
                throw std::runtime_error("Series-First module mode requires series_generator binding");
            const auto& record = require_module(binding->second);
            if (record.descriptor.kind != ModuleKind::polymorphism_wasm)
                throw std::runtime_error("series_generator binding is not POLYMORPHISM_WASM");
            if (record.descriptor.module_version > std::numeric_limits<std::uint32_t>::max())
                throw std::runtime_error("polymorphism module version exceeds SeriesProfile width");
            SeriesProfile profile;
            profile.generator_id = "v0id-wasm-module:" + record.descriptor.module_id;
            profile.version = static_cast<std::uint32_t>(record.descriptor.module_version);
            profile.parameters.assign(record.descriptor.digest.begin(),
                                      record.descriptor.digest.end());
            return profile;
        }
        throw std::runtime_error("unknown configured Series-First generator mode");
    }

    std::vector<ModuleDescriptor> shared_bound_descriptors() const {
        std::set<std::string> seen;
        std::vector<ModuleDescriptor> out;
        for (const auto& [slot, key] : bindings_) {
            (void)slot;
            if (!seen.insert(key).second) continue;
            const auto& record = require_module(key);
            if (record.descriptor.visibility == ModuleVisibility::shared_sync)
                out.push_back(record.descriptor);
        }
        return out;
    }

    json state_json() const {
        json module_list = json::array();
        for (const auto& [key, record] : modules_) {
            (void)key;
            module_list.push_back(module_record_json(record));
        }

        json bindings = json::object();
        for (const auto& [slot, key] : bindings_) bindings[slot] = key;

        json capabilities = {
            {"series_generator_kmacxof256", true},
            {"series_first_stack", true},
#ifdef V0ID_CONTROL_HAVE_MATHVM
            {"polymorphism_wasm", true},
            {"mathvm_wasm", true},
#else
            {"polymorphism_wasm", false},
            {"mathvm_wasm", false},
#endif
            {"tfhe_cloud_job_submission", false},
        };

        json generator;
        try {
            generator = profile_json(selected_series_profile());
        } catch (const std::exception& e) {
            generator = {{"error", e.what()}};
        }

        return json{
            {"protocol", "v0id-local-control-v1"},
            {"revision", revision_},
            {"updated_unix_ms", unix_ms()},
            {"runtime_root", root_.string()},
            {"capabilities", std::move(capabilities)},
            {"series_first", {
                {"mode", series_mode_},
                {"series_bytes", series_bytes_},
                {"selected_profile", std::move(generator)},
                {"private_root", "process-local / C++ only / not serialized"},
            }},
            {"bindings", std::move(bindings)},
            {"modules", std::move(module_list)},
            {"computation", computation_},
            {"last_command", last_command_},
            {"last_error", last_error_},
        };
    }

    void publish_state() {
        ++revision_;
        atomic_write_json(state_path_, state_json());
    }

    json registry_json() const {
        json module_list = json::array();
        for (const auto& [key, record] : modules_) {
            (void)key;
            module_list.push_back(module_record_json(record));
        }
        json bindings = json::object();
        for (const auto& [slot, key] : bindings_) bindings[slot] = key;
        return json{
            {"protocol", "v0id-local-control-registry-v1"},
            {"series_mode", series_mode_},
            {"series_bytes", series_bytes_},
            {"bindings", std::move(bindings)},
            {"modules", std::move(module_list)},
        };
    }

    void persist_registry() const {
        atomic_write_json(registry_path_, registry_json());
    }

    void load_registry() {
        if (!std::filesystem::exists(registry_path_)) return;
        const auto registry = json::parse(read_text(registry_path_, MAX_COMMAND_BYTES));
        if (registry.value("protocol", std::string{}) != "v0id-local-control-registry-v1")
            throw std::runtime_error("unsupported local control registry protocol");

        series_mode_ = registry.value("series_mode", std::string("kmacxof256"));
        series_bytes_ = registry.value("series_bytes", std::size_t{64});
        if (series_bytes_ == 0 || series_bytes_ > MAX_CONTROL_SERIES_BYTES)
            throw std::runtime_error("persisted Series-First length outside limit");

        modules_.clear();
        for (const auto& item : registry.value("modules", json::array())) {
            const auto kind = parse_module_kind(item.at("kind").get<std::string>());
            const auto visibility =
                parse_module_visibility(item.at("visibility").get<std::string>());
            const auto id = item.at("module_id").get<std::string>();
            const auto version = item.at("module_version").get<std::uint64_t>();
            const auto storage_file = item.at("storage_file").get<std::string>();
            if (!safe_staging_name(storage_file))
                throw std::runtime_error("unsafe module storage filename in registry");
            const auto bytes = read_binary(modules_dir_ / storage_file,
                                           MAX_MODULE_BYTES, "registry module");
            ModuleRecord record;
            record.descriptor = v0id::net::describe_module(
                kind, visibility, id, version, bytes);
            record.storage_file = storage_file;
            record.entrypoint = item.value("entrypoint", std::string("v0id_main"));
            record.required_primitives = parse_primitive_requirements(
                item.value("required_primitives", json::array()));
            if (v0id::net::module_digest_hex(record.descriptor.digest) !=
                item.at("digest_sha3_512").get<std::string>())
                throw std::runtime_error("module registry digest does not match stored bytes");
            modules_.emplace(module_key(record.descriptor), std::move(record));
        }

        bindings_.clear();
        if (registry.contains("bindings")) {
            for (auto it = registry["bindings"].begin();
                 it != registry["bindings"].end(); ++it) {
                const auto key = it.value().get<std::string>();
                (void)require_module(key);
                bindings_[it.key()] = key;
            }
        }
    }

    void initialize() {
        if (initialized_) return;
        if (root_.empty())
            throw std::runtime_error("local control runtime root must not be empty");

        commands_dir_ = root_ / "commands";
        processing_dir_ = root_ / "processing";
        responses_dir_ = root_ / "responses";
        uploads_dir_ = root_ / "uploads";
        modules_dir_ = root_ / "modules";
        state_path_ = root_ / "state.json";
        registry_path_ = root_ / "registry.json";

        std::filesystem::create_directories(commands_dir_);
        std::filesystem::create_directories(processing_dir_);
        std::filesystem::create_directories(responses_dir_);
        std::filesystem::create_directories(uploads_dir_);
        std::filesystem::create_directories(modules_dir_);

        private_root_ = v0id::polymorph::random_series_seed();
        load_registry();
        persist_registry();
        initialized_ = true;
        publish_state();
    }

    void set_progress(const std::string& stage,
                      std::uint64_t current,
                      std::uint64_t total,
                      const std::string& message) {
        computation_["stage"] = stage;
        computation_["current"] = current;
        computation_["total"] = total;
        computation_["percent"] = total == 0
            ? 0.0
            : (100.0 * static_cast<double>(std::min(current, total)) /
               static_cast<double>(total));
        computation_["message"] = message;
        computation_["updated_unix_ms"] = unix_ms();
        publish_state();
    }

    void begin_computation(const std::string& command_id, const std::string& type) {
        computation_ = {
            {"job_id", command_id},
            {"type", type},
            {"state", "running"},
            {"stage", "queued"},
            {"current", 0},
            {"total", 1},
            {"percent", 0.0},
            {"message", "queued by local JSON control plane"},
            {"started_unix_ms", unix_ms()},
            {"updated_unix_ms", unix_ms()},
            {"result", json::object()},
        };
        last_error_.clear();
        publish_state();
    }

    void complete_computation(json result) {
        computation_["state"] = "completed";
        computation_["stage"] = "completed";
        computation_["current"] = 1;
        computation_["total"] = 1;
        computation_["percent"] = 100.0;
        computation_["message"] = "computation completed";
        computation_["updated_unix_ms"] = unix_ms();
        computation_["result"] = std::move(result);
        publish_state();
    }

    void fail_computation(const std::string& error) {
        computation_["state"] = "failed";
        computation_["stage"] = "failed";
        computation_["message"] = error;
        computation_["updated_unix_ms"] = unix_ms();
        last_error_ = error;
        publish_state();
    }

    json run_series_generator(const json& payload) {
        const auto epoch = payload.value("epoch", std::uint64_t{0});
        const auto input_hex = payload.value("input_hex", std::string{});
        const auto input = from_hex(input_hex, MAX_CONTROL_INPUT_BYTES, "Series-First input");

        set_progress("prepare", 1, 4, "validated Series-First input and selected profile");
        const auto profile = selected_series_profile();
        DerivedSeries derived;

        set_progress("derive", 2, 4, "deriving private polymorphic series");
        if (series_mode_ == "kmacxof256") {
            KmacSeriesGenerator generator(series_bytes_);
            derived = generator.derive(input, private_root_, epoch);
        } else if (series_mode_ == "module") {
#ifdef V0ID_CONTROL_HAVE_MATHVM
            const auto binding = bindings_.find("series_generator");
            if (binding == bindings_.end())
                throw std::runtime_error("no POLYMORPHISM_WASM module is bound");
            const auto& record = require_module(binding->second);
            auto bytes = module_bytes(record);
            v0id::polymorph::WasmSeriesGenerator generator(
                std::move(bytes), profile);
            derived = generator.derive(input, private_root_, epoch);
#else
            throw std::runtime_error(
                "this build has no WAMR polymorphism-module support");
#endif
        } else {
            throw std::runtime_error("unknown configured Series-First generator mode");
        }

        set_progress("commit", 3, 4,
                     "committing result metadata without exporting private series bytes");
        const auto series_digest = sha3_512(derived.series);
        const std::vector<std::uint8_t> morph_seed(
            derived.morph_seed.begin(), derived.morph_seed.end());
        const auto morph_digest = sha3_512(morph_seed);
        const auto manifest_digest = sha3_512(derived.private_manifest);

        set_progress("finalize", 4, 4, "Series-First metadata ready");
        return json{
            {"type", "series_generator"},
            {"epoch", epoch},
            {"input_bytes", input.size()},
            {"profile", profile_json(profile)},
            {"series_bytes", derived.series.size()},
            {"series_digest_sha3_512", digest_json(series_digest)},
            {"morph_seed_digest_sha3_512", digest_json(morph_digest)},
            {"private_manifest_bytes", derived.private_manifest.size()},
            {"private_manifest_digest_sha3_512", digest_json(manifest_digest)},
            {"private_material_exported", false},
        };
    }

    json run_series_first_stack(const json& payload,
                                const std::string& command_id) {
        set_progress("context", 1, 5, "building canonical Series-First stack context");

        SeriesFirstStackContext context;
        if (payload.contains("session_id_hex") &&
            !payload.at("session_id_hex").get<std::string>().empty()) {
            const auto bytes = from_hex(payload.at("session_id_hex").get<std::string>(),
                                        context.session_id.size(), "session_id_hex");
            if (bytes.size() != context.session_id.size())
                throw std::runtime_error("Series-First session id must be exactly 32 bytes");
            std::copy(bytes.begin(), bytes.end(), context.session_id.begin());
        } else {
            context.session_id = random_session_id();
        }

        context.job_id = payload.value("job_id", command_id);
        context.epoch = payload.value("epoch", std::uint64_t{0});
        context.machine_protocol =
            payload.value("machine_protocol", std::string("v0id-local-control-v1"));
        context.fhe_parameter_set =
            payload.value("fhe_parameter_set", std::string("LOCAL-CONTROL"));

        if (payload.contains("semantic_binding_hex") &&
            !payload.at("semantic_binding_hex").get<std::string>().empty()) {
            const auto bytes = from_hex(
                payload.at("semantic_binding_hex").get<std::string>(),
                context.semantic_binding.size(), "semantic_binding_hex");
            if (bytes.size() != context.semantic_binding.size())
                throw std::runtime_error("semantic binding must be exactly 64 bytes");
            std::copy(bytes.begin(), bytes.end(), context.semantic_binding.begin());
        } else {
            const auto semantic_text =
                payload.value("semantic_text", std::string("local-control-computation"));
            context.semantic_binding = sha3_512(bytes_of(semantic_text));
        }

        const auto profile = selected_series_profile();
        context.generator_binding = profile_binding(profile);
        const auto shared_descriptors = shared_bound_descriptors();
        if (!shared_descriptors.empty()) {
            context.shared_modules_binding =
                v0id::net::shared_module_set_digest512(shared_descriptors);
        }

        const auto purpose_text =
            payload.value("purpose", std::string("execution-integrity"));
        const auto purpose = parse_stack_purpose(purpose_text);

        set_progress("purpose-series", 2, 5,
                     "deriving purpose-specific private stack series");
        const auto context_hash = v0id::crypto::hash_series_first_stack_context(context);
        const auto purpose_series = v0id::crypto::derive_private_stack_series(
            private_root_, context_hash, purpose);

        const auto algorithm_id =
            payload.value("algorithm_id", std::string("v0id-local-preview"));
        const auto algorithm_version =
            payload.value("algorithm_version", std::uint64_t{1});
        const auto output_bytes = payload.value("output_bytes", std::size_t{64});
        if (output_bytes == 0 || output_bytes > MAX_CONTROL_SERIES_BYTES)
            throw std::runtime_error("Series-First algorithm output length outside limit");
        const auto algorithm_context = from_hex(
            payload.value("algorithm_context_hex", std::string{}),
            MAX_CONTROL_INPUT_BYTES, "algorithm_context_hex");

        set_progress("algorithm-later", 3, 5,
                     "expanding selected algorithm only after purpose series exists");
        const auto output = v0id::crypto::expand_stack_algorithm_later(
            purpose_series, algorithm_id, algorithm_version,
            algorithm_context, output_bytes);

        set_progress("commit", 4, 5,
                     "committing derived output and module bindings");
        const auto output_digest = sha3_512(output);
        json shared_binding = nullptr;
        if (!all_zero(context.shared_modules_binding))
            shared_binding = to_hex(context.shared_modules_binding);

        set_progress("finalize", 5, 5, "Series-First stack result metadata ready");
        return json{
            {"type", "series_first_stack"},
            {"session_id_hex", to_hex(context.session_id)},
            {"job_id", context.job_id},
            {"epoch", context.epoch},
            {"purpose", v0id::crypto::stack_purpose_name(purpose)},
            {"machine_protocol", context.machine_protocol},
            {"fhe_parameter_set", context.fhe_parameter_set},
            {"generator_profile", profile_json(profile)},
            {"context_digest_sha3_512", to_hex(context_hash)},
            {"shared_modules_binding_sha3_512", std::move(shared_binding)},
            {"algorithm_id", algorithm_id},
            {"algorithm_version", algorithm_version},
            {"output_bytes", output.size()},
            {"output_digest_sha3_512", digest_json(output_digest)},
            {"private_material_exported", false},
        };
    }

    json run_mathvm(const json& payload) {
#ifdef V0ID_CONTROL_HAVE_MATHVM
        std::string key;
        if (payload.contains("module_key") &&
            !payload.at("module_key").get<std::string>().empty()) {
            key = payload.at("module_key").get<std::string>();
        } else {
            const auto binding = bindings_.find("mathvm");
            if (binding == bindings_.end())
                throw std::runtime_error("no MATHVM_WASM module is bound");
            key = binding->second;
        }

        const auto& record = require_module(key);
        if (record.descriptor.kind != ModuleKind::mathvm_wasm)
            throw std::runtime_error("selected module is not MATHVM_WASM");

        set_progress("prepare", 1, 3, "loading verified MathVM module and primitive manifest");
        v0id::mathvm::WasmMathProgram program;
        program.wasm = module_bytes(record);
        program.entrypoint = record.entrypoint;
        for (const auto& requirement : record.required_primitives) {
            program.required_primitives.push_back({
                requirement.tag, requirement.id, requirement.version});
        }

        auto registry = v0id::mathvm::make_default_registry();
        v0id::mathvm::WamrMathSandbox sandbox;
        set_progress("execute", 2, 3, "executing bounded local MathVM module");
        const auto report = sandbox.execute(program, registry);
        set_progress("finalize", 3, 3, "MathVM execution report ready");

        return json{
            {"type", "mathvm"},
            {"module_key", key},
            {"module_digest_sha3_512",
             v0id::net::module_digest_hex(record.descriptor.digest)},
            {"entrypoint", record.entrypoint},
            {"result_u64", report.result},
            {"provider_calls", report.provider_calls},
            {"provider_cost", report.provider_cost},
        };
#else
        (void)payload;
        throw std::runtime_error("this build has no MathVM/WAMR support");
#endif
    }

    json run_computation(const json& payload, const std::string& command_id) {
        const auto type = payload.at("type").get<std::string>();
        begin_computation(command_id, type);
        try {
            json result;
            if (type == "series_generator") {
                result = run_series_generator(payload);
            } else if (type == "series_first_stack") {
                result = run_series_first_stack(payload, command_id);
            } else if (type == "mathvm") {
                result = run_mathvm(payload);
            } else {
                throw std::runtime_error("unsupported local computation type: " + type);
            }
            complete_computation(result);
            return result;
        } catch (const std::exception& e) {
            fail_computation(e.what());
            throw;
        }
    }

    void register_module(const json& payload) {
        const auto upload_name = payload.at("upload_name").get<std::string>();
        if (!safe_staging_name(upload_name))
            throw std::runtime_error("unsafe module upload name");
        const auto upload_path = uploads_dir_ / upload_name;
        auto bytes = read_binary(upload_path, MAX_MODULE_BYTES, "module upload");

        const auto kind = parse_module_kind(payload.at("kind").get<std::string>());
        const auto visibility =
            parse_module_visibility(payload.at("visibility").get<std::string>());
        const auto id = payload.at("module_id").get<std::string>();
        const auto version = payload.at("module_version").get<std::uint64_t>();
        auto descriptor = v0id::net::describe_module(kind, visibility, id, version, bytes);
        const auto key = module_key(descriptor);

        const auto existing = modules_.find(key);
        if (existing != modules_.end() && existing->second.descriptor.digest != descriptor.digest) {
            throw std::runtime_error(
                "module kind/id/version already exists with different bytes; bump module_version");
        }

        ModuleRecord record;
        record.descriptor = descriptor;
        record.storage_file = v0id::net::module_digest_hex(descriptor.digest) + ".wasm";
        record.entrypoint = payload.value("entrypoint", std::string("v0id_main"));
        if (record.entrypoint.empty() || record.entrypoint.size() > 128)
            throw std::runtime_error("module entrypoint length outside limit");
        record.required_primitives = parse_primitive_requirements(
            payload.value("required_primitives", json::array()));

        write_binary_if_missing(modules_dir_ / record.storage_file, bytes);
        modules_[key] = std::move(record);
        persist_registry();
        std::error_code ignored;
        std::filesystem::remove(upload_path, ignored);
    }

    void update_module_config(const json& payload) {
        const auto key = payload.at("module_key").get<std::string>();
        auto& record = require_module(key);
        if (payload.contains("entrypoint")) {
            const auto entrypoint = payload.at("entrypoint").get<std::string>();
            if (entrypoint.empty() || entrypoint.size() > 128)
                throw std::runtime_error("module entrypoint length outside limit");
            record.entrypoint = entrypoint;
        }
        if (payload.contains("required_primitives")) {
            record.required_primitives =
                parse_primitive_requirements(payload.at("required_primitives"));
        }
        persist_registry();
    }

    void remove_module(const json& payload) {
        const auto key = payload.at("module_key").get<std::string>();
        for (const auto& [slot, bound] : bindings_) {
            if (bound == key)
                throw std::runtime_error("cannot remove module while bound to slot: " + slot);
        }
        const auto it = modules_.find(key);
        if (it == modules_.end())
            throw std::runtime_error("unknown local module key: " + key);
        const auto storage_file = it->second.storage_file;
        modules_.erase(it);

        bool still_referenced = false;
        for (const auto& [other_key, record] : modules_) {
            (void)other_key;
            if (record.storage_file == storage_file) {
                still_referenced = true;
                break;
            }
        }
        if (!still_referenced) {
            std::error_code ignored;
            std::filesystem::remove(modules_dir_ / storage_file, ignored);
        }
        persist_registry();
    }

    static ModuleKind required_kind_for_slot(const std::string& slot) {
        if (slot == "series_generator") return ModuleKind::polymorphism_wasm;
        if (slot == "mathvm") return ModuleKind::mathvm_wasm;
        if (slot == "strategy") return ModuleKind::strategy_wasm;
        if (slot == "neural") return ModuleKind::neural_wasm;
        throw std::runtime_error("unknown local module binding slot");
    }

    void bind_module(const json& payload) {
        const auto slot = payload.at("slot").get<std::string>();
        const auto key = payload.at("module_key").get<std::string>();
        const auto& record = require_module(key);
        if (record.descriptor.kind != required_kind_for_slot(slot))
            throw std::runtime_error("module kind does not match requested binding slot");
        bindings_[slot] = key;
        persist_registry();
    }

    void unbind_module(const json& payload) {
        const auto slot = payload.at("slot").get<std::string>();
        (void)required_kind_for_slot(slot);
        bindings_.erase(slot);
        if (slot == "series_generator" && series_mode_ == "module")
            series_mode_ = "kmacxof256";
        persist_registry();
    }

    void configure_series(const json& payload) {
        const auto mode = payload.at("mode").get<std::string>();
        const auto bytes = payload.value("series_bytes", series_bytes_);
        if (bytes == 0 || bytes > MAX_CONTROL_SERIES_BYTES)
            throw std::runtime_error("configured Series-First length outside limit");
        if (mode != "kmacxof256" && mode != "module")
            throw std::runtime_error("Series-First mode must be kmacxof256 or module");
        if (mode == "module") {
            const auto binding = bindings_.find("series_generator");
            if (binding == bindings_.end())
                throw std::runtime_error("bind a POLYMORPHISM_WASM module before selecting module mode");
            if (require_module(binding->second).descriptor.kind != ModuleKind::polymorphism_wasm)
                throw std::runtime_error("invalid series_generator binding");
        }
        series_mode_ = mode;
        series_bytes_ = bytes;
        persist_registry();
    }

    json handle_command(const json& command) {
        if (command.value("protocol", std::string{}) != "v0id-local-control-v1")
            throw std::runtime_error("unsupported local control command protocol");
        const auto command_id = command.at("command_id").get<std::string>();
        if (command_id.empty() || command_id.size() > 128)
            throw std::runtime_error("invalid local control command id");
        const auto action = command.at("command").get<std::string>();
        const auto payload = command.value("payload", json::object());

        if (action == "register_module") {
            register_module(payload);
        } else if (action == "update_module_config") {
            update_module_config(payload);
        } else if (action == "remove_module") {
            remove_module(payload);
        } else if (action == "bind_module") {
            bind_module(payload);
        } else if (action == "unbind_module") {
            unbind_module(payload);
        } else if (action == "configure_series") {
            configure_series(payload);
        } else if (action == "run_computation") {
            return run_computation(payload, command_id);
        } else if (action == "shutdown") {
            stop_requested_.store(true);
        } else {
            throw std::runtime_error("unknown local control command: " + action);
        }

        publish_state();
        return json{{"applied", true}};
    }

    void write_response(const std::string& command_id,
                        bool ok,
                        const json& result,
                        const std::string& error) {
        json response{
            {"protocol", "v0id-local-control-response-v1"},
            {"command_id", command_id},
            {"ok", ok},
            {"completed_unix_ms", unix_ms()},
        };
        if (ok) response["result"] = result;
        else response["error"] = error;
        atomic_write_json(responses_dir_ / (command_id + ".json"), response);
    }

    bool process_one() {
        ensure_initialized();
        std::vector<std::filesystem::path> queued;
        for (const auto& entry : std::filesystem::directory_iterator(commands_dir_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json")
                queued.push_back(entry.path());
        }
        if (queued.empty()) return false;
        std::sort(queued.begin(), queued.end());

        const auto source = queued.front();
        const auto processing = processing_dir_ / source.filename();
        std::filesystem::rename(source, processing);

        std::string command_id = source.stem().string();
        try {
            const auto command = json::parse(read_text(processing, MAX_COMMAND_BYTES));
            if (command.contains("command_id"))
                command_id = command.at("command_id").get<std::string>();
            const auto result = handle_command(command);
            last_command_ = {
                {"command_id", command_id},
                {"command", command.value("command", std::string{})},
                {"ok", true},
                {"completed_unix_ms", unix_ms()},
            };
            last_error_.clear();
            write_response(command_id, true, result, {});
        } catch (const std::exception& e) {
            last_command_ = {
                {"command_id", command_id},
                {"ok", false},
                {"completed_unix_ms", unix_ms()},
            };
            last_error_ = e.what();
            write_response(command_id, false, json::object(), e.what());
        }

        std::error_code ignored;
        std::filesystem::remove(processing, ignored);
        publish_state();
        return true;
    }
};

LocalControlPlane::LocalControlPlane(std::filesystem::path runtime_root)
    : impl_(std::make_unique<Impl>(std::move(runtime_root))) {}

LocalControlPlane::~LocalControlPlane() = default;
LocalControlPlane::LocalControlPlane(LocalControlPlane&&) noexcept = default;
LocalControlPlane& LocalControlPlane::operator=(LocalControlPlane&&) noexcept = default;

void LocalControlPlane::initialize() {
    impl_->initialize();
}

bool LocalControlPlane::process_one() {
    return impl_->process_one();
}

void LocalControlPlane::run_forever() {
    impl_->ensure_initialized();
    while (!impl_->stop_requested_.load()) {
        if (!impl_->process_one())
            std::this_thread::sleep_for(POLL_INTERVAL);
    }
}

void LocalControlPlane::request_stop() noexcept {
    impl_->stop_requested_.store(true);
}

const std::filesystem::path& LocalControlPlane::runtime_root() const noexcept {
    return impl_->root_;
}

} // namespace v0id::control
