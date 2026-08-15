#include "tfhe_remote_control.hpp"

#include "boolean_program_image.hpp"
#include "tfhe_cloud_client.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace v0id::control {
namespace {

using json = nlohmann::json;
using v0id::integrity::BooleanProgramImage;
using v0id::integrity::BooleanProgramInstruction;
using v0id::integrity::BooleanProgramOpcode;

constexpr std::size_t MAX_COMMAND_BYTES = 4 * 1024 * 1024;
constexpr auto POLL_INTERVAL = std::chrono::milliseconds(200);

std::uint64_t unix_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

std::string read_text(const std::filesystem::path& path, std::size_t max_bytes) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open TFHE cloud control JSON: " + path.string());
    const auto end = in.tellg();
    if (end < 0 || static_cast<std::uint64_t>(end) > max_bytes)
        throw std::runtime_error("TFHE cloud control JSON exceeds size limit");
    std::string text(static_cast<std::size_t>(end), '\0');
    in.seekg(0, std::ios::beg);
    if (!text.empty()) in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (!in && !text.empty())
        throw std::runtime_error("failed reading TFHE cloud control JSON");
    return text;
}

void atomic_write_json(const std::filesystem::path& path, const json& value) {
    const auto tmp = path.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("cannot create TFHE cloud JSON temp file");
        out << value.dump(2) << '\n';
        if (!out) throw std::runtime_error("failed writing TFHE cloud JSON");
    }
    std::filesystem::rename(tmp, path);
}

std::string uppercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        if (c >= 'a' && c <= 'z') return static_cast<char>(c - 'a' + 'A');
        return static_cast<char>(c);
    });
    return value;
}

BooleanProgramOpcode parse_opcode(std::string value) {
    value = uppercase(std::move(value));
    if (value == "XOR2") return BooleanProgramOpcode::Xor2;
    if (value == "XOR5") return BooleanProgramOpcode::Xor5;
    if (value == "XOR_ROT1" || value == "XORROT1") return BooleanProgramOpcode::XorRot1;
    if (value == "ROT_COPY" || value == "ROTCOPY") return BooleanProgramOpcode::RotCopy;
    if (value == "CHI") return BooleanProgramOpcode::Chi;
    if (value == "XOR_INPUT" || value == "XORINPUT") return BooleanProgramOpcode::XorInput;
    if (value == "XOR_CONST" || value == "XORCONST") return BooleanProgramOpcode::XorConst;
    throw std::runtime_error("unknown BooleanProgramImage opcode: " + value);
}

std::uint64_t parse_u64(const json& value, const char* what) {
    if (value.is_number_unsigned()) return value.get<std::uint64_t>();
    if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value < 0)
            throw std::runtime_error(std::string(what) + " must not be negative");
        return static_cast<std::uint64_t>(signed_value);
    }
    if (value.is_string()) {
        const auto text = value.get<std::string>();
        if (text.empty()) throw std::runtime_error(std::string(what) + " is empty");
        std::size_t consumed = 0;
        const int base = text.size() > 2 && text[0] == '0' &&
                         (text[1] == 'x' || text[1] == 'X') ? 16 : 10;
        const auto parsed = std::stoull(text, &consumed, base);
        if (consumed != text.size())
            throw std::runtime_error(std::string(what) + " contains trailing characters");
        return parsed;
    }
    throw std::runtime_error(std::string(what) + " must be integer or integer string");
}

template <typename T>
T bounded_integer(const json& object,
                  const char* key,
                  std::uint64_t default_value = 0) {
    const auto value = object.contains(key)
        ? parse_u64(object.at(key), key)
        : default_value;
    if (value > static_cast<std::uint64_t>(std::numeric_limits<T>::max()))
        throw std::runtime_error(std::string(key) + " exceeds field width");
    return static_cast<T>(value);
}

BooleanProgramImage parse_program(const json& value) {
    if (!value.is_object())
        throw std::runtime_error("program must be a JSON object");

    BooleanProgramImage image;
    image.register_count = value.at("register_count").get<std::size_t>();
    image.input_word_count = value.at("input_word_count").get<std::size_t>();

    const auto& instructions = value.at("instructions");
    if (!instructions.is_array())
        throw std::runtime_error("program.instructions must be an array");
    if (instructions.size() > v0id::net::kTfheCloudMaxInstructions)
        throw std::runtime_error("program instruction count exceeds TFHE cloud protocol limit");

    image.instructions.reserve(instructions.size());
    for (const auto& item : instructions) {
        if (!item.is_object())
            throw std::runtime_error("each program instruction must be an object");
        BooleanProgramInstruction instruction;
        instruction.op = parse_opcode(item.at("op").get<std::string>());
        instruction.dst = bounded_integer<std::uint8_t>(item, "dst");
        instruction.a = bounded_integer<std::uint8_t>(item, "a");
        instruction.b = bounded_integer<std::uint8_t>(item, "b");
        instruction.c = bounded_integer<std::uint8_t>(item, "c");
        instruction.d = bounded_integer<std::uint8_t>(item, "d");
        instruction.e = bounded_integer<std::uint8_t>(item, "e");
        instruction.input_index = bounded_integer<std::uint16_t>(item, "input_index");
        instruction.rotate = bounded_integer<std::uint8_t>(item, "rotate");
        instruction.immediate = item.contains("immediate")
            ? parse_u64(item.at("immediate"), "immediate")
            : 0;
        image.instructions.push_back(instruction);
    }

    const auto& outputs = value.at("output_registers");
    if (!outputs.is_array())
        throw std::runtime_error("program.output_registers must be an array");
    if (outputs.size() > v0id::net::kTfheCloudMaxOutputs)
        throw std::runtime_error("program output count exceeds TFHE cloud protocol limit");
    for (const auto& output : outputs) {
        const auto raw = parse_u64(output, "output_register");
        if (raw > std::numeric_limits<std::uint8_t>::max())
            throw std::runtime_error("output register exceeds field width");
        image.output_registers.push_back(static_cast<std::uint8_t>(raw));
    }

    image.validate();
    return image;
}

std::vector<std::uint64_t> parse_input_words(const json& value,
                                             std::size_t expected) {
    if (!value.is_array())
        throw std::runtime_error("input_words must be a JSON array");
    if (value.size() != expected)
        throw std::runtime_error("input_words count does not match program input_word_count");
    std::vector<std::uint64_t> out;
    out.reserve(value.size());
    for (const auto& item : value)
        out.push_back(parse_u64(item, "input_word"));
    return out;
}

std::string u64_hex(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    return out.str();
}

struct CloudConfigRecord {
    std::string endpoint;
    std::string client_peer_id;
    std::string client_public_key_file;
    std::string client_secret_key_file;
    std::string server_public_key_file;
    std::string expected_server_peer_id;
    int timeout_ms{3'600'000};
    std::uint32_t retry_attempts{2};
    std::size_t instruction_chunk_size{32};
    bool verify_plaintext_result{true};

    bool configured() const {
        return !endpoint.empty() &&
               !client_peer_id.empty() &&
               !client_public_key_file.empty() &&
               !client_secret_key_file.empty() &&
               !server_public_key_file.empty() &&
               !expected_server_peer_id.empty();
    }
};

json config_json(const CloudConfigRecord& config) {
    return {
        {"endpoint", config.endpoint},
        {"client_peer_id", config.client_peer_id},
        {"client_public_key_file", config.client_public_key_file},
        {"client_secret_key_file", config.client_secret_key_file},
        {"server_public_key_file", config.server_public_key_file},
        {"expected_server_peer_id", config.expected_server_peer_id},
        {"timeout_ms", config.timeout_ms},
        {"retry_attempts", config.retry_attempts},
        {"instruction_chunk_size", config.instruction_chunk_size},
        {"verify_plaintext_result", config.verify_plaintext_result},
    };
}

CloudConfigRecord parse_config(const json& payload) {
    CloudConfigRecord config;
    config.endpoint = payload.at("endpoint").get<std::string>();
    config.client_peer_id = payload.at("client_peer_id").get<std::string>();
    config.client_public_key_file = payload.at("client_public_key_file").get<std::string>();
    config.client_secret_key_file = payload.at("client_secret_key_file").get<std::string>();
    config.server_public_key_file = payload.at("server_public_key_file").get<std::string>();
    config.expected_server_peer_id = payload.at("expected_server_peer_id").get<std::string>();
    config.timeout_ms = payload.value("timeout_ms", 3'600'000);
    config.retry_attempts = payload.value("retry_attempts", std::uint32_t{2});
    config.instruction_chunk_size = payload.value("instruction_chunk_size", std::size_t{32});
    config.verify_plaintext_result = payload.value("verify_plaintext_result", true);

    if (!config.configured())
        throw std::runtime_error("TFHE cloud endpoint configuration is incomplete");
    if (config.timeout_ms <= 0)
        throw std::runtime_error("TFHE cloud timeout must be positive");
    if (config.retry_attempts == 0 || config.retry_attempts > 8)
        throw std::runtime_error("TFHE cloud retry attempts must be in 1..8");
    if (config.instruction_chunk_size == 0 || config.instruction_chunk_size > 32)
        throw std::runtime_error("TFHE cloud instruction chunk size must be in 1..32");
    return config;
}

} // namespace

struct TfheRemoteControl::Impl {
    explicit Impl(std::filesystem::path root) : root_(std::move(root)) {}

    std::filesystem::path root_;
    std::filesystem::path commands_dir_;
    std::filesystem::path processing_dir_;
    std::filesystem::path responses_dir_;
    std::filesystem::path state_path_;
    std::filesystem::path registry_path_;

    CloudConfigRecord config_;
    std::uint64_t revision_{};
    std::string last_error_;
    json last_command_ = json::object();
    json computation_ = {
        {"job_id", ""},
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
    bool initialized_{};

    json state_json() const {
        return {
            {"protocol", "v0id-tfhe-cloud-control-v1"},
            {"revision", revision_},
            {"updated_unix_ms", unix_ms()},
            {"configured", config_.configured()},
            {"config", config_json(config_)},
            {"computation", computation_},
            {"last_command", last_command_},
            {"last_error", last_error_},
        };
    }

    void publish_state() {
        ++revision_;
        atomic_write_json(state_path_, state_json());
    }

    void persist_config() const {
        atomic_write_json(registry_path_, {
            {"protocol", "v0id-tfhe-cloud-control-registry-v1"},
            {"config", config_json(config_)},
        });
    }

    void load_config() {
        if (!std::filesystem::exists(registry_path_)) return;
        const auto value = json::parse(read_text(registry_path_, MAX_COMMAND_BYTES));
        if (value.value("protocol", std::string{}) !=
            "v0id-tfhe-cloud-control-registry-v1")
            throw std::runtime_error("unsupported TFHE cloud control registry protocol");
        config_ = parse_config(value.at("config"));
    }

    void initialize() {
        if (initialized_) return;
        commands_dir_ = root_ / "cloud_commands";
        processing_dir_ = root_ / "cloud_processing";
        responses_dir_ = root_ / "cloud_responses";
        state_path_ = root_ / "cloud_state.json";
        registry_path_ = root_ / "cloud_registry.json";
        std::filesystem::create_directories(commands_dir_);
        std::filesystem::create_directories(processing_dir_);
        std::filesystem::create_directories(responses_dir_);
        load_config();
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
            : 100.0 * static_cast<double>(std::min(current, total)) /
                  static_cast<double>(total);
        computation_["message"] = message;
        computation_["updated_unix_ms"] = unix_ms();
        publish_state();
    }

    void begin_job(const std::string& command_id, const std::string& job_id) {
        computation_ = {
            {"job_id", job_id},
            {"command_id", command_id},
            {"state", "running"},
            {"stage", "queued"},
            {"current", 0},
            {"total", 1},
            {"percent", 0.0},
            {"message", "queued by local TFHE cloud dashboard"},
            {"started_unix_ms", unix_ms()},
            {"updated_unix_ms", unix_ms()},
            {"result", json::object()},
        };
        last_error_.clear();
        publish_state();
    }

    void complete_job(json result) {
        computation_["state"] = "completed";
        computation_["stage"] = "completed";
        computation_["current"] = 1;
        computation_["total"] = 1;
        computation_["percent"] = 100.0;
        computation_["message"] = "encrypted remote computation completed";
        computation_["updated_unix_ms"] = unix_ms();
        computation_["result"] = std::move(result);
        publish_state();
    }

    void fail_job(const std::string& error) {
        computation_["state"] = "failed";
        computation_["stage"] = "failed";
        computation_["message"] = error;
        computation_["updated_unix_ms"] = unix_ms();
        last_error_ = error;
        publish_state();
    }

    json run_remote_program(const json& payload, const std::string& command_id) {
        if (!config_.configured())
            throw std::runtime_error("configure a remote TFHE endpoint first");

        const auto image = parse_program(payload.at("program"));
        const auto input_words = parse_input_words(
            payload.at("input_words"), image.input_word_count);
        const auto job_id = payload.value("job_id", command_id);
        const auto epoch = payload.value("epoch", std::uint64_t{1});
        if (job_id.empty())
            throw std::runtime_error("remote TFHE job id must not be empty");

        begin_job(command_id, job_id);
        try {
            v0id::net::TfheCloudClientConfig cloud;
            cloud.client_peer_id = config_.client_peer_id;
            cloud.endpoint = config_.endpoint;
            cloud.client_keys = v0id::net::load_curve_keypair_files(
                config_.client_public_key_file,
                config_.client_secret_key_file);
            cloud.server_public_key_z85 = v0id::net::load_curve_public_key_file(
                config_.server_public_key_file);
            cloud.expected_server_peer_id = config_.expected_server_peer_id;
            cloud.job_id = job_id;
            cloud.epoch = epoch;
            cloud.timeout_ms = config_.timeout_ms;
            cloud.retry_attempts = config_.retry_attempts;
            cloud.instruction_chunk_size = config_.instruction_chunk_size;
            cloud.verify_plaintext_result = config_.verify_plaintext_result;

            auto progress = [&](const std::string& stage,
                                std::uint64_t current,
                                std::uint64_t total,
                                const std::string& message) {
                set_progress(stage, current, total, message);
            };

            const auto result = v0id::net::execute_boolean_program_tfhe_cloud(
                image, input_words, cloud, progress);

            json output_words = json::array();
            for (const auto word : result.output_words)
                output_words.push_back(u64_hex(word));

            json out = {
                {"type", "tfhe_cloud_boolean_program"},
                {"endpoint", config_.endpoint},
                {"expected_server_peer_id", config_.expected_server_peer_id},
                {"session_id_hex", result.session_id_hex},
                {"job_id", job_id},
                {"epoch", epoch},
                {"instruction_count", result.instruction_count},
                {"output_word_count", result.output_word_count},
                {"server_key_bytes", result.server_key_bytes},
                {"encrypted_init_bytes", result.encrypted_init_bytes},
                {"encrypted_result_bytes", result.encrypted_result_bytes},
                {"output_words", std::move(output_words)},
                {"plaintext_verified", result.plaintext_verified},
                {"client_key_sent_to_evaluator", false},
                {"plaintext_program_sent_to_evaluator", false},
                {"plaintext_input_sent_to_evaluator", false},
            };
            complete_job(out);
            return out;
        } catch (const std::exception& e) {
            fail_job(e.what());
            throw;
        }
    }

    std::vector<std::filesystem::path> queued_commands() const {
        std::vector<std::filesystem::path> paths;
        for (const auto& entry : std::filesystem::directory_iterator(commands_dir_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json")
                paths.push_back(entry.path());
        }
        std::sort(paths.begin(), paths.end());
        return paths;
    }

    bool process_one() {
        if (!initialized_)
            throw std::runtime_error("TFHE remote control is not initialized");
        auto queued = queued_commands();
        if (queued.empty()) return false;

        const auto source = queued.front();
        const auto processing = processing_dir_ / source.filename();
        std::filesystem::rename(source, processing);

        std::string command_id = processing.stem().string();
        json response;
        try {
            const auto command = json::parse(read_text(processing, MAX_COMMAND_BYTES));
            if (command.value("protocol", std::string{}) != "v0id-tfhe-cloud-control-v1")
                throw std::runtime_error("unsupported TFHE cloud dashboard command protocol");
            command_id = command.at("command_id").get<std::string>();
            if (command_id.empty())
                throw std::runtime_error("TFHE cloud command id must not be empty");
            const auto name = command.at("command").get<std::string>();
            const auto payload = command.value("payload", json::object());

            last_command_ = {
                {"command_id", command_id},
                {"command", name},
                {"received_unix_ms", unix_ms()},
            };

            json result = json::object();
            if (name == "configure_cloud") {
                config_ = parse_config(payload);
                // Validate key files immediately, before accepting the config.
                (void)v0id::net::load_curve_keypair_files(
                    config_.client_public_key_file,
                    config_.client_secret_key_file);
                (void)v0id::net::load_curve_public_key_file(
                    config_.server_public_key_file);
                persist_config();
                result = {{"configured", true}, {"config", config_json(config_)}};
                last_error_.clear();
                publish_state();
            } else if (name == "run_tfhe_boolean_program") {
                result = run_remote_program(payload, command_id);
            } else {
                throw std::runtime_error("unknown TFHE cloud dashboard command: " + name);
            }

            response = {
                {"protocol", "v0id-tfhe-cloud-control-response-v1"},
                {"command_id", command_id},
                {"ok", true},
                {"result", std::move(result)},
            };
        } catch (const std::exception& e) {
            last_error_ = e.what();
            publish_state();
            response = {
                {"protocol", "v0id-tfhe-cloud-control-response-v1"},
                {"command_id", command_id},
                {"ok", false},
                {"error", e.what()},
            };
        }

        atomic_write_json(responses_dir_ / (command_id + ".json"), response);
        std::filesystem::remove(processing);
        return true;
    }
};

TfheRemoteControl::TfheRemoteControl(std::filesystem::path runtime_root)
    : impl_(std::make_unique<Impl>(std::move(runtime_root))) {}

TfheRemoteControl::~TfheRemoteControl() = default;
TfheRemoteControl::TfheRemoteControl(TfheRemoteControl&&) noexcept = default;
TfheRemoteControl& TfheRemoteControl::operator=(TfheRemoteControl&&) noexcept = default;

void TfheRemoteControl::initialize() { impl_->initialize(); }
bool TfheRemoteControl::process_one() { return impl_->process_one(); }

void TfheRemoteControl::run(std::stop_token stop_token) {
    while (!stop_token.stop_requested()) {
        if (!process_one()) std::this_thread::sleep_for(POLL_INTERVAL);
    }
}

} // namespace v0id::control
