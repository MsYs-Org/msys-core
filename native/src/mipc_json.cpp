#include "msys/mipc_broker.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>

namespace msys::native::mipc {
namespace {

[[noreturn]] void fail(const std::string& detail) {
    throw ProtocolError(detail);
}

bool valid_utf8(std::string_view value) noexcept {
    std::size_t index = 0U;
    while (index < value.size()) {
        const auto first = static_cast<unsigned char>(value[index]);
        if (first <= 0x7fU) {
            ++index;
            continue;
        }
        std::size_t continuation_count = 0U;
        std::uint32_t code_point = 0U;
        if (first >= 0xc2U && first <= 0xdfU) {
            continuation_count = 1U;
            code_point = static_cast<std::uint32_t>(first & 0x1fU);
        } else if (first >= 0xe0U && first <= 0xefU) {
            continuation_count = 2U;
            code_point = static_cast<std::uint32_t>(first & 0x0fU);
        } else if (first >= 0xf0U && first <= 0xf4U) {
            continuation_count = 3U;
            code_point = static_cast<std::uint32_t>(first & 0x07U);
        } else {
            return false;
        }
        if (continuation_count > value.size() - index - 1U) {
            return false;
        }
        for (std::size_t offset = 1U; offset <= continuation_count; ++offset) {
            const auto next = static_cast<unsigned char>(value[index + offset]);
            if ((next & 0xc0U) != 0x80U) {
                return false;
            }
            code_point = (code_point << 6U) | static_cast<std::uint32_t>(next & 0x3fU);
        }
        if ((continuation_count == 2U && code_point < 0x800U)
            || (continuation_count == 3U && code_point < 0x10000U)
            || code_point > 0x10ffffU
            || (code_point >= 0xd800U && code_point <= 0xdfffU)) {
            return false;
        }
        index += continuation_count + 1U;
    }
    return true;
}

int hex_nibble(char value) noexcept {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

void append_utf8(std::string& output, std::uint32_t code_point) {
    if (code_point <= 0x7fU) {
        output.push_back(static_cast<char>(code_point));
    } else if (code_point <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else if (code_point <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
    }
}

class Parser final {
public:
    explicit Parser(std::string_view input) : input_(input) {}

    DecodedMessage parse() {
        if (input_.empty()) {
            fail("mIPC packet is empty");
        }
        if (!valid_utf8(input_)) {
            fail("mIPC packet is not valid UTF-8");
        }
        DecodedMessage message{};
        std::unordered_set<std::string> fields;
        skip_space();
        expect('{');
        skip_space();
        if (consume('}')) {
            fail("mIPC packet requires string type");
        }
        for (;;) {
            if (fields.size() >= max_json_container_entries) {
                fail("JSON object has too many fields");
            }
            const std::string key = parse_string();
            if (!fields.insert(key).second) {
                fail("duplicate JSON field: " + key);
            }
            skip_space();
            expect(':');
            skip_space();
            if (key == "type") {
                type_name_ = parse_string();
            } else if (key == "id") {
                message.request_id = parse_unsigned_integer("id", true);
            } else if (key == "component") {
                message.component = parse_string();
                component_present_ = true;
            } else if (key == "generation") {
                message.generation = parse_unsigned_integer("generation", true);
            } else if (key == "target") {
                message.target = parse_string();
                target_present_ = true;
            } else if (key == "method") {
                message.method = parse_string();
                method_present_ = true;
            } else if (key == "topic") {
                message.topic = parse_string();
                topic_present_ = true;
            } else if (key == "code") {
                message.code = parse_string();
                code_present_ = true;
            } else if (key == "message") {
                message.message = parse_string();
                message_present_ = true;
            } else if (key == "source") {
                (void)parse_string();
                source_present_ = true;
            } else if (key == "deadline_ms") {
                message.deadline_ms = parse_unsigned_integer("deadline_ms", false);
            } else if (key == "idempotent") {
                message.idempotent = parse_boolean("idempotent");
            } else if (key == "payload") {
                const std::size_t payload_begin = position_;
                parse_payload(message);
                message.payload_json = std::string{
                    input_.substr(payload_begin, position_ - payload_begin)};
                payload_present_ = true;
            } else {
                fail("unknown top-level JSON field: " + key);
            }
            skip_space();
            if (consume('}')) {
                break;
            }
            expect(',');
            skip_space();
        }
        skip_space();
        if (position_ != input_.size()) {
            fail("trailing data after JSON object");
        }
        validate_message(message, fields);
        return message;
    }

private:
    void validate_message(
        DecodedMessage& message,
        const std::unordered_set<std::string>& fields) {
        if (type_name_.empty()) {
            fail("mIPC packet requires non-empty string type");
        }
        const auto has = [&fields](std::string_view key) {
            return fields.find(std::string{key}) != fields.end();
        };
        if (type_name_ == "hello") {
            message.type = MessageType::hello;
            if (message.request_id.has_value() || target_present_ || method_present_
                || payload_present_ || message.deadline_ms.has_value()
                || message.idempotent.has_value() || topic_present_ || code_present_
                || message_present_ || source_present_) {
                fail("hello contains call-only fields");
            }
            if (component_present_ != message.generation.has_value()) {
                fail("component hello requires component and generation together");
            }
            if (component_present_ && (message.component.empty() || message.component.size() > 128U)) {
                fail("component hello has invalid component");
            }
            return;
        }
        if (type_name_ == "ready") {
            message.type = MessageType::ready;
            if (fields.size() != 1U || !has("type")) {
                fail("ready accepts only the type field");
            }
            return;
        }
        if (type_name_ == "call") {
            message.type = MessageType::call;
            if (!message.request_id.has_value() || !target_present_ || !method_present_) {
                fail("call requires id, target, and method");
            }
            if (component_present_ || message.generation.has_value()) {
                fail("call contains hello-only fields");
            }
            if (topic_present_ || code_present_ || message_present_ || source_present_) {
                fail("call contains fields reserved for routed output");
            }
            if (message.target.empty() || message.target.size() > 256U
                || message.method.empty() || message.method.size() > 256U) {
                fail("call target or method is outside its allowed length");
            }
            return;
        }
        if (type_name_ == "subscribe") {
            message.type = MessageType::subscribe;
            if (!topic_present_ || message.topic.empty() || message.topic.size() > 256U
                || fields.size() != 2U || !has("type") || !has("topic")) {
                fail("subscribe requires only type and a bounded topic");
            }
            return;
        }
        if (type_name_ == "event") {
            message.type = MessageType::event;
            if (!topic_present_ || message.topic.empty() || message.topic.size() > 256U
                || !payload_present_ || fields.size() != 3U
                || !has("type") || !has("topic") || !has("payload")) {
                fail("event requires type, topic, and payload");
            }
            return;
        }
        if (type_name_ == "return") {
            message.type = MessageType::returned;
            if (!message.request_id.has_value() || !payload_present_
                || fields.size() != 3U || !has("type") || !has("id")
                || !has("payload")) {
                fail("return requires only type, id, and payload");
            }
            return;
        }
        if (type_name_ == "error") {
            message.type = MessageType::error;
            if (!message.request_id.has_value() || !code_present_
                || message.code.empty() || message.code.size() > 128U
                || (message_present_ && message.message.size() > 1024U)
                || target_present_ || method_present_ || topic_present_
                || component_present_ || message.generation.has_value()
                || message.deadline_ms.has_value() || message.idempotent.has_value()
                || source_present_) {
                fail("error has invalid fields");
            }
            return;
        }
        fail("unsupported mIPC message type");
    }

    void parse_payload(DecodedMessage& message) {
        expect('{');
        skip_space();
        if (consume('}')) {
            return;
        }
        std::unordered_set<std::string> fields;
        for (;;) {
            if (fields.size() >= max_json_container_entries) {
                fail("payload object has too many fields");
            }
            const std::string key = parse_string();
            if (!fields.insert(key).second) {
                fail("duplicate payload JSON field: " + key);
            }
            skip_space();
            expect(':');
            skip_space();
            if (key == "component") {
                message.payload_component = parse_string();
                if (message.payload_component->empty()
                    || message.payload_component->size() > 128U) {
                    fail("payload.component is outside its allowed length");
                }
            } else if (key == "role") {
                message.payload_role = parse_string();
                validate_payload_string(*message.payload_role, "payload.role");
            } else if (key == "topic") {
                message.payload_topic = parse_string();
                validate_payload_string(*message.payload_topic, "payload.topic");
            } else if (key == "provider") {
                message.payload_provider = parse_string();
                validate_payload_string(*message.payload_provider, "payload.provider");
            } else if (key == "action") {
                message.payload_action = parse_string();
                validate_payload_string(*message.payload_action, "payload.action");
            } else if (key == "payload") {
                const std::size_t nested_begin = position_;
                skip_value(2U);
                message.nested_payload_json = std::string{
                    input_.substr(nested_begin, position_ - nested_begin)};
            } else {
                skip_value(2U);
            }
            skip_space();
            if (consume('}')) {
                return;
            }
            expect(',');
            skip_space();
        }
    }

    static void validate_payload_string(
        const std::string& value,
        std::string_view field) {
        if (value.empty() || value.size() > 256U) {
            fail(std::string{field} + " is outside its allowed length");
        }
    }

    void skip_value(std::size_t depth) {
        if (depth > max_json_depth) {
            fail("JSON nesting exceeds 32 levels");
        }
        if (position_ >= input_.size()) {
            fail("truncated JSON value");
        }
        const char value = input_[position_];
        if (value == '"') {
            (void)parse_string();
            return;
        }
        if (value == '{') {
            ++position_;
            skip_space();
            if (consume('}')) {
                return;
            }
            std::unordered_set<std::string> fields;
            for (;;) {
                if (fields.size() >= max_json_container_entries) {
                    fail("JSON object has too many fields");
                }
                const std::string key = parse_string();
                if (!fields.insert(key).second) {
                    fail("duplicate nested JSON field: " + key);
                }
                skip_space();
                expect(':');
                skip_space();
                skip_value(depth + 1U);
                skip_space();
                if (consume('}')) {
                    return;
                }
                expect(',');
                skip_space();
            }
        }
        if (value == '[') {
            ++position_;
            skip_space();
            if (consume(']')) {
                return;
            }
            std::size_t entries = 0U;
            for (;;) {
                if (entries >= max_json_container_entries) {
                    fail("JSON array has too many entries");
                }
                ++entries;
                skip_value(depth + 1U);
                skip_space();
                if (consume(']')) {
                    return;
                }
                expect(',');
                skip_space();
            }
        }
        if (value == 't') {
            expect_literal("true");
            return;
        }
        if (value == 'f') {
            expect_literal("false");
            return;
        }
        if (value == 'n') {
            expect_literal("null");
            return;
        }
        parse_number_token();
    }

    std::uint64_t parse_unsigned_integer(std::string_view field, bool positive) {
        const std::size_t begin = position_;
        parse_number_token();
        const std::string_view token = input_.substr(begin, position_ - begin);
        if (token.empty() || token.front() == '-'
            || token.find_first_of(".eE") != std::string_view::npos) {
            fail(std::string{field} + " must be an unsigned integer");
        }
        std::uint64_t result = 0U;
        const auto parsed = std::from_chars(
            token.data(), token.data() + token.size(), result, 10);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size()
            || (positive && result == 0U)) {
            fail(std::string{field} + " is outside its allowed integer range");
        }
        return result;
    }

    bool parse_boolean(std::string_view field) {
        if (input_.substr(position_, 4U) == "true") {
            position_ += 4U;
            return true;
        }
        if (input_.substr(position_, 5U) == "false") {
            position_ += 5U;
            return false;
        }
        fail(std::string{field} + " must be a boolean");
    }

    void parse_number_token() {
        const std::size_t begin = position_;
        (void)consume('-');
        if (consume('0')) {
            if (position_ < input_.size() && input_[position_] >= '0'
                && input_[position_] <= '9') {
                fail("JSON number has a leading zero");
            }
        } else {
            require_digit('1', '9');
            while (consume_digit()) {
            }
        }
        if (consume('.')) {
            require_digit('0', '9');
            while (consume_digit()) {
            }
        }
        if (consume('e') || consume('E')) {
            if (!consume('+')) {
                (void)consume('-');
            }
            require_digit('0', '9');
            while (consume_digit()) {
            }
        }
        if (position_ == begin) {
            fail("expected JSON value");
        }
    }

    std::string parse_string() {
        expect('"');
        std::string output;
        while (position_ < input_.size()) {
            const auto byte = static_cast<unsigned char>(input_[position_++]);
            if (byte == static_cast<unsigned char>('"')) {
                return output;
            }
            if (byte < 0x20U) {
                fail("JSON string contains an unescaped control byte");
            }
            if (byte != static_cast<unsigned char>('\\')) {
                output.push_back(static_cast<char>(byte));
                continue;
            }
            if (position_ >= input_.size()) {
                fail("truncated JSON escape");
            }
            const char escape = input_[position_++];
            switch (escape) {
            case '"':
            case '\\':
            case '/':
                output.push_back(escape);
                break;
            case 'b':
                output.push_back('\b');
                break;
            case 'f':
                output.push_back('\f');
                break;
            case 'n':
                output.push_back('\n');
                break;
            case 'r':
                output.push_back('\r');
                break;
            case 't':
                output.push_back('\t');
                break;
            case 'u': {
                std::uint32_t code_point = parse_hex_quad();
                if (code_point >= 0xd800U && code_point <= 0xdbffU) {
                    if (position_ + 2U > input_.size()
                        || input_[position_] != '\\' || input_[position_ + 1U] != 'u') {
                        fail("JSON high surrogate lacks a low surrogate");
                    }
                    position_ += 2U;
                    const std::uint32_t low = parse_hex_quad();
                    if (low < 0xdc00U || low > 0xdfffU) {
                        fail("JSON high surrogate has an invalid low surrogate");
                    }
                    code_point = 0x10000U
                        + ((code_point - 0xd800U) << 10U)
                        + (low - 0xdc00U);
                } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
                    fail("JSON string contains an unpaired low surrogate");
                }
                append_utf8(output, code_point);
                break;
            }
            default:
                fail("JSON string contains an invalid escape");
            }
        }
        fail("unterminated JSON string");
    }

    std::uint32_t parse_hex_quad() {
        if (position_ + 4U > input_.size()) {
            fail("truncated JSON unicode escape");
        }
        std::uint32_t result = 0U;
        for (std::size_t offset = 0U; offset < 4U; ++offset) {
            const int nibble = hex_nibble(input_[position_ + offset]);
            if (nibble < 0) {
                fail("JSON unicode escape is not hexadecimal");
            }
            result = (result << 4U) | static_cast<std::uint32_t>(nibble);
        }
        position_ += 4U;
        return result;
    }

    void skip_space() noexcept {
        while (position_ < input_.size()) {
            const char value = input_[position_];
            if (value != ' ' && value != '\t' && value != '\n' && value != '\r') {
                break;
            }
            ++position_;
        }
    }

    bool consume(char expected) noexcept {
        if (position_ < input_.size() && input_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    bool consume_digit() noexcept {
        if (position_ < input_.size() && input_[position_] >= '0'
            && input_[position_] <= '9') {
            ++position_;
            return true;
        }
        return false;
    }

    void require_digit(char minimum, char maximum) {
        if (position_ >= input_.size() || input_[position_] < minimum
            || input_[position_] > maximum) {
            fail("JSON number requires a digit");
        }
        ++position_;
    }

    void expect(char expected) {
        if (!consume(expected)) {
            fail(std::string{"expected JSON token: "} + expected);
        }
    }

    void expect_literal(std::string_view literal) {
        if (input_.substr(position_, literal.size()) != literal) {
            fail("invalid JSON literal");
        }
        position_ += literal.size();
    }

    std::string_view input_;
    std::size_t position_{0U};
    std::string type_name_;
    bool component_present_{false};
    bool target_present_{false};
    bool method_present_{false};
    bool topic_present_{false};
    bool code_present_{false};
    bool message_present_{false};
    bool source_present_{false};
    bool payload_present_{false};
};

}  // namespace

ProtocolError::ProtocolError(const std::string& detail)
    : std::runtime_error("mIPC protocol: " + detail) {}

DecodedMessage decode_message(std::string_view packet) {
    if (packet.size() > max_packet_bytes) {
        throw ProtocolError("packet exceeds 262144 bytes");
    }
    return Parser{packet}.parse();
}

}  // namespace msys::native::mipc
