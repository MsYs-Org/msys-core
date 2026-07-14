#include "msys/mipc_broker.hpp"

#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using msys::native::mipc::DecodedMessage;
using msys::native::mipc::MessageType;
using msys::native::mipc::ProtocolError;

void expect(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Callback>
void expect_protocol_error(Callback callback, const char* message) {
    bool rejected = false;
    try {
        callback();
    } catch (const ProtocolError&) {
        rejected = true;
    }
    expect(rejected, message);
}

void test_valid_messages() {
    const DecodedMessage public_hello =
        msys::native::mipc::decode_message("{\"type\":\"hello\"}");
    expect(public_hello.type == MessageType::hello, "public hello type mismatch");
    expect(public_hello.component.empty(), "public hello unexpectedly has component");

    const DecodedMessage component_hello = msys::native::mipc::decode_message(
        "{\"generation\":7,\"component\":\"org.msys.demo:main\",\"type\":\"hello\"}");
    expect(component_hello.type == MessageType::hello, "component hello type mismatch");
    expect(component_hello.component == "org.msys.demo:main", "hello component mismatch");
    expect(component_hello.generation == 7U, "hello generation mismatch");

    const DecodedMessage ready =
        msys::native::mipc::decode_message(" { \"type\" : \"ready\" } ");
    expect(ready.type == MessageType::ready, "ready type mismatch");

    const DecodedMessage call = msys::native::mipc::decode_message(
        "{\"type\":\"call\",\"id\":42,\"target\":\"msys.core\","
        "\"method\":\"start\",\"deadline_ms\":0,\"idempotent\":true,\"payload\":{"
        "\"component\":\"org.msys.\\u0064emo:main\","
        "\"activation\":{\"title\":\"\\ud83d\\ude80\",\"values\":[1,true,null]}}}");
    expect(call.type == MessageType::call, "call type mismatch");
    expect(call.request_id == 42U, "call id mismatch");
    expect(call.deadline_ms == 0U, "call deadline mismatch");
    expect(call.idempotent == true, "call idempotent mismatch");
    expect(call.target == "msys.core" && call.method == "start", "call route mismatch");
    expect(
        call.payload_component == std::optional<std::string>{"org.msys.demo:main"},
        "payload component mismatch");

    const DecodedMessage subscribe = msys::native::mipc::decode_message(
        "{\"type\":\"subscribe\",\"topic\":\"msys.hal.*\"}");
    expect(subscribe.type == MessageType::subscribe, "subscribe type mismatch");
    expect(subscribe.topic == "msys.hal.*", "subscribe topic mismatch");

    const DecodedMessage event = msys::native::mipc::decode_message(
        "{\"type\":\"event\",\"topic\":\"msys.hal.changed\","
        "\"payload\":{\"topic\":\"nested\",\"payload\":{\"ok\":true}}}");
    expect(event.type == MessageType::event, "event type mismatch");
    expect(event.payload_topic == std::optional<std::string>{"nested"},
           "event payload topic mismatch");
    expect(event.nested_payload_json == std::optional<std::string>{"{\"ok\":true}"},
           "nested payload raw JSON mismatch");

    const DecodedMessage returned = msys::native::mipc::decode_message(
        "{\"type\":\"return\",\"id\":9,\"payload\":{\"ok\":true}}");
    expect(returned.type == MessageType::returned, "return type mismatch");
    expect(returned.payload_json == "{\"ok\":true}", "return payload mismatch");

    const DecodedMessage error = msys::native::mipc::decode_message(
        "{\"type\":\"error\",\"id\":10,\"code\":\"NOPE\",\"message\":\"failed\"}");
    expect(error.type == MessageType::error && error.code == "NOPE",
           "error envelope mismatch");
}

void test_strict_rejections() {
    const std::vector<std::string> invalid{
        "",
        "[]",
        "{}",
        "{\"type\":\"ready\",\"extra\":1}",
        "{\"type\":\"ready\",\"type\":\"ready\"}",
        "{\"type\":\"ready\",\"\\u0074ype\":\"ready\"}",
        "{\"type\":\"unknown\"}",
        "{\"type\":\"hello\",\"component\":\"x\"}",
        "{\"type\":\"hello\",\"generation\":1}",
        "{\"type\":\"call\",\"id\":0,\"target\":\"msys.core\",\"method\":\"x\"}",
        "{\"type\":\"call\",\"id\":-1,\"target\":\"msys.core\",\"method\":\"x\"}",
        "{\"type\":\"call\",\"id\":1.0,\"target\":\"msys.core\",\"method\":\"x\"}",
        "{\"type\":\"call\",\"id\":true,\"target\":\"msys.core\",\"method\":\"x\"}",
        "{\"type\":\"call\",\"id\":1,\"target\":\"msys.core\",\"method\":\"x\",\"idempotent\":1}",
        "{\"type\":\"call\",\"id\":1,\"method\":\"x\"}",
        "{\"type\":\"call\",\"id\":1,\"target\":\"msys.core\",\"method\":\"x\",\"payload\":[]}",
        "{\"type\":\"call\",\"id\":1,\"target\":\"msys.core\",\"method\":\"x\",\"payload\":{\"x\":1,\"x\":2}}",
        "{\"type\":\"ready\"} trailing",
        "{\"type\":\"ready\"",
        "{\"type\":\"re\\x01ady\"}",
        "{\"type\":\"hello\",\"component\":\"x\",\"generation\":01}",
        "{\"type\":\"hello\",\"component\":\"\\ud800\",\"generation\":1}",
        "{\"type\":\"subscribe\",\"topic\":\"\"}",
        "{\"type\":\"event\",\"topic\":\"x\"}",
        "{\"type\":\"return\",\"id\":1}",
        "{\"type\":\"error\",\"id\":1,\"message\":\"missing code\"}",
        "{\"type\":\"event\",\"topic\":\"x\",\"payload\":{},\"source\":\"forged\"}",
    };
    for (const auto& packet : invalid) {
        expect_protocol_error(
            [&packet] { (void)msys::native::mipc::decode_message(packet); },
            "invalid packet was accepted");
    }

    std::string invalid_utf8 = "{\"type\":\"hello\",\"component\":\"";
    invalid_utf8.push_back(static_cast<char>(0xc0U));
    invalid_utf8 += "\",\"generation\":1}";
    expect_protocol_error(
        [&invalid_utf8] { (void)msys::native::mipc::decode_message(invalid_utf8); },
        "invalid UTF-8 was accepted");

    std::string too_large(msys::native::mipc::max_packet_bytes + 1U, 'x');
    expect_protocol_error(
        [&too_large] { (void)msys::native::mipc::decode_message(too_large); },
        "oversized packet was accepted");

    std::string too_deep =
        "{\"type\":\"call\",\"id\":1,\"target\":\"msys.core\","
        "\"method\":\"list_components\",\"payload\":{\"nested\":";
    too_deep.append(msys::native::mipc::max_json_depth + 2U, '[');
    too_deep += "0";
    too_deep.append(msys::native::mipc::max_json_depth + 2U, ']');
    too_deep += "}}";
    expect_protocol_error(
        [&too_deep] { (void)msys::native::mipc::decode_message(too_deep); },
        "excessive JSON nesting was accepted");
}

}  // namespace

int main() {
    try {
        test_valid_messages();
        test_strict_rejections();
        std::cout << "mIPC broker unit tests: ok\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "mIPC broker unit tests: " << error.what() << '\n';
        return 1;
    }
}
