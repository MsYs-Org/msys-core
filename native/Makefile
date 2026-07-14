CXX ?= c++
AR ?= ar
PYTHON ?= python3
INSTALL ?= install
BUILD_DIR ?= build
PREFIX ?= /usr/local

CPPFLAGS += -Iinclude -D_GNU_SOURCE
OPTIMIZE ?= -O1
DEBUG_INFO ?= -g1
STRICT_CXXFLAGS := \
	-std=c++20 $(OPTIMIZE) $(DEBUG_INFO) \
	-Wall -Wextra -Wpedantic -Werror \
	-Wconversion -Wsign-conversion -Wshadow -Wformat=2 -Wundef \
	-Wcast-align -Wcast-qual -Wnull-dereference -Wdouble-promotion \
	-Wimplicit-fallthrough
THREAD_FLAGS := -pthread

LIBRARY := $(BUILD_DIR)/libmsys-reactor.a
LIBRARY_OBJECTS := \
	$(BUILD_DIR)/reactor.o \
	$(BUILD_DIR)/reactor_events.o \
	$(BUILD_DIR)/reactor_children.o \
	$(BUILD_DIR)/reactor_spawn.o
UNIT_TEST := $(BUILD_DIR)/reactor-unit-tests
INTEGRATION_TEST := $(BUILD_DIR)/reactor-integration-tests
NATIVE_LITE_OBJECTS := \
	$(BUILD_DIR)/native_lite_plan.o \
	$(BUILD_DIR)/native_catalog.o \
	$(BUILD_DIR)/native_router.o \
	$(BUILD_DIR)/native_lite_supervisor.o
NATIVE_LITE := $(BUILD_DIR)/msysd-native-lite
NATIVE_LITE_UNIT := $(BUILD_DIR)/native-lite-unit-tests
NATIVE_LITE_INTEGRATION := $(BUILD_DIR)/native-lite-integration-tests
NATIVE_LITE_CHILD := $(BUILD_DIR)/native-lite-test-child
MIPC_OBJECTS := \
	$(BUILD_DIR)/mipc_json.o \
	$(BUILD_DIR)/mipc_broker.o
MIPC_LIBRARY := $(BUILD_DIR)/libmsys-mipc-broker.a
MIPC_UNIT := $(BUILD_DIR)/mipc-broker-unit-tests
MIPC_INTEGRATION := $(BUILD_DIR)/mipc-broker-integration-tests
NATIVE_ROUTER_INTEGRATION := $(BUILD_DIR)/native-router-integration-tests

.PHONY: all test test-unit test-integration test-lite test-lite-plan \
	lite-rss-test test-mipc mipc-rss-test install-lite clean

all: $(LIBRARY) $(NATIVE_LITE) $(MIPC_LIBRARY)

test: test-unit test-integration test-lite test-mipc

test-unit: $(UNIT_TEST)
	$(UNIT_TEST)

test-integration: $(INTEGRATION_TEST)
	$(INTEGRATION_TEST)

test-lite: $(NATIVE_LITE_UNIT) $(NATIVE_LITE_INTEGRATION) $(NATIVE_LITE_CHILD) $(NATIVE_LITE) test-lite-plan
	$(NATIVE_LITE_UNIT)
	$(NATIVE_LITE_INTEGRATION) $(abspath $(NATIVE_LITE)) $(abspath $(NATIVE_LITE_CHILD))

test-lite-plan:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) tests/test_plan_compiler.py -v

lite-rss-test: $(NATIVE_LITE_INTEGRATION) $(NATIVE_LITE_CHILD) $(NATIVE_LITE)
	$(NATIVE_LITE_INTEGRATION) $(abspath $(NATIVE_LITE)) $(abspath $(NATIVE_LITE_CHILD))

test-mipc: $(MIPC_UNIT) $(MIPC_INTEGRATION) $(NATIVE_ROUTER_INTEGRATION)
	$(MIPC_UNIT)
	$(MIPC_INTEGRATION)
	$(NATIVE_ROUTER_INTEGRATION)

mipc-rss-test: $(MIPC_INTEGRATION)
	$(MIPC_INTEGRATION)

$(LIBRARY): $(LIBRARY_OBJECTS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/%.o: src/%.cpp src/reactor_internal.hpp include/msys/reactor.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) -MMD -MP -c $< -o $@

$(UNIT_TEST): tests/reactor_unit.cpp $(LIBRARY) include/msys/reactor.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(LIBRARY) -o $@

$(INTEGRATION_TEST): tests/reactor_integration.cpp $(LIBRARY) include/msys/reactor.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(LIBRARY) -o $@

$(NATIVE_LITE_OBJECTS): $(BUILD_DIR)/%.o: src/%.cpp include/msys/native_lite.hpp include/msys/native_catalog.hpp include/msys/native_router.hpp include/msys/mipc_broker.hpp include/msys/reactor.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) -MMD -MP -c $< -o $@

$(NATIVE_LITE): src/native_lite_main.cpp $(NATIVE_LITE_OBJECTS) $(MIPC_LIBRARY) $(LIBRARY) include/msys/native_lite.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(NATIVE_LITE_OBJECTS) $(MIPC_LIBRARY) $(LIBRARY) -o $@

$(NATIVE_LITE_UNIT): tests/native_lite_unit.cpp $(BUILD_DIR)/native_lite_plan.o include/msys/native_lite.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(BUILD_DIR)/native_lite_plan.o -o $@

$(NATIVE_LITE_INTEGRATION): tests/native_lite_integration.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< -o $@

$(NATIVE_LITE_CHILD): tests/native_lite_child.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< -o $@

$(MIPC_OBJECTS): $(BUILD_DIR)/%.o: src/%.cpp include/msys/mipc_broker.hpp include/msys/reactor.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) -MMD -MP -c $< -o $@

$(MIPC_LIBRARY): $(MIPC_OBJECTS)
	$(AR) rcs $@ $^

$(MIPC_UNIT): tests/mipc_broker_unit.cpp $(BUILD_DIR)/mipc_json.o include/msys/mipc_broker.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(BUILD_DIR)/mipc_json.o -o $@

$(MIPC_INTEGRATION): tests/mipc_broker_integration.cpp $(MIPC_LIBRARY) $(LIBRARY) include/msys/mipc_broker.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(MIPC_LIBRARY) $(LIBRARY) -o $@

$(NATIVE_ROUTER_INTEGRATION): tests/native_router_integration.cpp $(BUILD_DIR)/native_catalog.o $(BUILD_DIR)/native_router.o $(MIPC_LIBRARY) $(LIBRARY) include/msys/native_router.hpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(STRICT_CXXFLAGS) $(THREAD_FLAGS) $< $(BUILD_DIR)/native_catalog.o $(BUILD_DIR)/native_router.o $(MIPC_LIBRARY) $(LIBRARY) -o $@

install-lite: $(NATIVE_LITE)
	$(INSTALL) -d "$(DESTDIR)$(PREFIX)/bin"
	$(INSTALL) -m 0755 $(NATIVE_LITE) "$(DESTDIR)$(PREFIX)/bin/msysd-native-lite"

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf -- $(BUILD_DIR)

-include $(LIBRARY_OBJECTS:.o=.d) $(NATIVE_LITE_OBJECTS:.o=.d) $(MIPC_OBJECTS:.o=.d)
