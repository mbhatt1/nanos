#
# Authority Kernel - Integration Tests Makefile
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#
# Builds and runs AK integration tests:
#   - Host tests: Run on the build machine (unit-like tests)
#   - QEMU tests: Run in the Nanos unikernel (full integration)
#

include ../../vars.mk

# Integration test programs (run on host)
HOST_PROGRAMS = \
	ak_integration_test

# Integration test programs (run in QEMU)
QEMU_PROGRAMS = \
	ak_qemu_test

# Current directory
CURDIR := $(shell pwd)

# Source files for host integration tests
SRCS-ak_integration_test = \
	$(CURDIR)/ak_integration_test.c

# Strict warning flags for test code
# Use -isystem for runtime headers to suppress warnings from them
STRICT_WARN_FLAGS = -Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion \
                    -Wformat=2 -Wundef -Wpointer-arith -Wstrict-prototypes -Wvla

# Compiler flags for host tests
CFLAGS += -O2 -g $(STRICT_WARN_FLAGS)
CFLAGS += -isystem $(SRCDIR)/runtime \
          -isystem $(SRCDIR)/agentic \
          -isystem $(SRCDIR) \
          -I..

# Link flags for host tests
LDFLAGS-ak_integration_test = -static

# For cross-compilation to target
ifneq ($(CROSS_COMPILE),)
TARGET_ROOT = $(NANOS_TARGET_ROOT)
LDFLAGS += --sysroot=$(TARGET_ROOT)
ifeq ($(UNAME_s),Darwin)
ifeq ($(ARCH),x86_64)
LD = x86_64-elf-ld
else ifeq ($(ARCH),aarch64)
LD = aarch64-linux-ld
endif
endif
endif

# Object directory
OBJDIR_INT = $(OBJDIR)/test/integration

# Default target
all: host-tests

# Build host tests (can run on build machine)
host-tests: $(HOST_PROGRAMS)

# Build QEMU tests (run inside Nanos)
qemu-tests: $(QEMU_PROGRAMS)

# Run host tests
test: host-tests run-host-tests

# Run tests on host
run-host-tests: $(HOST_PROGRAMS)
	@echo "=== Running AK Integration Tests (Host) ==="
	@for prog in $(HOST_PROGRAMS); do \
		echo "Running $$prog..."; \
		./$$prog || exit 1; \
	done
	@echo "=== All host integration tests passed ==="

# Run individual test with filter
test-filter: host-tests
	@if [ -z "$(FILTER)" ]; then \
		echo "Usage: make test-filter FILTER=<pattern>"; \
		exit 1; \
	fi
	./ak_integration_test $(FILTER)

# Run tests in QEMU (requires nanos-run or equivalent)
run-qemu-tests: qemu-tests
	@echo "=== Running AK Integration Tests (QEMU) ==="
	@for prog in $(QEMU_PROGRAMS); do \
		echo "Running $$prog in QEMU..."; \
		$(NANOS_RUN) $$prog || exit 1; \
	done
	@echo "=== All QEMU integration tests passed ==="

# Clean build artifacts
clean:
	rm -f $(HOST_PROGRAMS) $(QEMU_PROGRAMS)
	rm -rf $(OBJDIR_INT)

# Pattern rule for host programs
# Simple build for host testing (minimal dependencies)
ak_integration_test: $(CURDIR)/ak_integration_test.c
	@echo "Building $@..."
	$(CC) $(CFLAGS) -o $@ $< -lm

# For building with full AK module linking (when available)
ak_integration_test_full: $(CURDIR)/ak_integration_test.c
	@echo "Building $@ with AK modules..."
	$(CC) $(CFLAGS) \
		-I$(SRCDIR)/agentic \
		-o $@ $< \
		$(SRCDIR)/agentic/ak_context.c \
		$(SRCDIR)/agentic/ak_effects.c \
		$(SRCDIR)/agentic/ak_posix_route.c \
		$(SRCDIR)/agentic/ak_policy_v2.c \
		$(SRCDIR)/agentic/ak_deny_ux.c \
		$(SRCDIR)/agentic/ak_agentic.c \
		-lm

# QEMU test program (links against full AK and runtime)
ak_qemu_test: $(CURDIR)/ak_integration_test.c
	@echo "Building $@ for QEMU..."
	$(CC) $(CFLAGS) $(LDFLAGS-ak_integration_test) \
		-I$(SRCDIR)/agentic \
		-DAK_QEMU_TEST \
		-o $@ $<

# Phony targets
.PHONY: all host-tests qemu-tests test run-host-tests run-qemu-tests clean test-filter

# Include common rules
-include ../../rules.mk

# Verbose output control
ifeq ($(V),1)
Q =
else
Q = @
endif

# Help target
help:
	@echo "AK Integration Tests Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all              - Build host integration tests (default)"
	@echo "  host-tests       - Build tests that run on host"
	@echo "  qemu-tests       - Build tests that run in QEMU"
	@echo "  test             - Build and run host tests"
	@echo "  test-filter      - Run tests matching FILTER pattern"
	@echo "                     Example: make test-filter FILTER=fs"
	@echo "  run-host-tests   - Run host tests"
	@echo "  run-qemu-tests   - Run tests in QEMU"
	@echo "  clean            - Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  V=1              - Verbose output"
	@echo "  FILTER=<pattern> - Filter tests by name pattern"
	@echo ""
	@echo "Test Categories:"
	@echo "  deny_by_default  - Deny-by-default enforcement"
	@echo "  fs               - Filesystem routing and policy"
	@echo "  dns              - DNS resolution gating"
	@echo "  connect          - Network connection control"
	@echo "  tool             - Tool call authorization"
	@echo "  wasm             - WASM invocation control"
	@echo "  infer            - LLM inference authorization"
	@echo "  budget           - Budget/resource tracking"
	@echo "  mode             - Routing mode (OFF/SOFT/HARD)"
	@echo "  boot_capsule     - Boot capsule transitions"
	@echo "  suggestion       - Policy suggestion generation"
