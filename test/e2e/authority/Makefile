#
# Authority Kernel E2E Tests Makefile
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#

# Include project variables if available
-include ../../../vars.mk

# Configuration
CURDIR := $(shell pwd)
PROJECT_ROOT := $(CURDIR)/../../..
OUTPUT_DIR := $(PROJECT_ROOT)/output
PLATFORM ?= pc

# Paths
KERNEL_IMG := $(OUTPUT_DIR)/platform/$(PLATFORM)/bin/kernel.img
BOOT_IMG := $(OUTPUT_DIR)/platform/$(PLATFORM)/boot/boot.img
MKFS_TOOL := $(OUTPUT_DIR)/tools/bin/mkfs

# Test binaries
TEST_BASIC := $(CURDIR)/test_basic
TEST_IMAGE := $(CURDIR)/test_e2e.img
TEST_MANIFEST := $(CURDIR)/test_e2e.manifest
LOG_FILE := $(CURDIR)/e2e_output.log

# Compiler settings
CC ?= gcc
CFLAGS := -O2 -Wall -Wextra
LDFLAGS := -static

# Cross-compilation support
ifneq ($(CROSS_COMPILE),)
CC := $(CROSS_COMPILE)gcc
endif

# QEMU settings
QEMU := qemu-system-x86_64
QEMU_TIMEOUT ?= 120
QEMU_MEMORY ?= 512M

# Detect OS for acceleration
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
QEMU_ACCEL := -accel hvf -cpu host,-rdtscp
else
QEMU_ACCEL := -enable-kvm -cpu host
endif

QEMU_ARGS := \
	-machine q35 \
	-m $(QEMU_MEMORY) \
	-display none \
	-serial stdio \
	-drive if=none,id=hd0,format=raw,file=$(TEST_IMAGE) \
	-device virtio-scsi-pci,id=scsi0 \
	-device scsi-hd,bus=scsi0.0,drive=hd0 \
	-device isa-debug-exit \
	-no-reboot

# Default target
all: test

# Build test program
$(TEST_BASIC): test_basic.c
	@echo "=== Building E2E test program ==="
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@file $@

# Generate manifest
$(TEST_MANIFEST): $(TEST_BASIC) test_policy.json
	@echo "=== Generating manifest ==="
	@cat > $@ << 'MANIFEST'
(
    children:(
        test_basic:(contents:(host:$(TEST_BASIC)))
        policy.json:(contents:(host:$(CURDIR)/test_policy.json))
        tmp:(children:())
        proc:(children:(
            self:(children:(
                status:(contents:"Name:\ttest_basic\nState:\tR (running)\n")
            ))
        ))
    )
    program:/test_basic
    debug_exit:t
    fault:t
    arguments:[test_basic e2e_test]
    environment:(USER:e2e_test PWD:/)
)
MANIFEST

# Create disk image
$(TEST_IMAGE): $(TEST_BASIC) $(TEST_MANIFEST) $(KERNEL_IMG) $(BOOT_IMG)
	@echo "=== Creating disk image ==="
	@if [ ! -f $(MKFS_TOOL) ]; then \
		echo "Error: mkfs tool not found at $(MKFS_TOOL)"; \
		echo "Run 'make tools' from project root first."; \
		exit 1; \
	fi
	@if [ ! -f $(KERNEL_IMG) ]; then \
		echo "Error: kernel not found at $(KERNEL_IMG)"; \
		echo "Run 'make PLATFORM=$(PLATFORM)' from project root first."; \
		exit 1; \
	fi
	$(MKFS_TOOL) -b $(BOOT_IMG) -k $(KERNEL_IMG) $@ < $(TEST_MANIFEST)
	@ls -lh $@

# Build everything
build: $(TEST_IMAGE)

# Run tests in QEMU
run: $(TEST_IMAGE)
	@echo "=== Running E2E tests in QEMU ==="
	@echo "Timeout: $(QEMU_TIMEOUT)s"
	@rm -f $(LOG_FILE)
	@timeout $(QEMU_TIMEOUT) $(QEMU) $(QEMU_ARGS) $(QEMU_ACCEL) 2>&1 | tee $(LOG_FILE) || true
	@echo ""
	@echo "=== Test output saved to $(LOG_FILE) ==="

# Run without acceleration (slower but more compatible)
run-noaccel: $(TEST_IMAGE)
	@echo "=== Running E2E tests in QEMU (no acceleration) ==="
	@rm -f $(LOG_FILE)
	@timeout $(QEMU_TIMEOUT) $(QEMU) $(QEMU_ARGS) -cpu max 2>&1 | tee $(LOG_FILE) || true

# Run and analyze results
test: run analyze

# Analyze test results
analyze:
	@echo "=== Analyzing E2E test results ==="
	@if [ ! -f $(LOG_FILE) ]; then \
		echo "Error: No log file found"; \
		exit 1; \
	fi
	@PASSED=$$(grep -c '\[TEST_PASS\]' $(LOG_FILE) 2>/dev/null || echo 0); \
	FAILED=$$(grep -c '\[TEST_FAIL\]' $(LOG_FILE) 2>/dev/null || echo 0); \
	echo "Tests passed: $$PASSED"; \
	echo "Tests failed: $$FAILED"; \
	if grep -q '\[E2E\] TEST_SUITE_PASS' $(LOG_FILE); then \
		echo ""; \
		echo "=== E2E Tests PASSED ==="; \
		exit 0; \
	elif grep -q '\[E2E\] TEST_SUITE_FAIL' $(LOG_FILE); then \
		echo ""; \
		echo "=== E2E Tests FAILED ==="; \
		grep '\[TEST_FAIL\]' $(LOG_FILE) || true; \
		exit 1; \
	elif grep -q '\[E2E\] TEST_SUITE_START' $(LOG_FILE); then \
		if [ "$$FAILED" -eq 0 ] && [ "$$PASSED" -gt 0 ]; then \
			echo "All completed tests passed"; \
			exit 0; \
		fi; \
		exit 1; \
	else \
		echo "=== E2E Tests did not start ==="; \
		exit 1; \
	fi

# Run using the shell script
test-script:
	./run_e2e.sh

# Clean build artifacts
clean:
	rm -f $(TEST_BASIC) $(TEST_IMAGE) $(TEST_MANIFEST) $(LOG_FILE)

# Help
help:
	@echo "Authority Kernel E2E Tests"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build and run tests (default)"
	@echo "  build         - Build test binary and disk image"
	@echo "  test          - Run tests and analyze results"
	@echo "  run           - Run tests in QEMU"
	@echo "  run-noaccel   - Run tests without hardware acceleration"
	@echo "  analyze       - Analyze test results from log file"
	@echo "  test-script   - Run tests using shell script"
	@echo "  clean         - Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  PLATFORM      - Target platform (default: pc)"
	@echo "  QEMU_TIMEOUT  - QEMU timeout in seconds (default: 120)"
	@echo "  QEMU_MEMORY   - QEMU memory allocation (default: 512M)"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Kernel must be built: make PLATFORM=$(PLATFORM)"
	@echo "  - QEMU must be installed: qemu-system-x86_64"

.PHONY: all build test run run-noaccel analyze test-script clean help
