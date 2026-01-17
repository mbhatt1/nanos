# Authority Kernel - Fuzz Testing Makefile
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Authority Systems
#
# This Makefile builds fuzz targets for parser/decoder boundaries.
# Requires: clang with libFuzzer support
#
# Usage:
#   make                    - Build all fuzz targets
#   make fuzz_json_parser   - Build JSON parser fuzzer
#   make run                - Run all fuzzers with default settings
#   make run-json           - Run JSON parser fuzzer
#   make clean              - Remove build artifacts
#   make corpus             - Generate initial corpus

# Compiler settings
CC ?= clang
CFLAGS = -Wall -Wextra -Werror -g -O1

# Fuzzer-specific flags
FUZZ_FLAGS = -fsanitize=fuzzer,address,undefined
FUZZ_FLAGS += -fno-omit-frame-pointer
FUZZ_FLAGS += -fno-optimize-sibling-calls

# Include paths for kernel headers (when linking against real code)
INCLUDES = -I../../src -I../../src/agentic -I../../src/runtime

# Default timeout for fuzzing (seconds)
FUZZ_TIMEOUT ?= 60

# Maximum total time for all fuzzers (seconds)
MAX_TOTAL_TIME ?= 300

# Corpus directories
CORPUS_JSON = corpus/json
CORPUS_PATTERN = corpus/pattern
CORPUS_PATH = corpus/path

# Fuzz targets
TARGETS = fuzz_json_parser fuzz_pattern_match fuzz_path_canonicalize

# Default target: build all
.PHONY: all
all: $(TARGETS)

# Build fuzz_json_parser
fuzz_json_parser: fuzz_json_parser.c
	$(CC) $(CFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

# Build fuzz_pattern_match
fuzz_pattern_match: fuzz_pattern_match.c
	$(CC) $(CFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

# Build fuzz_path_canonicalize
fuzz_path_canonicalize: fuzz_path_canonicalize.c
	$(CC) $(CFLAGS) $(FUZZ_FLAGS) $(INCLUDES) $< -o $@

# Build standalone (non-fuzzer) versions for debugging
.PHONY: standalone
standalone: fuzz_json_parser_standalone fuzz_pattern_match_standalone fuzz_path_canonicalize_standalone

fuzz_json_parser_standalone: fuzz_json_parser.c
	$(CC) $(CFLAGS) -DFUZZ_STANDALONE $(INCLUDES) $< -o $@

fuzz_pattern_match_standalone: fuzz_pattern_match.c
	$(CC) $(CFLAGS) -DFUZZ_STANDALONE $(INCLUDES) $< -o $@

fuzz_path_canonicalize_standalone: fuzz_path_canonicalize.c
	$(CC) $(CFLAGS) -DFUZZ_STANDALONE $(INCLUDES) $< -o $@

# Create corpus directories
.PHONY: corpus-dirs
corpus-dirs:
	@mkdir -p $(CORPUS_JSON)
	@mkdir -p $(CORPUS_PATTERN)
	@mkdir -p $(CORPUS_PATH)

# Generate initial corpus
.PHONY: corpus
corpus: corpus-dirs
	@echo "Generating initial corpus..."
	@# JSON corpus - valid policies
	@echo '{}' > $(CORPUS_JSON)/empty.json
	@echo '{"version":"1.0"}' > $(CORPUS_JSON)/version.json
	@echo '{"fs":{"read":["/tmp/**"]}}' > $(CORPUS_JSON)/fs_read.json
	@echo '{"fs":{"write":["/data/**"]}}' > $(CORPUS_JSON)/fs_write.json
	@echo '{"net":{"dns":["*.example.com"]}}' > $(CORPUS_JSON)/net_dns.json
	@echo '{"net":{"connect":["ip:*:443"]}}' > $(CORPUS_JSON)/net_connect.json
	@echo '{"tools":{"allow":["bash","python"]}}' > $(CORPUS_JSON)/tools_allow.json
	@echo '{"tools":{"deny":["rm","dd"]}}' > $(CORPUS_JSON)/tools_deny.json
	@echo '{"budgets":{"tool_calls":100,"tokens":50000}}' > $(CORPUS_JSON)/budgets.json
	@echo '{"fs":{"read":["/etc/**","/lib/**"]},"net":{"dns":["*"]}}' > $(CORPUS_JSON)/combined.json
	@# JSON corpus - edge cases
	@echo '{"fs":{"read":[]}}' > $(CORPUS_JSON)/empty_array.json
	@echo '{"unknown_key":"value"}' > $(CORPUS_JSON)/unknown_key.json
	@printf '{"fs":{"read":["/%s"]}}' "$$(printf 'a%.0s' {1..200})" > $(CORPUS_JSON)/long_path.json
	@# Pattern corpus - valid patterns
	@printf '\x10*\x00foo' > $(CORPUS_PATTERN)/star_foo.bin
	@printf '\x08*.txt\x00test.txt' > $(CORPUS_PATTERN)/glob_txt.bin
	@printf '\x10/home/**\x00/home/user/file' > $(CORPUS_PATTERN)/doublestar.bin
	@printf '\x08*.com\x00example.com' > $(CORPUS_PATTERN)/dns_wildcard.bin
	@printf '\x10/tmp/?\x00/tmp/a' > $(CORPUS_PATTERN)/question_mark.bin
	@# Path corpus
	@printf '\x00/etc/passwd' > $(CORPUS_PATH)/absolute.bin
	@printf '\x01../../../etc/passwd' > $(CORPUS_PATH)/traversal.bin
	@printf '\x00/home/user/./file' > $(CORPUS_PATH)/dot.bin
	@printf '\x00/home/../etc/passwd' > $(CORPUS_PATH)/dotdot.bin
	@printf '\x00/path//double//slash' > $(CORPUS_PATH)/doubleslash.bin
	@printf '\x02' > $(CORPUS_PATH)/sockaddr_ipv4.bin
	@printf '\x00\x00\x00\x50\x7f\x00\x00\x01' >> $(CORPUS_PATH)/sockaddr_ipv4.bin
	@echo "Corpus generated."

# Run all fuzzers
.PHONY: run
run: all corpus
	@echo "Running all fuzzers ($(MAX_TOTAL_TIME)s total)..."
	@./fuzz_json_parser $(CORPUS_JSON) -max_total_time=$$(( $(MAX_TOTAL_TIME) / 3 )) &
	@./fuzz_pattern_match $(CORPUS_PATTERN) -max_total_time=$$(( $(MAX_TOTAL_TIME) / 3 )) &
	@./fuzz_path_canonicalize $(CORPUS_PATH) -max_total_time=$$(( $(MAX_TOTAL_TIME) / 3 )) &
	@wait
	@echo "All fuzzers completed."

# Run individual fuzzers
.PHONY: run-json
run-json: fuzz_json_parser corpus
	./fuzz_json_parser $(CORPUS_JSON) -max_total_time=$(FUZZ_TIMEOUT)

.PHONY: run-pattern
run-pattern: fuzz_pattern_match corpus
	./fuzz_pattern_match $(CORPUS_PATTERN) -max_total_time=$(FUZZ_TIMEOUT)

.PHONY: run-path
run-path: fuzz_path_canonicalize corpus
	./fuzz_path_canonicalize $(CORPUS_PATH) -max_total_time=$(FUZZ_TIMEOUT)

# Run with coverage
.PHONY: coverage
coverage: FUZZ_FLAGS += -fprofile-instr-generate -fcoverage-mapping
coverage: clean all corpus
	@echo "Running fuzzers with coverage..."
	LLVM_PROFILE_FILE="fuzz_%p.profraw" ./fuzz_json_parser $(CORPUS_JSON) -max_total_time=30
	LLVM_PROFILE_FILE="fuzz_%p.profraw" ./fuzz_pattern_match $(CORPUS_PATTERN) -max_total_time=30
	LLVM_PROFILE_FILE="fuzz_%p.profraw" ./fuzz_path_canonicalize $(CORPUS_PATH) -max_total_time=30
	llvm-profdata merge -sparse fuzz_*.profraw -o fuzz.profdata
	llvm-cov show ./fuzz_json_parser -instr-profile=fuzz.profdata > coverage_json.txt
	llvm-cov show ./fuzz_pattern_match -instr-profile=fuzz.profdata > coverage_pattern.txt
	llvm-cov show ./fuzz_path_canonicalize -instr-profile=fuzz.profdata > coverage_path.txt
	@echo "Coverage reports generated: coverage_*.txt"

# Minimize corpus
.PHONY: minimize
minimize: all
	@echo "Minimizing corpus..."
	@mkdir -p corpus_min/json corpus_min/pattern corpus_min/path
	./fuzz_json_parser -merge=1 corpus_min/json $(CORPUS_JSON)
	./fuzz_pattern_match -merge=1 corpus_min/pattern $(CORPUS_PATTERN)
	./fuzz_path_canonicalize -merge=1 corpus_min/path $(CORPUS_PATH)
	@echo "Minimized corpus in corpus_min/"

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(TARGETS)
	rm -f *_standalone
	rm -f *.profraw *.profdata
	rm -f coverage_*.txt
	rm -rf crash-* leak-* timeout-*

# Clean everything including corpus
.PHONY: distclean
distclean: clean
	rm -rf corpus corpus_min

# Help
.PHONY: help
help:
	@echo "Authority Kernel Fuzz Testing"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all fuzz targets (default)"
	@echo "  standalone   - Build standalone debug versions"
	@echo "  corpus       - Generate initial seed corpus"
	@echo "  run          - Run all fuzzers in parallel"
	@echo "  run-json     - Run JSON parser fuzzer"
	@echo "  run-pattern  - Run pattern matcher fuzzer"
	@echo "  run-path     - Run path canonicalization fuzzer"
	@echo "  coverage     - Run with coverage and generate reports"
	@echo "  minimize     - Minimize corpus"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Remove everything including corpus"
	@echo ""
	@echo "Variables:"
	@echo "  CC=clang         Compiler (default: clang)"
	@echo "  FUZZ_TIMEOUT=60  Per-fuzzer timeout in seconds"
	@echo "  MAX_TOTAL_TIME=300  Total time for 'run' target"
	@echo ""
	@echo "Examples:"
	@echo "  make run FUZZ_TIMEOUT=120"
	@echo "  make run-json MAX_TOTAL_TIME=600"
	@echo "  ./fuzz_json_parser corpus/json/ -jobs=4"
