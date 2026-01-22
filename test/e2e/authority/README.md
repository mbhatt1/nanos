# Authority Kernel End-to-End Tests

This directory contains end-to-end tests that run actual agent programs inside the Authority Kernel via QEMU.

## Overview

The E2E tests verify that the Authority Kernel works correctly by:

1. **Building the kernel** - Compiles the full kernel with Authority Kernel features
2. **Building test agents** - Compiles minimal C test programs
3. **Creating disk images** - Packages the test program with the kernel
4. **Running in QEMU** - Boots the kernel and executes the test agent
5. **Verifying results** - Parses output for test pass/fail markers

## Quick Start

### Run E2E Tests Locally

```bash
# From the test/e2e/authority directory:
./run_e2e.sh

# Or from the project root:
./test/e2e/authority/run_e2e.sh

# With verbose output:
./run_e2e.sh --verbose

# Skip kernel build (use existing):
./run_e2e.sh --no-build

# Custom timeout:
./run_e2e.sh --timeout 180
```

### Prerequisites

**Required:**
- GCC (for building test programs)
- QEMU (`qemu-system-x86_64` or `qemu-system-aarch64`)
- nasm (for x86_64 kernel builds)
- GNU Make

**macOS:**
```bash
brew install nasm qemu gcc
```

**Ubuntu/Debian:**
```bash
sudo apt-get install build-essential nasm qemu-system-x86
```

## Test Structure

### Files

| File | Description |
|------|-------------|
| `test_basic.c` | Minimal C test agent that exercises core features |
| `test_policy.json` | Test policy for policy enforcement tests |
| `test_basic.manifest` | Nanos manifest template for the test program |
| `run_e2e.sh` | Main test runner script |
| `README.md` | This documentation |

### Test Cases

The `test_basic.c` program includes the following test cases:

| Test | Description |
|------|-------------|
| `basic_boot` | Verifies kernel boots and can execute code |
| `heap_operations` | Tests malloc/free, read/write to heap |
| `policy_allow` | Tests that allowed operations succeed |
| `policy_deny` | Tests that denied operations are blocked |
| `audit_logging` | Triggers operations that generate audit events |
| `environment` | Verifies environment variable access |
| `stack_operations` | Tests stack and recursion |

### Output Markers

The test program outputs structured markers for automated parsing:

```
[E2E] TEST_SUITE_START     - Test suite started
[TEST_START] name          - Individual test started
[TEST_PASS] name           - Test passed
[TEST_FAIL] name: reason   - Test failed with reason
[TEST_INFO] message        - Informational message
[E2E] TEST_SUITE_PASS      - All tests passed
[E2E] TEST_SUITE_FAIL      - Some tests failed
```

## GitHub Actions

The E2E tests run automatically on:
- Push to `master` branch
- Pull requests to `master`
- Manual workflow dispatch

See `.github/workflows/e2e-test.yml` for the CI configuration.

## Adding New Tests

### Adding a Test Case

1. Add a new test function to `test_basic.c`:

```c
static int test_my_feature(void)
{
    TEST_START("my_feature");

    // Test code here

    if (/* test passed */) {
        TEST_PASS("my_feature");
        return 0;
    } else {
        TEST_FAIL("my_feature", "reason for failure");
        return -1;
    }
}
```

2. Call the function from `main()`:

```c
test_my_feature();
```

### Adding a New Test Program

1. Create a new `.c` file (e.g., `test_network.c`)
2. Create a corresponding manifest (e.g., `test_network.manifest`)
3. Update `run_e2e.sh` to build and run the new test

## Troubleshooting

### QEMU Timeout

If tests timeout, try:
- Increase timeout: `./run_e2e.sh --timeout 300`
- Check if KVM/HVF is available for acceleration
- Verify the kernel boots by checking the log file

### Build Failures

**Cross-compilation issues:**
```bash
# Ensure cross-compiler is installed
brew install x86_64-elf-binutils x86_64-elf-gcc  # macOS
apt-get install gcc-x86-64-linux-gnu              # Linux (ARM host)
```

**Missing target-root:**
The cross-compilation requires system libraries. See `docs/getting-started/cross-compilation-setup.md`.

### No Test Output

If the test suite starts but produces no output:
1. Check `e2e_output.log` for kernel messages
2. Verify the test binary was built correctly: `file test_basic`
3. Try running QEMU manually to see boot messages

### Policy Enforcement Not Working

If policy tests pass when they should fail:
- The Authority Kernel policy enforcement may be in SOFT mode
- Check that `CONFIG_AK_ENABLED` is set during kernel build
- Verify the policy file is being loaded

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 124 | QEMU timed out |

## Related Documentation

- [Architecture: Authority Kernel](../../../docs/architecture/authority-kernel.md)
- [Security: Invariants](../../../docs/security/invariants.md)
- [Testing: Runtime Testing](../../../docs/testing/runtime-testing.md)
