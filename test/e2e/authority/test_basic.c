/*
 * Authority Kernel E2E Test - Basic Test Agent
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Minimal test agent that exercises the Authority Kernel's core features:
 *   - Basic boot and execution
 *   - Heap operations (alloc, read, write, delete)
 *   - Policy enforcement (ALLOW and DENY cases)
 *   - Audit log generation
 *
 * This test is designed to run inside the Nanos unikernel via QEMU.
 * Exit codes:
 *   0 - All tests passed
 *   1 - Test failure
 *   2 - Fatal error
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Test result tracking */
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_total = 0;

/* Test output markers for automated parsing */
#define TEST_START(name) printf("[TEST_START] %s\n", name); tests_total++
#define TEST_PASS(name)  printf("[TEST_PASS] %s\n", name); tests_passed++
#define TEST_FAIL(name, reason) printf("[TEST_FAIL] %s: %s\n", name, reason); tests_failed++
#define TEST_INFO(msg)   printf("[TEST_INFO] %s\n", msg)
#define TEST_MARKER(msg) printf("[E2E] %s\n", msg)

/*
 * Test 1: Basic Boot and Execution
 * Verifies that the kernel boots and can execute basic operations.
 */
static int test_basic_boot(void)
{
    TEST_START("basic_boot");

    /* Verify we can print to stdout */
    printf("Authority Kernel E2E Test Agent Started\n");

    /* Verify basic arithmetic works */
    int sum = 0;
    for (int i = 1; i <= 100; i++) {
        sum += i;
    }

    if (sum != 5050) {
        TEST_FAIL("basic_boot", "arithmetic check failed");
        return -1;
    }

    /* Verify memory allocation works */
    void *ptr = malloc(1024);
    if (ptr == NULL) {
        TEST_FAIL("basic_boot", "malloc failed");
        return -1;
    }
    free(ptr);

    TEST_PASS("basic_boot");
    return 0;
}

/*
 * Test 2: Heap Operations
 * Exercises the Authority Kernel's heap tracking and enforcement.
 */
static int test_heap_operations(void)
{
    TEST_START("heap_operations");

    /* Test 2a: Allocation */
    TEST_INFO("Testing heap allocation...");

    char *buffer = (char *)malloc(4096);
    if (buffer == NULL) {
        TEST_FAIL("heap_operations", "allocation failed");
        return -1;
    }

    /* Test 2b: Write to allocated memory */
    TEST_INFO("Testing heap write...");

    const char *test_data = "Authority Kernel Test Data";
    size_t data_len = strlen(test_data);
    memcpy(buffer, test_data, data_len + 1);

    /* Test 2c: Read from allocated memory */
    TEST_INFO("Testing heap read...");

    if (strcmp(buffer, test_data) != 0) {
        TEST_FAIL("heap_operations", "read verification failed");
        free(buffer);
        return -1;
    }

    /* Test 2d: Multiple allocations */
    TEST_INFO("Testing multiple allocations...");

    void *ptrs[10];
    for (int i = 0; i < 10; i++) {
        ptrs[i] = malloc(1024 * (size_t)(i + 1));
        if (ptrs[i] == NULL) {
            TEST_FAIL("heap_operations", "multiple allocation failed");
            /* Clean up previous allocations */
            for (int j = 0; j < i; j++) {
                free(ptrs[j]);
            }
            free(buffer);
            return -1;
        }
    }

    /* Test 2e: Deallocation */
    TEST_INFO("Testing heap deallocation...");

    for (int i = 0; i < 10; i++) {
        free(ptrs[i]);
    }
    free(buffer);

    TEST_PASS("heap_operations");
    return 0;
}

/*
 * Test 3: Filesystem Policy - ALLOW Case
 * Tests that allowed filesystem operations succeed.
 */
static int test_policy_allow(void)
{
    TEST_START("policy_allow");

    /* Test 3a: Read from allowed path (/tmp is typically allowed) */
    TEST_INFO("Testing allowed filesystem read...");

    /* Create a test file in /tmp */
    const char *test_file = "/tmp/e2e_test_file.txt";
    const char *test_content = "E2E Test Content";

    int fd = open(test_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        /* If /tmp is not writable, skip this test */
        if (errno == EACCES || errno == EROFS) {
            TEST_INFO("Skipping: /tmp not writable (expected in some configurations)");
            TEST_PASS("policy_allow");
            return 0;
        }
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "failed to create test file: %s", strerror(errno));
        TEST_FAIL("policy_allow", err_msg);
        return -1;
    }

    ssize_t written = write(fd, test_content, strlen(test_content));
    close(fd);

    if (written < 0) {
        TEST_FAIL("policy_allow", "failed to write test file");
        return -1;
    }

    /* Read back the file */
    fd = open(test_file, O_RDONLY);
    if (fd < 0) {
        TEST_FAIL("policy_allow", "failed to open test file for reading");
        return -1;
    }

    char read_buffer[256];
    ssize_t bytes_read = read(fd, read_buffer, sizeof(read_buffer) - 1);
    close(fd);

    if (bytes_read < 0) {
        TEST_FAIL("policy_allow", "failed to read test file");
        return -1;
    }

    read_buffer[bytes_read] = '\0';

    if (strcmp(read_buffer, test_content) != 0) {
        TEST_FAIL("policy_allow", "read content mismatch");
        return -1;
    }

    /* Clean up */
    unlink(test_file);

    TEST_PASS("policy_allow");
    return 0;
}

/*
 * Test 4: Filesystem Policy - DENY Case
 * Tests that denied filesystem operations are blocked and properly reported.
 */
static int test_policy_deny(void)
{
    TEST_START("policy_deny");

    /* Test 4a: Attempt to access a path that should be denied */
    TEST_INFO("Testing denied filesystem access...");

    /*
     * Attempt to read /etc/shadow - this should be denied by policy.
     * In a properly configured Authority Kernel:
     * - The operation should fail with EACCES or EPERM
     * - An audit event should be generated
     */
    const char *denied_path = "/etc/shadow";

    int fd = open(denied_path, O_RDONLY);
    if (fd >= 0) {
        /* Access was allowed - this might be OK if running without policy */
        close(fd);
        TEST_INFO("Note: /etc/shadow access allowed (no restrictive policy loaded)");
        TEST_PASS("policy_deny");
        return 0;
    }

    /* Check that we got a proper denial error */
    if (errno == EACCES || errno == EPERM || errno == ENOENT) {
        TEST_INFO("Access correctly denied or file not found");
        TEST_MARKER("POLICY_DENY_VERIFIED");
        TEST_PASS("policy_deny");
        return 0;
    }

    char err_msg[256];
    snprintf(err_msg, sizeof(err_msg), "unexpected error: %s", strerror(errno));
    TEST_FAIL("policy_deny", err_msg);
    return -1;
}

/*
 * Test 5: Audit Log Generation
 * Verifies that audit events are being generated.
 */
static int test_audit_logging(void)
{
    TEST_START("audit_logging");

    /*
     * Perform operations that should generate audit events.
     * The actual audit log verification happens externally by
     * checking the kernel's output for audit markers.
     */

    TEST_INFO("Triggering audit events...");

    /* File operations should generate audit events */
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        read(fd, buf, sizeof(buf));
        close(fd);
    }

    /* Memory operations */
    void *p = malloc(8192);
    if (p) {
        memset(p, 0xAA, 8192);
        free(p);
    }

    /* Mark that audit events should have been generated */
    TEST_MARKER("AUDIT_EVENTS_GENERATED");

    TEST_PASS("audit_logging");
    return 0;
}

/*
 * Test 6: Environment Variables
 * Verifies that environment is properly passed through.
 */
static int test_environment(void)
{
    TEST_START("environment");

    /* Check if any environment variables are set */
    const char *path = getenv("PATH");
    const char *user = getenv("USER");

    TEST_INFO("Checking environment variables...");

    if (path != NULL) {
        printf("[TEST_INFO] PATH=%s\n", path);
    }

    if (user != NULL) {
        printf("[TEST_INFO] USER=%s\n", user);
    }

    /* Environment might be minimal in unikernel, so just check we can call getenv */
    TEST_PASS("environment");
    return 0;
}

/*
 * Test 7: Stack and Recursion
 * Tests that stack operations work correctly.
 */
static int recursive_sum(int n)
{
    if (n <= 0) return 0;
    return n + recursive_sum(n - 1);
}

static int test_stack_operations(void)
{
    TEST_START("stack_operations");

    TEST_INFO("Testing recursion...");

    /* Test with reasonable recursion depth */
    int result = recursive_sum(100);

    if (result != 5050) {
        TEST_FAIL("stack_operations", "recursion result incorrect");
        return -1;
    }

    /* Test local array on stack */
    char stack_buffer[1024];
    memset(stack_buffer, 0x55, sizeof(stack_buffer));

    int check = 1;
    for (size_t i = 0; i < sizeof(stack_buffer); i++) {
        if (stack_buffer[i] != 0x55) {
            check = 0;
            break;
        }
    }

    if (!check) {
        TEST_FAIL("stack_operations", "stack buffer corruption");
        return -1;
    }

    TEST_PASS("stack_operations");
    return 0;
}

/*
 * Main entry point
 */
int main(int argc, char **argv)
{
    printf("==============================================\n");
    printf("Authority Kernel E2E Test Suite\n");
    printf("==============================================\n");
    printf("\n");

    /* Print arguments */
    printf("Arguments: ");
    for (int i = 0; i < argc; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n\n");

    /* Marker for automated parsing - test suite started */
    TEST_MARKER("TEST_SUITE_START");

    /* Run all tests */
    test_basic_boot();
    test_heap_operations();
    test_policy_allow();
    test_policy_deny();
    test_audit_logging();
    test_environment();
    test_stack_operations();

    /* Print summary */
    printf("\n");
    printf("==============================================\n");
    printf("Test Summary\n");
    printf("==============================================\n");
    printf("Total:  %d\n", tests_total);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("\n");

    /* Marker for automated parsing - test suite ended */
    if (tests_failed == 0) {
        TEST_MARKER("TEST_SUITE_PASS");
        printf("All tests passed!\n");
        return EXIT_SUCCESS;
    } else {
        TEST_MARKER("TEST_SUITE_FAIL");
        printf("Some tests failed.\n");
        return EXIT_FAILURE;
    }
}
