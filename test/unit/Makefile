include ../../vars.mk

override ARCH=$(HOST_ARCH)
override CROSS_COMPILE=
ifeq ($(shell uname -s),Darwin)
override CC=cc
# Darwin doesn't have epoll - define early for all targets including sanitizers
PLATFORM_FLAGS=	-DNO_EPOLL
endif

PROGRAMS= \
	ak_approval_test \
	ak_audit_test \
	ak_capability_test \
	ak_crypto_test \
	ak_effects_test \
	ak_ipc_test \
	ak_multiprocess_test \
	ak_negative_test \
	ak_pattern_test \
	ak_policy_test \
	ak_state_test \
	ak_syscall_test \
	ak_wasm_test \
	bitmap_test \
	buffer_test \
	closure_test \
	id_heap_test \
	memops_test \
	network_test \
	objcache_test \
	pageheap_test \
	parser_test \
	pqueue_test \
	queue_test \
	range_test \
	random_test \
	rbtree_test \
	table_test \
	tuple_test \
	udp_test \
	vector_test
SKIP_TEST=	network_test udp_test

# Authority Kernel unit tests
# These tests run on the host without booting the unikernel

SRCS-ak_effects_test= \
	$(CURDIR)/ak_effects_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

# Negative/edge case tests - standalone, no runtime dependencies
SRCS-ak_negative_test= \
	$(CURDIR)/ak_negative_test.c

SRCS-ak_pattern_test= \
	$(CURDIR)/ak_pattern_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-ak_policy_test= \
	$(CURDIR)/ak_policy_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-bitmap_test= \
	$(CURDIR)/bitmap_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-buffer_test= \
	$(CURDIR)/buffer_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-closure_test= \
	$(CURDIR)/closure_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-id_heap_test= \
	$(CURDIR)/id_heap_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-memops_test= \
	$(CURDIR)/memops_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-network_test= \
	$(CURDIR)/network_test.c \
	$(SRCDIR)/http/http.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c

SRCS-objcache_test= \
	$(CURDIR)/objcache_test.c \
	$(RUNTIME)\
	$(SRCDIR)/runtime/heap/objcache.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c

SRCS-pageheap_test= \
	$(CURDIR)/pageheap_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-parser_test= \
	$(CURDIR)/parser_test.c \
	$(SRCDIR)/runtime/tuple_parser.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-pqueue_test= \
	$(CURDIR)/pqueue_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-queue_test= \
	$(CURDIR)/queue_test.c \
	$(RUNTIME)\
	$(SRCDIR)/runtime/queue.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

LIBS-queue_test=	-lpthread

SRCS-range_test= \
	$(CURDIR)/range_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-random_test = \
	$(CURDIR)/random_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-rbtree_test= \
	$(CURDIR)/rbtree_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-table_test= \
	$(CURDIR)/table_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c

SRCS-tuple_test= \
	$(CURDIR)/tuple_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-udp_test= \
	$(CURDIR)/udp_test.c \
	$(SRCDIR)/http/http.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c \
	$(SRCDIR)/unix_process/mmap_heap.c \
	$(SRCDIR)/unix_process/socket_user.c \
	$(SRCDIR)/unix_process/tiny_heap.c

SRCS-vector_test= \
	$(CURDIR)/vector_test.c \
	$(RUNTIME)\
	$(SRCDIR)/unix_process/unix_process_runtime.c


# Standard includes for runtime sources (non-test files)
CFLAGS+=	-O3 \
		-I$(ARCHDIR) \
		-I$(SRCDIR) \
		-I$(SRCDIR)/http \
		-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/unix_process \
		-I$(SRCDIR)/unix
#CFLAGS+=	-DENABLE_MSG_DEBUG -DID_HEAP_DEBUG

# Strict warning flags for test source files only (applied per-file)
# These flags catch bugs in test code without breaking on runtime headers
# We use -isystem to treat runtime headers as system headers (suppresses warnings from them)
STRICT_WARN_FLAGS= -Wall -Wextra -Werror -Wshadow -Wconversion -Wsign-conversion \
		   -Wformat=2 -Wundef -Wpointer-arith -Wstrict-prototypes -Wvla

# System include flags to suppress warnings from runtime headers in test files
SYSTEM_INCLUDES= -isystem $(ARCHDIR) -isystem $(SRCDIR) -isystem $(SRCDIR)/http \
		 -isystem $(SRCDIR)/runtime -isystem $(SRCDIR)/unix_process -isystem $(SRCDIR)/unix

# Combined flags for test files: suppress runtime header warnings + strict warnings for test code
TEST_CFLAGS= $(SYSTEM_INCLUDES) $(STRICT_WARN_FLAGS)

# Apply strict warnings to test source files
CFLAGS-ak_effects_test.c=	$(TEST_CFLAGS)
CFLAGS-ak_negative_test.c=	$(TEST_CFLAGS)
CFLAGS-ak_pattern_test.c=	$(TEST_CFLAGS)
CFLAGS-ak_policy_test.c=	$(TEST_CFLAGS)
CFLAGS-bitmap_test.c=		$(TEST_CFLAGS)
CFLAGS-buffer_test.c=		$(TEST_CFLAGS)
CFLAGS-closure_test.c=		$(TEST_CFLAGS)
CFLAGS-id_heap_test.c=		$(TEST_CFLAGS)
CFLAGS-memops_test.c=		$(TEST_CFLAGS)
CFLAGS-network_test.c=		$(TEST_CFLAGS)
CFLAGS-objcache_test.c=		$(TEST_CFLAGS)
CFLAGS-pageheap_test.c=		$(TEST_CFLAGS)
CFLAGS-parser_test.c=		$(TEST_CFLAGS)
CFLAGS-pqueue_test.c=		$(TEST_CFLAGS)
CFLAGS-queue_test.c=		$(TEST_CFLAGS)
CFLAGS-range_test.c=		$(TEST_CFLAGS)
CFLAGS-random_test.c=		$(TEST_CFLAGS)
CFLAGS-rbtree_test.c=		$(TEST_CFLAGS)
CFLAGS-table_test.c=		$(TEST_CFLAGS)
CFLAGS-tuple_test.c=		$(TEST_CFLAGS)
CFLAGS-udp_test.c=		$(TEST_CFLAGS)
CFLAGS-vector_test.c=		$(TEST_CFLAGS)

CLEANDIRS+=	$(OBJDIR)/test

# gcov support (can be disabled for sanitizer builds via DISABLE_GCOV=1)
ifndef DISABLE_GCOV
CFLAGS+=	-fprofile-arcs -ftest-coverage
LDFLAGS+=	-fprofile-arcs
endif

# Extra flags for sanitizer builds (passed from sanitizer targets)
CFLAGS+=	$(EXTRA_CFLAGS)
LDFLAGS+=	$(EXTRA_LDFLAGS)
GCDAFILES=	$(sort $(foreach p,$(PROGRAMS),$(patsubst %.o,%.gcda,$(OBJS-$p))))
GCOVFILES=	$(sort $(foreach p,$(PROGRAMS),$(patsubst %.o,%.gcno,$(OBJS-$p))))
GCOVFILES+=	$(GCDAFILES) $(OBJDIR)/gcov-tests.info
CLEANFILES+=	$(GCOVFILES)

all: $(PROGRAMS)

.PHONY: test gcov gcov-clean

test: all
	$(Q) $(RM) $(GCDAFILES)
	$(foreach p,$(filter-out $(SKIP_TEST),$(PROGRAMS)),$(call execute_command,$(PROG-$p)))

gcov: test
	$(foreach p,$(PROGRAMS),$(call execute_command,$(GCOV) -o $(OBJDIR)/test/unit $(PROG-$p)))
	$(LCOV) --capture --directory $(ROOTDIR) --output-file $(OBJDIR)/gcov-tests.info
	$(MKDIR) $(OBJDIR)/gcov
	$(GENHTML) $(OBJDIR)/gcov-tests.info --output-directory $(OBJDIR)/gcov

pre-clean:
	$(Q) $(RM) -r $(OBJDIR)/gcov

gcov-clean:
	$(Q) $(RM) $(GCOVFILES)

# Sanitizer targets for host tests
# These require clang and are useful for catching memory errors, undefined behavior, and data races
# We use recursive make to pass sanitizer flags cleanly through the build system

.PHONY: asan tsan msan sanitizer-clean

# AddressSanitizer + UndefinedBehaviorSanitizer
# Detects: buffer overflows, use-after-free, memory leaks, undefined behavior
asan:
	$(Q) $(MAKE) clean
	$(Q) $(MAKE) test \
		EXTRA_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1" \
		EXTRA_LDFLAGS="-fsanitize=address,undefined" \
		DISABLE_GCOV=1 \
		TEST_CFLAGS=

# ThreadSanitizer
# Detects: data races, deadlocks
tsan:
	$(Q) $(MAKE) clean
	$(Q) $(MAKE) test \
		EXTRA_CFLAGS="-fsanitize=thread -g -O1" \
		EXTRA_LDFLAGS="-fsanitize=thread" \
		DISABLE_GCOV=1 \
		TEST_CFLAGS=

# MemorySanitizer (Linux only, requires instrumented libc)
# Detects: uninitialized memory reads
msan:
	$(Q) $(MAKE) clean
	$(Q) $(MAKE) test \
		EXTRA_CFLAGS="-fsanitize=memory -fno-omit-frame-pointer -g -O1" \
		EXTRA_LDFLAGS="-fsanitize=memory" \
		DISABLE_GCOV=1 \
		TEST_CFLAGS=

sanitizer-clean:
	$(Q) $(MAKE) clean

include ../../rules.mk

# Add platform-specific flags to CFLAGS (defined early for Darwin)
CFLAGS+=	$(PLATFORM_FLAGS)
