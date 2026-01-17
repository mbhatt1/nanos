# Authority Kernel - Build Configuration
#
# SPDX-License-Identifier: Apache-2.0
#
# This Makefile builds the Authority Kernel module for Nanos.
# It should be included from the main Nanos kernel.mk.

# Module name
AK_MODULE := agentic

# Source files
AK_SRCS := \
	ak_agentic.c \
	ak_capability.c \
	ak_audit.c \
	ak_context.c \
	ak_deny_ux.c \
	ak_ed25519.c \
	ak_effects.c \
	ak_heap.c \
	ak_inference.c \
	ak_ipc.c \
	ak_lz4.c \
	ak_nanos.c \
	ak_pattern.c \
	ak_policy.c \
	ak_policy_v2.c \
	ak_posix_route.c \
	ak_sanitize.c \
	ak_secrets.c \
	ak_state.c \
	ak_syscall.c \
	ak_wasm.c \
	ak_wasm_host.c \
	ak_approval.c

# Headers
AK_HDRS := \
	ak_types.h \
	ak_agentic.h \
	ak_approval.h \
	ak_audit.h \
	ak_capability.h \
	ak_compat.h \
	ak_compress.h \
	ak_context.h \
	ak_deny_ux.h \
	ak_ed25519.h \
	ak_effects.h \
	ak_heap.h \
	ak_inference.h \
	ak_ipc.h \
	ak_pattern.h \
	ak_policy.h \
	ak_policy_v2.h \
	ak_posix_route.h \
	ak_sanitize.h \
	ak_secrets.h \
	ak_state.h \
	ak_syscall.h \
	ak_wasm.h

# Object files
AK_OBJS := $(AK_SRCS:.c=.o)

# Compiler flags
AK_CFLAGS := \
	-I$(SRCDIR)/agentic \
	-I$(SRCDIR)/runtime \
	-I$(SRCDIR)/kernel \
	-DAK_DEBUG=$(DEBUG) \
	-DCONFIG_AK_ENABLED=1

# Security flags
AK_CFLAGS += \
	-fstack-protector-strong \
	-fno-strict-aliasing

# Optimization
ifeq ($(DEBUG),1)
AK_CFLAGS += -O0 -g -DAK_DEBUG=1
else
AK_CFLAGS += -O2 -DNDEBUG
endif

# Build rules
.PHONY: all clean

all: $(AK_OBJS)

%.o: %.c $(AK_HDRS)
	$(CC) $(CFLAGS) $(AK_CFLAGS) -c $< -o $@

clean:
	rm -f $(AK_OBJS)

# Dependencies
ak_agentic.o: ak_agentic.c ak_agentic.h ak_types.h ak_effects.h ak_wasm.h ak_inference.h ak_policy_v2.h ak_compat.h
ak_capability.o: ak_capability.c ak_capability.h ak_types.h
ak_audit.o: ak_audit.c ak_audit.h ak_types.h
ak_heap.o: ak_heap.c ak_heap.h ak_types.h ak_audit.h
ak_ipc.o: ak_ipc.c ak_ipc.h ak_types.h ak_capability.h
ak_policy.o: ak_policy.c ak_policy.h ak_types.h ak_capability.h
ak_syscall.o: ak_syscall.c ak_syscall.h ak_types.h ak_capability.h ak_audit.h ak_heap.h ak_policy.h ak_ipc.h
ak_nanos.o: ak_nanos.c ak_syscall.h
ak_posix_route.o: ak_posix_route.c ak_posix_route.h ak_effects.h ak_context.h ak_compat.h

# Integration with main kernel build
# Add the following to kernel.mk:
#
# KERNEL_SRCS += $(wildcard $(SRCDIR)/agentic/*.c)
# KERNEL_CFLAGS += -I$(SRCDIR)/agentic -DCONFIG_AK_ENABLED=1
