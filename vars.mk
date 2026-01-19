# paths
makefile_dir=	$(patsubst %/,%,$(dir $(abspath $(firstword $(filter $1, $(MAKEFILE_LIST))))))
CURDIR=		$(call makefile_dir, Makefile)
ROOTDIR=	$(call makefile_dir, %vars.mk)
SRCDIR=		$(ROOTDIR)/src
OUTDIR=		$(ROOTDIR)/output
OBJDIR=		$(subst $(ROOTDIR),$(OUTDIR),$(CURDIR))
VENDORDIR=	$(ROOTDIR)/vendor
TOOLDIR=	$(OUTDIR)/tools/bin
PATCHDIR=	$(ROOTDIR)/patches
UNAME_s=	$(shell uname -s)
UNAME_m=	$(shell uname -m)

HOST_ARCH=	$(UNAME_m)
ifeq ($(HOST_ARCH),arm64)
override HOST_ARCH:=	aarch64
endif

# If no platform is specified, try to guess it from the host architecture.
ifeq ($(PLATFORM),)
ARCH?=	$(HOST_ARCH)
ifeq ($(ARCH),aarch64)
PLATFORM?=	virt
endif
ifeq ($(ARCH),x86_64)
PLATFORM?=	pc
endif
ifeq ($(ARCH),riscv64)
PLATFORM?=	riscv-virt
endif
else
# Otherwise, assume we're cross-compiling, and derive the arch from the platform.
ifeq ($(PLATFORM),virt)
ARCH?=		aarch64
endif
ifeq ($(PLATFORM),pc)
ARCH?=		x86_64
endif
ifeq ($(PLATFORM),riscv-virt)
ARCH?=		riscv64
endif
ifneq ($(ARCH),$(HOST_ARCH))
  ifeq ($(ARCH),riscv64)
    CROSS_COMPILE?= riscv64-linux-gnu-
  else ifeq ($(ARCH),aarch64)
    CROSS_COMPILE?= aarch64-linux-gnu-
  else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE?= x86_64-linux-gnu-
  else
    CROSS_COMPILE?= $(ARCH)-linux-gnu-
  endif
endif
endif

# macOS cross-compilation (uses ELF toolchains)
ifeq ($(UNAME_s),Darwin)
  ifeq ($(ARCH),riscv64)
    CROSS_COMPILE= riscv64-unknown-elf-
  else ifeq ($(ARCH),aarch64)
    CROSS_COMPILE= aarch64-elf-
  else ifeq ($(ARCH),x86_64)
    CROSS_COMPILE= x86_64-elf-
  else
    CROSS_COMPILE= $(ARCH)-elf-
  endif
endif 

PLATFORMDIR=	$(ROOTDIR)/platform/$(PLATFORM)
PLATFORMOBJDIR=	$(subst $(ROOTDIR),$(OUTDIR),$(PLATFORMDIR))
ARCHDIR=	$(SRCDIR)/$(ARCH)
