# Cross-Compilation Toolchains

This guide explains how to set up cross-compilation toolchains to build Authority Nanos for different target architectures from macOS or Linux hosts.

## Overview

Authority Nanos supports building for three target architectures:
- **x86_64** (Intel/AMD 64-bit) - `PLATFORM=pc`
- **aarch64** (ARM 64-bit) - `PLATFORM=virt`
- **riscv64** (RISC-V 64-bit) - `PLATFORM=riscv-virt`

These can be built from any supported host platform (macOS or Linux) using cross-compilation toolchains.

## Installation by Host Platform

### macOS - Install Cross-Compilers via Homebrew

If you're on Apple Silicon and want to build for Intel x86_64, or on Intel and want to build for ARM64/RISC-V, you'll need cross-compiler toolchains.

```bash
# For ARM64 targets (on Intel macOS)
brew install aarch64-elf-gcc aarch64-elf-binutils

# For RISC-V targets (on any macOS)
brew install riscv64-elf-gcc riscv64-elf-binutils

# For x86_64 targets (on Apple Silicon macOS)
brew install x86_64-elf-gcc x86_64-elf-binutils
```

**Note:** On macOS, cross-compilers use ELF format (`*-elf-*`), not the Linux GNU format.

### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt-get update

# For ARM64 targets (when building on x86_64)
sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu

# For RISC-V targets
sudo apt-get install -y gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu

# For x86_64 targets (when building on ARM64, if available)
sudo apt-get install -y gcc-x86-64-linux-gnu binutils-x86-64-linux-gnu
```

### Linux (Fedora/RHEL)

```bash
# For ARM64 targets
sudo dnf install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu

# For RISC-V targets
sudo dnf install -y gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
```

## Building for Different Targets

The build system automatically detects the correct cross-compiler based on your host and target architecture.

### Native Builds (No Cross-Compiler Needed)

Build for the same architecture as your host:

```bash
# On x86_64 host → x86_64 target
make PLATFORM=pc ARCH=x86_64

# On aarch64 host → aarch64 target
make PLATFORM=virt ARCH=aarch64

# On riscv64 host → riscv64 target
make PLATFORM=riscv-virt ARCH=riscv64
```

### Cross-Compilation Builds

Build for a different architecture than your host:

```bash
# From x86_64 → aarch64
make PLATFORM=virt ARCH=aarch64

# From x86_64 → riscv64
make PLATFORM=riscv-virt ARCH=riscv64

# From aarch64 → x86_64
make PLATFORM=pc ARCH=x86_64

# From aarch64 → riscv64
make PLATFORM=riscv-virt ARCH=riscv64
```

### Parallel Build

Use `make -j$(nproc)` (Linux) or `make -j$(sysctl -n hw.ncpu)` (macOS) to speed up builds:

```bash
make -j$(nproc) PLATFORM=virt ARCH=aarch64 all-binaries
```

## Build Output

After a successful build, you'll have:

```
output/platform/pc/bin/kernel.img          # x86_64 kernel
output/platform/pc/lib/libak.so            # x86_64 libak (Linux) or libak.dylib (macOS)

output/platform/virt/bin/kernel.img        # ARM64 kernel
output/platform/virt/lib/libak.so          # ARM64 libak (Linux) or libak.dylib (macOS)

output/platform/riscv-virt/bin/kernel.img  # RISC-V kernel
output/platform/riscv-virt/lib/libak.so    # RISC-V libak (Linux) or libak.dylib (macOS)
```

## Verifying Architecture

Check the correct architecture was built using the `file` command:

```bash
file output/platform/pc/bin/kernel.img
# Should output: ELF 64-bit LSB executable, x86-64

file output/platform/virt/bin/kernel.img
# Should output: ELF 64-bit LSB executable, ARM aarch64

file output/platform/riscv-virt/bin/kernel.img
# Should output: ELF 64-bit LSB executable, RISC-V
```

## Troubleshooting

### Cross-Compiler Not Found

If you see an error like `x86_64-elf-gcc: command not found`, ensure you've installed the toolchain:

**On macOS:**
```bash
brew install x86_64-elf-gcc
```

**On Linux (Ubuntu):**
```bash
sudo apt-get install gcc-x86-64-linux-gnu
```

### RISC-V GCC Version Too Old

If you see: `gcc version 9.3.0 or higher required to build RISC-V`

Update your cross-compiler:

**On macOS:**
```bash
brew upgrade riscv64-elf-gcc
```

**On Linux:**
```bash
sudo apt-get upgrade gcc-riscv64-linux-gnu
```

### Build Fails with Compiler Error

If compilation fails with architecture-specific errors:

1. Verify the correct cross-compiler is being used:
   ```bash
   which aarch64-linux-gnu-gcc  # or appropriate compiler
   ```

2. Check the compiler supports your target:
   ```bash
   aarch64-linux-gnu-gcc --version
   aarch64-linux-gnu-gcc -march=armv8-a -dM -E - < /dev/null | grep __ARM
   ```

3. Try a clean build:
   ```bash
   make clean
   make PLATFORM=virt ARCH=aarch64 -j1  # Single-threaded to see errors clearly
   ```

## Toolchain Detection Logic

The build system uses this logic to select the compiler:

1. **Native builds** (host arch = target arch):
   - Uses system default compiler (`gcc` on Linux, `clang` on macOS)
   - No cross-compiler needed

2. **Linux cross-compilation** (host ≠ target):
   - Linux uses GNU toolchains: `{arch}-linux-gnu-gcc`
   - Examples: `aarch64-linux-gnu-gcc`, `riscv64-linux-gnu-gcc`

3. **macOS cross-compilation** (host ≠ target):
   - macOS uses ELF toolchains: `{arch}-elf-gcc`
   - Examples: `aarch64-elf-gcc`, `riscv64-unknown-elf-gcc`

This is configured in `vars.mk` and automatically detected during build.

## Build Matrix

For a complete overview of which host can build which targets, see [Build Matrix](../building/build-matrix.md).
