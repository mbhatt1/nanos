# Build Matrix

This document shows which host platforms can build for which target architectures, and the required toolchains.

## Quick Reference

| Host Platform | Native Target | Cross-Compile To | Setup |
|---------------|---------------|------------------|-------|
| **macOS x86_64** | x86_64 (pc) | aarch64, riscv64 | `brew install aarch64-elf-gcc riscv64-elf-gcc` |
| **macOS ARM64** | aarch64 (virt) | x86_64, riscv64 | `brew install x86_64-elf-gcc riscv64-elf-gcc` |
| **Linux x86_64** | x86_64 (pc) | aarch64, riscv64 | `apt install gcc-aarch64-linux-gnu gcc-riscv64-linux-gnu` |
| **Linux ARM64** | aarch64 (virt) | x86_64, riscv64 | `apt install gcc-x86-64-linux-gnu gcc-riscv64-linux-gnu` (if available) |

## Detailed Build Matrix

### macOS x86_64 (Intel)

| Target | Arch | Platform | Command | Toolchain | Status |
|--------|------|----------|---------|-----------|--------|
| **Native** | x86_64 | pc | `make PLATFORM=pc ARCH=x86_64` | None (native) | ✅ Working |
| **ARM64** | aarch64 | virt | `make PLATFORM=virt ARCH=aarch64` | `aarch64-elf-gcc` | ✅ Tested |
| **RISC-V** | riscv64 | riscv-virt | `make PLATFORM=riscv-virt ARCH=riscv64` | `riscv64-unknown-elf-gcc` | ✅ Supported |

### macOS ARM64 (Apple Silicon)

| Target | Arch | Platform | Command | Toolchain | Status |
|--------|------|----------|---------|-----------|--------|
| **Native** | aarch64 | virt | `make PLATFORM=virt ARCH=aarch64` | None (native) | ✅ Working |
| **x86_64** | x86_64 | pc | `make PLATFORM=pc ARCH=x86_64` | `x86_64-elf-gcc` | ⚠️ Needs testing |
| **RISC-V** | riscv64 | riscv-virt | `make PLATFORM=riscv-virt ARCH=riscv64` | `riscv64-unknown-elf-gcc` | ✅ Supported |

### Linux x86_64 (Ubuntu/Debian)

| Target | Arch | Platform | Command | Toolchain | Status |
|--------|------|----------|---------|-----------|--------|
| **Native** | x86_64 | pc | `make PLATFORM=pc ARCH=x86_64` | None (native) | ✅ Working |
| **ARM64** | aarch64 | virt | `make PLATFORM=virt ARCH=aarch64` | `aarch64-linux-gnu-gcc` | ✅ Tested in CI/CD |
| **RISC-V** | riscv64 | riscv-virt | `make PLATFORM=riscv-virt ARCH=riscv64` | `riscv64-linux-gnu-gcc` | ✅ Tested in CI/CD |

### Linux ARM64 (Graviton, etc.)

| Target | Arch | Platform | Command | Toolchain | Status |
|--------|------|----------|---------|-----------|--------|
| **Native** | aarch64 | virt | `make PLATFORM=virt ARCH=aarch64` | None (native) | ✅ Working |
| **x86_64** | x86_64 | pc | `make PLATFORM=pc ARCH=x86_64` | `x86_64-linux-gnu-gcc` | ⚠️ Limited availability |
| **RISC-V** | riscv64 | riscv-virt | `make PLATFORM=riscv-virt ARCH=riscv64` | `riscv64-linux-gnu-gcc` | ✅ Supported |

## Platform Details

### Target: x86_64 (Intel/AMD 64-bit)

```bash
# Native build (no cross-compiler)
make PLATFORM=pc

# From ARM64 macOS (requires cross-compiler)
brew install x86_64-elf-gcc
make PLATFORM=pc ARCH=x86_64
```

**Output:** `output/platform/pc/bin/kernel.img`

### Target: aarch64 (ARM 64-bit)

```bash
# Native build (no cross-compiler)
make PLATFORM=virt

# From x86_64 host
# macOS:
brew install aarch64-elf-gcc
make PLATFORM=virt ARCH=aarch64

# Linux:
sudo apt-get install gcc-aarch64-linux-gnu
make PLATFORM=virt ARCH=aarch64
```

**Output:** `output/platform/virt/bin/kernel.img`

### Target: riscv64 (RISC-V 64-bit)

```bash
# From any x86_64 or ARM64 host
# macOS:
brew install riscv64-elf-gcc
make PLATFORM=riscv-virt ARCH=riscv64

# Linux:
sudo apt-get install gcc-riscv64-linux-gnu
make PLATFORM=riscv-virt ARCH=riscv64
```

**Output:** `output/platform/riscv-virt/bin/kernel.img`

**Note:** RISC-V requires GCC 9.3.0 or higher

## Verification

Verify the correct architecture was built:

```bash
# Check x86_64 build
file output/platform/pc/bin/kernel.img
# Expected: ELF 64-bit LSB executable, x86-64

# Check ARM64 build
file output/platform/virt/bin/kernel.img
# Expected: ELF 64-bit LSB executable, ARM aarch64

# Check RISC-V build
file output/platform/riscv-virt/bin/kernel.img
# Expected: ELF 64-bit LSB executable, RISC-V
```

## CI/CD Pipeline

The automated CI/CD pipeline tests the following combinations:

| Job | Host | Native Target | Status |
|-----|------|---------------|--------|
| build-macos-x86 | macOS x86_64 | x86_64 | ✅ |
| build-macos-arm64 | macOS ARM64 | aarch64 | ✅ |
| build-linux-x86 | Linux x86_64 | x86_64 | ✅ |
| build-linux-arm64 | Linux ARM64 | aarch64 | ✅ |
| build-linux-riscv | Linux x86_64 | riscv64 | ✅ |

See `.github/workflows/build.yml` for the full workflow definition.

## Troubleshooting

### Compiler Not Available

If you see `command not found: aarch64-linux-gnu-gcc`:

1. Install the cross-compiler for your platform (see above)
2. Verify installation: `which aarch64-linux-gnu-gcc`
3. Try a clean build: `make clean && make PLATFORM=virt ARCH=aarch64`

### Wrong Architecture Built

If `file` shows the wrong architecture:

1. Verify the cross-compiler is correct: `aarch64-linux-gnu-gcc --version`
2. Check your `vars.mk` detection: `make --version` and `gcc --version`
3. Try explicit compiler: `make CC=aarch64-linux-gnu-gcc PLATFORM=virt`

### RISC-V Build Fails

If RISC-V build fails with GCC version error:

```bash
# Check GCC version
riscv64-linux-gnu-gcc --version
# Should be 9.3.0 or higher

# Update if too old
# macOS: brew upgrade riscv64-elf-gcc
# Linux: sudo apt-get upgrade gcc-riscv64-linux-gnu
```

## See Also

- [Cross-Compilation Toolchains](../getting-started/toolchains.md) - Setup and installation guide
- [Getting Started](../getting-started/) - Quick start guide
