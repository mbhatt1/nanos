FROM --platform=linux/amd64 ubuntu:22.04

# Set non-interactive mode
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    nasm \
    wget \
    golang-go \
    git \
    qemu-system-x86-64 \
    gcc-aarch64-linux-gnu \
    gcc-riscv64-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /work

# Default command
CMD ["make", "PLATFORM=pc", "-j4"]
