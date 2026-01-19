# Design & Specifications

This section contains in-depth design documents, threat models, and technical specifications for the Authority Kernel and Authority Nanos.

## Core Documentation

- **[Authority Kernel Design](./ak-design.md)** - Comprehensive design of the Authority Kernel subsystem
- **[Authority Kernel Base Contract](./ak-base-contract.md)** - The fundamental invariants and API contract
- **[Agentic Kernel Overview](./agentic-kernel.md)** - The security layer powering Authority Nanos

## Security & Threat Modeling

- **[Threat Model](./ak-threat-model.md)** - Comprehensive threat analysis and mitigations
- **[Security Invariants](./invariants.md)** - The four mathematical guarantees Authority enforces

## Development

- **[Authority Kernel Roadmap](./ak-roadmap.md)** - Planned features for the Authority Kernel
- **[Bug Checklist](./bug-checklist.md)** - Known issues and verification procedures

## Quick Reference

The Authority Kernel enforces **four security invariants**:

1. **INV-1: No-Bypass** - All external I/O occurs through kernel-mediated syscalls
2. **INV-2: Capability** - Every effectful syscall requires a valid, non-revoked capability
3. **INV-3: Budget** - Resource consumption never exceeds declared budgets
4. **INV-4: Log Commitment** - Every state transition appends a hash-chained audit entry
