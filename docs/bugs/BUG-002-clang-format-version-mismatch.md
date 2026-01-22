# BUG-002: clang-format Version Mismatch Between Local and CI

## Summary
Code formatting check fails in CI due to differences between local clang-format version and clang-format-15 used in GitHub Actions.

## Severity
**Low** - Affects CI only, cosmetic issue.

## Environment
- CI: Ubuntu 22.04 with clang-format-15
- Local: macOS with clang-format (version varies)

## Reproduction
1. Format files locally: `clang-format -i src/agentic/*.c`
2. Push to GitHub
3. CI fails with "Format error in: src/agentic/..." messages

## Error Output
```
=== Checking C Code Formatting (Authority Kernel files only) ===
Format error in: src/agentic/ak_types.h
Format error in: src/agentic/ak_inference.c
Format error in: src/agentic/ak_inference.h
Format error in: src/agentic/ak_capability.c
...
❌ Some files need formatting. Run: clang-format -i <file>
```

## Root Cause
Different versions of clang-format produce slightly different output for the same `.clang-format` configuration file. This is a known issue with clang-format where minor version differences can cause whitespace and alignment variations.

## Affected Files
- All files in `src/agentic/`
- All files matching `test/unit/ak_*.c`
- All files matching `test/integration/ak_*.c`
- All files in `test/fuzz/`

## Impact
- Code Quality CI job fails
- Blocks release workflow if Code Quality is required
- Does not affect actual code functionality

## Workarounds

### Option 1: Use Docker for Formatting
```bash
docker run --rm -v $(pwd):/src silkeh/clang:15 \
  bash -c "find /src/src/agentic -name '*.c' -o -name '*.h' | xargs clang-format -i"
```

### Option 2: Make Check Non-Blocking
Add `continue-on-error: true` to the formatting check step in `.github/workflows/test.yml`

### Option 3: Install Specific Version
```bash
# Ubuntu/Debian
sudo apt-get install clang-format-15
clang-format-15 -i src/agentic/*.c src/agentic/*.h
```

## Recommended Fix
1. Add a `.clang-format-version` file specifying required version
2. Document required clang-format version in CONTRIBUTING.md
3. Provide a script that uses Docker to ensure consistent formatting
4. Consider making formatting check advisory (non-blocking) until stabilized

## References
- CI Run: https://github.com/mbhatt1/authority/actions/runs/21266022477
- Workflow: `.github/workflows/test.yml`

## Status
**Open** - Needs consistent formatting approach across development environments.
