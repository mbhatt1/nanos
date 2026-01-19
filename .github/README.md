# GitHub Actions Workflows

This directory contains GitHub Actions workflows for building, testing, and deploying Authority Nanos.

## Workflow Overview

### 1. Build Artifacts (`workflows/build.yml`)

**Triggers:** Pushes to master/release branches, tags matching `v*`, manual dispatch

**Produces platform-specific artifacts for:**
- 🍎 **macOS x86_64** (Intel) - `authority-nanos-macos-x86_64.tar.gz`
- 🍎 **macOS ARM64** (Apple Silicon) - `authority-nanos-macos-arm64.tar.gz`
- 🐧 **Linux x86_64** (AMD64) - `authority-nanos-linux-x86_64.tar.gz` + `.deb`
- 🐧 **Linux ARM64** (aarch64) - `authority-nanos-linux-arm64.tar.gz`
- 🪟 **Windows x86_64** - `authority-nanos-windows-x86_64.zip`

**Features:**
- ✓ Parallel builds on native platforms
- ✓ SHA256 checksums for each artifact
- ✓ Dependency caching for faster builds
- ✓ 45-60 minute timeout per build job
- ✓ Automatic release creation for version tags

**Artifact Locations:**
Each build includes:
- Compiled kernel image
- README and LICENSE files
- HTML documentation (optional)
- SHA256 checksum for verification

**Release Creation:**
When pushing a git tag matching `v*` (e.g., `v1.0.0`), all artifacts are automatically gathered into a GitHub Release with:
- All platform-specific binaries
- SHA256 checksums
- Auto-generated release notes

### 2. Tests (`workflows/test.yml`)

**Triggers:** Pushes to master, feature/*, fix/* branches, pull requests

**Test Suites:**
- 🧪 **Unit Tests** - Authority Kernel component tests
- 🔗 **Integration Tests** - System-level testing in unikernel
- 🔀 **Fuzz Tests** - Fuzzing of parsers and policy engine
- 📝 **Code Quality** - Formatting and static analysis
- 🍎 **macOS Build** - Verify builds on macOS

**Features:**
- ✓ Parallel test execution
- ✓ Dependency caching
- ✓ macOS build verification
- ✓ Test summary report
- ✓ Code formatting checks with clang-format
- ✓ Static analysis with cppcheck
- ✓ Graceful handling of optional tests

**Test Requirements:**
- Unit tests must pass (hard requirement)
- Integration tests should pass
- Fuzz tests should not crash
- Code quality checks should pass

### 3. Documentation (`workflows/docs.yml`)

**Triggers:** Changes to docs/*, package.json, or workflow itself

**Produces:**
- 📖 Built VitePress documentation site
- 🚀 Automatic deployment to GitHub Pages

**Features:**
- ✓ Node.js dependency caching
- ✓ Build verification
- ✓ Link checking
- ✓ Automatic deployment on master push
- ✓ PR preview (build but don't deploy)

**Deployment:**
Documentation is automatically deployed to GitHub Pages when pushed to master.

## Build Platforms

### macOS Builds
- **x86_64**: Runs on `macos-13` (Intel MacBook Pro)
- **ARM64**: Runs on `macos-14` (Apple Silicon Mac mini/MacBook)
- Both use native Homebrew for dependencies

### Linux Builds
- **x86_64**: Runs on `ubuntu-22.04`
- **ARM64**: Runs on `ubuntu-22.04` with cross-compilation tools
- Produces both tar.gz and .deb packages (x86_64)

### Windows Builds
- **x86_64**: Cross-compiles from `ubuntu-22.04`
- Uses mingw-w64 toolchain
- Produces ZIP archive

## Artifact Organization

Artifacts follow this structure:

```
authority-nanos-{platform}-{arch}.tar.gz
├── README.md
├── LICENSE
├── kernel.img (or kernel.exe for Windows)
└── docs-html/ (optional)

authority-nanos-amd64.deb (Linux x86_64 only)
```

## Release Process

### Creating a Release

1. **Tag the commit:**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. **Wait for builds:**
   - All platform builds run in parallel
   - Each takes 45-60 minutes
   - Check Actions tab for status

3. **Release automatically created:**
   - Once all builds pass
   - GitHub Release created with all artifacts
   - Release notes auto-generated
   - Pre-release auto-detected for rc/beta/alpha tags

### Verify Release

```bash
# Download and verify
curl -LO https://github.com/nanovms/authority-nanos/releases/download/v1.0.0/authority-nanos-linux-x86_64.tar.gz
curl -LO https://github.com/nanovms/authority-nanos/releases/download/v1.0.0/authority-nanos-linux-x86_64.tar.gz.sha256

# Verify checksum
sha256sum -c authority-nanos-linux-x86_64.tar.gz.sha256

# Extract
tar xzf authority-nanos-linux-x86_64.tar.gz
```

## Cache Management

Workflows use GitHub Actions caching to speed up builds:

- **Build Cache:**
  - Homebrew cache (macOS)
  - apt cache (Linux)
  - Key: `${{ runner.os }}-build-${{ hashFiles('**/Makefile') }}`

- **Test Cache:**
  - Same as build cache
  - Key: `${{ runner.os }}-test-${{ hashFiles('**/Makefile') }}`

Caches are automatically invalidated when Makefile changes.

## Debugging

### View Workflow Runs
Go to GitHub: **Actions** tab → Select workflow → View runs

### Check Build Logs
Click on failed job → Expand step logs

### Re-run Failed Jobs
Use "Re-run failed jobs" button in GitHub Actions UI

### Manual Trigger
Some workflows have `workflow_dispatch` trigger:
- Go to **Actions** tab
- Select workflow
- Click **Run workflow**

## Environment

### Required Secrets
None currently needed - uses standard GITHUB_TOKEN

### GitHub Pages Setup
Documentation deployment requires:
- GitHub Pages enabled in repo settings
- Deploy from "GitHub Actions"

## Performance

Typical workflow times:
- **Build (single platform):** 45-60 minutes
- **All builds (parallel):** 60 minutes (same time, runs in parallel)
- **Tests:** 10-15 minutes
- **Documentation:** 5-10 minutes

Total time for full CI/CD: ~60 minutes for new release

## Troubleshooting

### Build Failures

**macOS build fails:**
- Check Homebrew package versions in logs
- May need to update `brew install` commands

**Linux build fails:**
- Check apt package availability
- May need to update `apt-get install` commands

**Windows build fails:**
- mingw-w64 cross-compiler may have issues
- Cross-compilation environment may need tuning

### Test Failures

**Unit tests fail:**
- Build issue - check test compilation output
- Test environment issue - check runner logs

**Integration tests don't run:**
- Test binaries may not be built
- Check test/runtime/Makefile

**Fuzz tests timeout:**
- Increase timeout in workflow
- Reduce test corpus size
- Run fuzz tests locally for debugging

### Documentation Deployment

**Pages not updating:**
- Check GitHub Pages settings in repo
- Verify deploy job ran successfully
- Check deploy logs for errors

**Links broken in deployed docs:**
- VitePress may have generated wrong paths
- Check docs/.vitepress/config.ts for path issues

## Best Practices

1. **Before pushing:**
   - Run tests locally
   - Check code formatting
   - Test builds on your machine

2. **For releases:**
   - Ensure all tests pass
   - Create git tag with semantic versioning
   - Wait for all builds to complete
   - Verify artifacts before announcing

3. **For PRs:**
   - Workflows run automatically
   - Check status before merging
   - Don't merge if tests fail

## See Also

- [Build Status](https://github.com/nanovms/authority-nanos/actions)
- [GitHub Pages](https://authority-nanos.dev)
- [Releases](https://github.com/nanovms/authority-nanos/releases)
