package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config represents the nanofile configuration
type Config struct {
	Args                   []string               `json:"Args"`
	Program                string                 `json:"Program"`
	ManifestPassthrough    map[string]interface{} `json:"ManifestPassthrough"`
	Env                    map[string]string      `json:"Env"`
	Files                  map[string]string      `json:"Files"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "run":
		runApp(os.Args[2:])
	case "mkimage":
		mkImageOnly(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `minops - Minimal Nanos ops replacement

Usage:
  minops run <app.py> [-c config.json] [-m memory] [-v]

Options:
  -c config.json    Configuration file (default: config.json)
  -m memory         Memory in MB (default: 512)
  -v, -verbose      Verbose output
  -h, -help         Show this help

Examples:
  minops run main.py -c config.json
  minops run myapp.py -m 1024 -v

`)
}

func runApp(args []string) {
	var (
		appFile    string
		configFile = "config.json"
		memory     = 512
		verbose    bool
	)

	// Parse command line arguments manually to handle flags after positional args
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "-verbose":
			verbose = true
		case "-c":
			if i+1 < len(args) {
				configFile = args[i+1]
				i++
			}
		case "-m":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil {
					memory = n
					i++
				}
			}
		default:
			remaining = append(remaining, arg)
		}
	}

	if len(remaining) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No app specified\n")
		printUsage()
		os.Exit(1)
	}

	appFile = remaining[0]

	// Verify app exists
	if _, err := os.Stat(appFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot find app: %s\n", appFile)
		os.Exit(1)
	}

	// Load config
	config := &Config{
		Args: []string{filepath.Base(appFile)},
	}

	if _, err := os.Stat(configFile); err == nil {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		if err := json.Unmarshal(data, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("🔧 Configuration:\n")
		fmt.Printf("   App: %s\n", appFile)
		fmt.Printf("   Args: %v\n", config.Args)
		fmt.Printf("   Memory: %dMB\n", memory)
		fmt.Printf("   Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("\n")
	}

	// Create temporary directory for image
	tmpDir, err := ioutil.TempDir("", "minops-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	if verbose {
		fmt.Printf("📂 Temp directory: %s\n", tmpDir)
	}

	// Copy app to temp directory
	tmpApp := filepath.Join(tmpDir, filepath.Base(appFile))
	if err := copyFile(appFile, tmpApp); err != nil {
		fmt.Fprintf(os.Stderr, "Error copying app: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Copied app to: %s\n", tmpApp)
	}

	// Find kernel image
	kernelPath := findKernelImage()
	if kernelPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot find kernel image\n")
		fmt.Fprintf(os.Stderr, "Build with: make -j$(nproc)\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Found kernel: %s\n", kernelPath)
	}

	// Create minimal image with app
	imagePath := filepath.Join(tmpDir, "image.raw")
	if err := createImage(imagePath, tmpApp, kernelPath, config, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating image: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Created image: %s\n", imagePath)
		fmt.Printf("\n")
	}

	// Launch QEMU
	fmt.Printf("🚀 Launching kernel...\n\n")
	if err := launchQEMU("", imagePath, config, memory, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error launching QEMU: %v\n", err)
		os.Exit(1)
	}
}

func mkImageOnly(args []string) {
	var (
		appFile    string
		configFile = "config.json"
		verbose    bool
	)

	// Parse command line arguments manually to handle flags after positional args
	// Go's flag package doesn't handle this well by default
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-v", "-verbose":
			verbose = true
		case "-c":
			if i+1 < len(args) {
				configFile = args[i+1]
				i++
			}
		default:
			remaining = append(remaining, arg)
		}
	}

	if len(remaining) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: minops mkimage <app.py> <output.img> [-c config.json] [-v]\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("🔧 Verbose mode enabled\n")
	}

	appFile = remaining[0]
	imagePath := remaining[1]

	// Verify app exists
	if _, err := os.Stat(appFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot find app: %s\n", appFile)
		os.Exit(1)
	}

	// Load config
	config := &Config{
		Args: []string{filepath.Base(appFile)},
	}

	if _, err := os.Stat(configFile); err == nil {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading config: %v\n", err)
			os.Exit(1)
		}

		if err := json.Unmarshal(data, config); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing config: %v\n", err)
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("🔧 Configuration:\n")
		fmt.Printf("   App: %s\n", appFile)
		fmt.Printf("   Image: %s\n", imagePath)
		fmt.Printf("   Args: %v\n", config.Args)
		fmt.Printf("\n")
	}

	// Find kernel image
	kernelPath := findKernelImage()
	if kernelPath == "" {
		fmt.Fprintf(os.Stderr, "Error: Cannot find kernel image\n")
		fmt.Fprintf(os.Stderr, "Build with: make -j$(nproc)\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Found kernel: %s\n", kernelPath)
	}

	// Create image
	if err := createImage(imagePath, appFile, kernelPath, config, verbose); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating image: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Created image: %s\n", imagePath)
		fi, _ := os.Stat(imagePath)
		if fi != nil {
			fmt.Printf("   Size: %d bytes\n", fi.Size())
		}
	} else {
		fmt.Printf("✅ Created image: %s\n", imagePath)
	}
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

func findKernelImage() string {
	// Try standard locations
	candidates := []string{
		"output/platform/pc/bin/kernel.img",
		"../output/platform/pc/bin/kernel.img",
		"../../output/platform/pc/bin/kernel.img",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func findMkfs() string {
	// Try standard locations
	candidates := []string{
		"output/tools/bin/mkfs",
		"../output/tools/bin/mkfs",
		"../../output/tools/bin/mkfs",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func findBootloader() string {
	// Try standard locations
	candidates := []string{
		"output/platform/pc/boot/boot.img",
		"../output/platform/pc/boot/boot.img",
		"../../output/platform/pc/boot/boot.img",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// bundleTree recursively bundles a directory tree, skipping problematic entries
func bundleTree(rootPath, dir, indent string, manifest *bytes.Buffer) error {
	entries, err := ioutil.ReadDir(filepath.Join(rootPath, dir))
	if err != nil {
		return nil // Skip unreadable directories
	}

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(rootPath, dir, name)
		relPath := filepath.Join(dir, name)

		// Skip hidden files and pycache
		if strings.HasPrefix(name, ".") || name == "__pycache__" {
			continue
		}

		if entry.IsDir() {
			// Skip dangerous or unnecessary directories
			if name == "tests" || name == "test" || name == "__phello__" {
				continue
			}
			manifest.WriteString(indent + name + ":(children:(\n")
			bundleTree(rootPath, relPath, indent+"  ", manifest)
			manifest.WriteString(indent + "))\n")
		} else {
			// Include all files in Python stdlib
			manifest.WriteString(indent + name + ":(contents:(host:" + fullPath + "))\n")
		}
	}

	return nil
}

func createImage(imagePath, appPath string, kernelPath string, config *Config, verbose bool) error {
	// Build manifest in Nanos tuple format with proper spacing
	var manifest bytes.Buffer

	// Convert to absolute path for manifest
	absAppPath, err := filepath.Abs(appPath)
	if err != nil {
		return fmt.Errorf("cannot get absolute path: %v", err)
	}

	// Program to run - execute Python directly (/bin/python3 now available)
	program := "/bin/python3"
	if config.Program != "" {
		program = config.Program
	}

	// Build children section with explicit Alpine bundles
	manifest.WriteString("(\n    children:(\n")

	// App file
	manifest.WriteString("        main.py:(contents:(host:" + absAppPath + "))\n")

	// Bundle /bin directory (Python, shell, etc.)
	pythonRoot := "/tmp/nanos-root"
	manifest.WriteString("        bin:(children:(\n")
	if _, err := os.Stat(pythonRoot + "/bin/python3.11"); err == nil {
		manifest.WriteString("            python3.11:(contents:(host:" + pythonRoot + "/bin/python3.11))\n")
	}
	if _, err := os.Stat(pythonRoot + "/bin/python3"); err == nil {
		manifest.WriteString("            python3:(contents:(host:" + pythonRoot + "/bin/python3))\n")
	}
	if _, err := os.Stat(pythonRoot + "/bin/sh"); err == nil {
		manifest.WriteString("            sh:(contents:(host:" + pythonRoot + "/bin/sh))\n")
	}
	if _, err := os.Stat(pythonRoot + "/bin/busybox"); err == nil {
		manifest.WriteString("            busybox:(contents:(host:" + pythonRoot + "/bin/busybox))\n")
	}
	manifest.WriteString("        ))\n")

	// Bundle /lib directory (runtime libraries)
	manifest.WriteString("        lib:(children:(\n")
	if _, err := os.Stat(pythonRoot + "/lib/libc.musl-x86_64.so.1"); err == nil {
		manifest.WriteString("            libc.musl-x86_64.so.1:(contents:(host:" + pythonRoot + "/lib/libc.musl-x86_64.so.1))\n")
	}
	if _, err := os.Stat(pythonRoot + "/lib/ld-musl-x86_64.so.1"); err == nil {
		manifest.WriteString("            ld-musl-x86_64.so.1:(contents:(host:" + pythonRoot + "/lib/ld-musl-x86_64.so.1))\n")
	}
	manifest.WriteString("        ))\n")

	// Bundle Python stdlib via /usr/lib directory
	manifest.WriteString("        usr:(children:(lib:(children:(\n")
	// Use bundleTree to recursively include Python stdlib, filtering for safe characters
	bundleTree(pythonRoot, "usr/lib", "", &manifest)
	manifest.WriteString("        ))))\n")

	manifest.WriteString("    )\n")

	manifest.WriteString("program:" + program + " ")

	// Enable serial console output
	manifest.WriteString("console:t ")

	// Add command-line arguments (default to just main.py if not specified)
	if len(config.Args) == 0 {
		manifest.WriteString("arguments:[main.py]")
	} else if len(config.Args) > 0 {
		manifest.WriteString("arguments:[")
		for i, arg := range config.Args {
			if i > 0 {
				manifest.WriteString(" ")
			}
			manifest.WriteString(arg)
		}
		manifest.WriteString("]")
	}

	// Add environment variables if present
	if len(config.Env) > 0 {
		manifest.WriteString(" environment:(")
		for k, v := range config.Env {
			manifest.WriteString(k + ":" + v + " ")
		}
		manifest.WriteString(")")
	}

	// Add manifest passthrough settings
	if len(config.ManifestPassthrough) > 0 {
		for k, v := range config.ManifestPassthrough {
			manifest.WriteString(" ")
			switch vv := v.(type) {
			case string:
				manifest.WriteString(k + ":" + vv)
			case []interface{}:
				manifest.WriteString(k + ":[")
				for i, item := range vv {
					if i > 0 {
						manifest.WriteString(" ")
					}
					manifest.WriteString(fmt.Sprintf("%v", item))
				}
				manifest.WriteString("]")
			default:
				manifest.WriteString(k + ":" + fmt.Sprintf("%v", v))
			}
		}
	}

	manifest.WriteString(")\n")

	if verbose {
		fmt.Printf("   Manifest:\n%s\n", manifest.String())
	}

	// Find mkfs tool
	mkfsPath := findMkfs()
	if mkfsPath == "" {
		return fmt.Errorf("mkfs tool not found. Build with: make -j$(nproc)")
	}

	if verbose {
		fmt.Printf("   Using mkfs: %s\n", mkfsPath)
	}

	// Find bootloader
	bootloaderPath := findBootloader()
	if bootloaderPath == "" {
		// For now, continue without bootloader - output may still work
		if verbose {
			fmt.Printf("   ⚠️  Bootloader not found (output may not display)\n")
		}
	} else {
		if verbose {
			fmt.Printf("   Using bootloader: %s\n", bootloaderPath)
		}
	}

	// Run mkfs with manifest from stdin
	// Use -b flag for bootloader (if found) and -k flag for kernel image
	mkfsArgs := []string{"-k", kernelPath}
	if bootloaderPath != "" {
		mkfsArgs = append([]string{"-b", bootloaderPath}, mkfsArgs...)
	}

	// Add minimal rootfs if it exists (for /bin/sh, etc)
	minimalRoot := "/tmp/nanos-root"
	if _, err := os.Stat(minimalRoot); err == nil {
		mkfsArgs = append(mkfsArgs, "-r", minimalRoot)
	}

	mkfsArgs = append(mkfsArgs, imagePath)

	cmd := exec.Command(mkfsPath, mkfsArgs...)
	cmd.Stdin = &manifest

	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Printf("   mkfs args: %v\n", mkfsArgs)
	} else {
		// Capture output for error reporting
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			output := stderr.String()
			if output == "" {
				output = stdout.String()
			}
			return fmt.Errorf("mkfs failed: %v\nOutput: %s", err, output)
		}
		return nil
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mkfs failed: %v", err)
	}

	return nil
}

func launchQEMU(kernelPath, imagePath string, config *Config, memory int, verbose bool) error {
	// Build QEMU command for Nanos bootloader + kernel
	cmd := exec.Command("qemu-system-x86_64")

	args := []string{
		"-m", fmt.Sprintf("%dM", memory),
		"-display", "none",
		"-serial", "stdio",
		"-hda", imagePath,
	}

	if verbose {
		fmt.Printf("🔧 QEMU Command:\n")
		fmt.Printf("   qemu-system-x86_64 %s\n\n", fmt.Sprint(args))
	}

	cmd.Args = append(cmd.Args, args...)

	// Run QEMU with output to stdout
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		// QEMU may exit with specific codes, which is OK
		if _, ok := err.(*exec.ExitError); ok {
			return nil // QEMU exited normally
		}
		return err
	}

	return nil
}
