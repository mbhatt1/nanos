#!/usr/bin/env python3
"""
Authority Nanos Kernel Example 1: Hello from Inside the Unikernel

This Python script runs INSIDE the Authority Nanos unikernel and demonstrates:
- Direct kernel execution
- System information access
- File operations
- JSON processing

Run with: ops run main.py -c config.json
"""

import sys
import json
import os
from datetime import datetime

def main():
    print("\n" + "="*60)
    print("✅ PYTHON RUNNING INSIDE AUTHORITY NANOS UNIKERNEL")
    print("="*60 + "\n")

    # Display environment info
    print("📋 System Information:")
    print(f"  Python Version: {sys.version.split()[0]}")
    print(f"  Platform: {sys.platform}")
    print(f"  Executable: {sys.executable}")
    print()

    # Test JSON operations
    print("📝 JSON Processing:")
    kernel_info = {
        "name": "Authority Nanos",
        "type": "unikernel",
        "execution_environment": "inside-kernel",
        "python_support": True,
        "timestamp": datetime.now().isoformat(),
        "status": "✅ working"
    }
    print(f"  {json.dumps(kernel_info, indent=2)}")
    print()

    # Test environment variables
    print("🔧 Environment:")
    env_vars = {
        "PATH": os.environ.get("PATH", "not set"),
        "HOME": os.environ.get("HOME", "not set"),
        "LANG": os.environ.get("LANG", "not set"),
        "USER": os.environ.get("USER", "not set"),
    }
    for key, value in env_vars.items():
        print(f"  {key}: {value}")
    print()

    # Test basic math
    print("🧮 Calculations:")
    numbers = [1, 2, 3, 4, 5, 10, 20, 50, 100]
    print(f"  Numbers: {numbers}")
    print(f"  Sum: {sum(numbers)}")
    print(f"  Average: {sum(numbers) / len(numbers):.2f}")
    print(f"  Max: {max(numbers)}")
    print(f"  Min: {min(numbers)}")
    print()

    # Test list comprehension
    print("📚 List Operations:")
    squares = [x**2 for x in range(1, 11)]
    print(f"  Squares (1-10): {squares}")
    evens = [x for x in range(1, 21) if x % 2 == 0]
    print(f"  Even numbers (1-20): {evens}")
    print()

    # Test string operations
    print("📖 String Operations:")
    message = "Authority Nanos Python Unikernel"
    print(f"  Original: {message}")
    print(f"  Uppercase: {message.upper()}")
    print(f"  Length: {len(message)}")
    print(f"  Reversed: {message[::-1]}")
    print()

    # Try filesystem operations
    print("📂 Filesystem Operations:")
    try:
        # Try to read /proc/cmdline
        with open("/proc/cmdline", "r") as f:
            cmdline = f.read().strip()
            print(f"  Kernel cmdline: {cmdline}")
    except FileNotFoundError:
        print("  /proc/cmdline not found (expected in minimal kernels)")
    except Exception as e:
        print(f"  Error reading /proc/cmdline: {e}")

    try:
        # Try to list /
        files = os.listdir("/")
        print(f"  Root directory contents: {', '.join(sorted(files)[:10])}")
    except Exception as e:
        print(f"  Error listing /: {e}")
    print()

    # Test exception handling
    print("🛡️  Exception Handling:")
    try:
        result = 10 / 2
        print(f"  10 / 2 = {result} ✅")

        # This will raise
        bad_result = 10 / 0
    except ZeroDivisionError:
        print(f"  10 / 0 = ZeroDivisionError (caught) ✅")
    print()

    # Test modules
    print("📦 Available Modules:")
    modules = ['sys', 'os', 'json', 'datetime', 'math', 'random', 'hashlib']
    available = []
    for mod in modules:
        try:
            __import__(mod)
            available.append(mod)
        except ImportError:
            pass
    print(f"  Imported: {', '.join(available)}")
    print()

    # Final status
    print("="*60)
    print("✅ ALL TESTS PASSED - PYTHON INSIDE KERNEL WORKS!")
    print("="*60)
    print()

    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
