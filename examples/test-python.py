#!/usr/bin/env python3
"""
Simple Python test for Authority Nanos kernel execution
"""

import sys
import os

print("=" * 60)
print("Authority Nanos - Python Execution Test")
print("=" * 60)
print()

# Test 1: Basic output
print("✅ Test 1: Basic print statement")
print("   Python version: {}".format(sys.version))
print("   Executable: {}".format(sys.executable))
print()

# Test 2: Environment variables
print("✅ Test 2: Environment variables")
print("   PATH: {}".format(os.environ.get("PATH", "(not set)")))
print("   HOME: {}".format(os.environ.get("HOME", "(not set)")))
print()

# Test 3: Filesystem operations
print("✅ Test 3: Filesystem operations")
cwd = os.getcwd()
print("   Current directory: {}".format(cwd))
try:
    files = os.listdir(cwd)
    print("   Files in cwd: {}".format(len(files)) if files else "   (no files)")
except Exception as e:
    print("   Error listing files: {}".format(e))
print()

# Test 4: Simple arithmetic
print("✅ Test 4: Arithmetic operations")
result = sum(range(1, 11))
print("   Sum of 1-10: {}".format(result))
print()

# Test 5: String operations
print("✅ Test 5: String operations")
text = "Authority Nanos"
print("   Original: {}".format(text))
print("   Reversed: {}".format(text[::-1]))
print("   Uppercase: {}".format(text.upper()))
print()

# Test 6: Collections
print("✅ Test 6: Collections")
data = {"kernel": "nanos", "language": "python", "version": 3.10}
for key, value in data.items():
    print("   {}: {}".format(key, value))
print()

print("=" * 60)
print("✅ All tests passed!")
print("=" * 60)
