#!/usr/bin/env python3
"""
Simple Python test for Nanos kernel execution.
This test does NOT use the Authority SDK - just basic Python functionality.
"""

import sys
import os

print("=" * 50)
print("Nanos Kernel - Basic Python Test")
print("=" * 50)
print()

# Test 1: Basic execution
print("Test 1: Basic Python execution")
print(f"   Python version: {sys.version}")
print(f"   Executable: {sys.executable}")
print()

# Test 2: Environment
print("Test 2: Environment variables")
print(f"   PYTHONHOME: {os.environ.get('PYTHONHOME', 'not set')}")
print(f"   PYTHONPATH: {os.environ.get('PYTHONPATH', 'not set')}")
print(f"   LIBAK_PATH: {os.environ.get('LIBAK_PATH', 'not set')}")
print()

# Test 3: Filesystem
print("Test 3: Filesystem access")
try:
    root_contents = os.listdir('/')
    print(f"   Root directory: {root_contents[:5]}..." if len(root_contents) > 5 else f"   Root directory: {root_contents}")
except Exception as e:
    print(f"   Error: {e}")
print()

# Test 4: Arithmetic
print("Test 4: Computation")
result = sum(range(1, 101))
print(f"   Sum of 1-100: {result}")
expected = 5050
print(f"   Expected: {expected}")
print(f"   Status: {'PASS' if result == expected else 'FAIL'}")
print()

# Test 5: Collections
print("Test 5: Data structures")
data = {"kernel": "nanos", "python": True, "version": 3}
print(f"   Dictionary: {data}")
items = list(data.items())
print(f"   Items: {items}")
print()

# Test 6: String operations
print("Test 6: String operations")
text = "Hello from Nanos"
print(f"   Original: {text}")
print(f"   Upper: {text.upper()}")
print(f"   Reversed: {text[::-1]}")
print()

print("=" * 50)
print("All basic tests completed!")
print("=" * 50)
