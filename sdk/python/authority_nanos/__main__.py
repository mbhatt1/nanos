#!/usr/bin/env python3
"""
Allow running authority_nanos as a module.

Usage:
    python -m authority_nanos [command] [args...]

Examples:
    python -m authority_nanos hello
    python -m authority_nanos doctor
    python -m authority_nanos example 1
"""

import sys
from authority_nanos.cli import main

if __name__ == "__main__":
    sys.exit(main())
