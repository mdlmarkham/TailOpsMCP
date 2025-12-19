#!/usr/bin/env python3
"""
Wrapper script to run bandit with UTF-8 encoding on Windows.
This ensures Unicode characters (like checkmarks) are properly handled.
"""

import os
import subprocess
import sys

# Set UTF-8 encoding for Python I/O
os.environ["PYTHONIOENCODING"] = "utf-8"

# Get arguments from command line
args = sys.argv[1:]

# Run bandit with the provided arguments
result = subprocess.run(["bandit"] + args)
sys.exit(result.returncode)
