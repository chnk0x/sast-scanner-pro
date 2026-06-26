#!/usr/bin/env python3
"""Convenience launcher for the SAST scanner."""
import sys
from sast_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
