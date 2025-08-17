#!/usr/bin/env python3
"""Thin CLI shim to keep backward compatibility with docs."""
from BugBounty_main import main

if __name__ == "__main__":
    raise SystemExit(main())
