"""
Pytest configuration and shared fixtures for Active Directory MCP Server tests.
"""

import os
import sys
from pathlib import Path

# Add src to sys.path
src_dir = Path(__file__).parent.parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Enforce clean test environment
os.environ["AD_MCP_MODE"] = "READ_ONLY"
os.environ["AD_SERVER"] = "127.0.0.1"
os.environ["AD_DOMAIN"] = "test.local"
os.environ["AD_AUDIT_LOG_FILE"] = "test_audit.jsonl"
