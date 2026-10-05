import pytest
import os
from stego_triage.security import safe_join

def test_safe_join_valid():
    assert safe_join("/tmp/runtime", "job-123", "input", "file") == "/tmp/runtime/job-123/input/file"

def test_safe_join_traversal():
    assert safe_join("/tmp/runtime", "job-123", "..", "..", "etc", "passwd") is None
