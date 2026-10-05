import os
import tempfile
import time
from stego_triage.runner import run_bounded

def test_runner_success():
    with tempfile.TemporaryDirectory() as td:
        stdout_path = os.path.join(td, "out")
        stderr_path = os.path.join(td, "err")
        res = run_bounded(["echo", "hello"], td, stdout_path, stderr_path)
        assert res.exit_code == 0
        assert res.stdout_preview.strip() == "hello"

def test_runner_timeout_and_termination():
    with tempfile.TemporaryDirectory() as td:
        stdout_path = os.path.join(td, "out")
        stderr_path = os.path.join(td, "err")
        start = time.time()
        # sleep 10 should be killed by timeout 1
        res = run_bounded(["sleep", "10"], td, stdout_path, stderr_path, timeout_secs=1)
        assert time.time() - start < 3.0
        assert res.timed_out is True
        assert res.exit_code == -1

def test_runner_truncation():
    with tempfile.TemporaryDirectory() as td:
        stdout_path = os.path.join(td, "out")
        stderr_path = os.path.join(td, "err")
        # generate 20KB output, max 10KB
        res = run_bounded(
            ["python3", "-c", "print('x' * 20000)"],
            td, stdout_path, stderr_path,
            max_output_bytes=10000,
            preview_bytes=100
        )
        assert res.stdout_truncated is True
        assert os.path.getsize(stdout_path) <= 10000

def test_runner_password_redaction():
    with tempfile.TemporaryDirectory() as td:
        stdout_path = os.path.join(td, "out")
        stderr_path = os.path.join(td, "err")
        res = run_bounded(
            ["echo", "mysecretpassword123"],
            td, stdout_path, stderr_path,
            password_to_redact="mysecretpassword123"
        )
        assert "mysecretpassword123" not in res.stdout_preview
        assert "***REDACTED***" in res.stdout_preview
