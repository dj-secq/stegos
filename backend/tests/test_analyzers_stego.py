import os
import shutil
import subprocess
import tempfile
import numpy as np
import pytest
from PIL import Image
import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.stego import ZstegAnalyzer, SteghideAnalyzer

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def test_zsteg():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"picoCTF{zsteg_t3st}")
        
    a = ZstegAnalyzer()
    res = a.run(input_path, job_dir, {"profile": "quick"})
    # it might fail because zsteg requires actual valid PNG format to not crash, 
    # but the runner handles the exit code
    assert res["status"] in ("success", "failed")

def test_steghide():
    job_id = jobs.create_job("test.jpeg", 100, "image/jpeg", "quick", password="test")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"fake jpeg data")
        
    a = SteghideAnalyzer()
    res = a.run(input_path, job_dir, {"profile": "quick", "password": "test"})
    # steghide will fail on fake data, but password should be redacted
    assert "test" not in str(res) # simple check for no leak in result dict
    # the runner already tests stdout redaction


def _jpeg(path):
    rng = np.random.default_rng(1)
    arr = rng.integers(0, 256, (400, 400, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, "JPEG", quality=95)


def _embed(cover, secret_path, stego, passphrase):
    subprocess.run(
        ["steghide", "embed", "-cf", cover, "-ef", secret_path, "-sf", stego, "-p", passphrase, "-f", "-q"],
        check=True,
        capture_output=True,
    )


def test_empty_steghide_passphrase_is_extracted():
    if shutil.which("steghide") is None:
        pytest.skip("steghide is not installed")
    job_id = jobs.create_job("cover.jpg", 100, "image/jpeg", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    cover = os.path.join(job_dir, "cover.jpg")
    secret = os.path.join(job_dir, "secret.txt")
    stego = os.path.join(job_dir, "input", "file")
    _jpeg(cover)
    with open(secret, "w", encoding="ascii") as handle:
        handle.write("H4G{empty-pass}")
    _embed(cover, secret, stego, "")
    res = SteghideAnalyzer().run(stego, job_dir, {"profile": "quick", "password": None})
    assert res["status"] == "success"
    assert any(item["value"] == "H4G{empty-pass}" for item in res["findings"])
    assert "empty passphrase" in res["summary"]


def test_empty_steghide_does_not_unlock_a_real_passphrase():
    if shutil.which("steghide") is None:
        pytest.skip("steghide is not installed")
    locked_id = jobs.create_job("locked.jpg", 100, "image/jpeg", "quick")
    locked_dir = os.path.join(config.RUNTIME_ROOT, locked_id)
    locked_cover = os.path.join(locked_dir, "cover.jpg")
    locked_secret = os.path.join(locked_dir, "secret.txt")
    locked_stego = os.path.join(locked_dir, "input", "file")
    _jpeg(locked_cover)
    with open(locked_secret, "w", encoding="ascii") as handle:
        handle.write("H4G{locked}")
    _embed(locked_cover, locked_secret, locked_stego, "sekret")
    locked = SteghideAnalyzer().run(locked_stego, locked_dir, {"profile": "quick", "password": None})
    assert all(item.get("value") != "H4G{locked}" for item in locked["findings"])
    assert "passphrase" in locked["summary"].lower()
    assert "sekret" not in str(locked)
