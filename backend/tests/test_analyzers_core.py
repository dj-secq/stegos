import os
import tempfile
from unittest import mock
import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.profile import FileProfileAnalyzer
from stego_triage.analyzers.metadata import FileAnalyzer, ExifToolAnalyzer, StringsAnalyzer

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def test_file_profile():
    job_id = jobs.create_job("test.txt", 11, "text/plain", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"hello world")
        
    a = FileProfileAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    
    # check if it wrote to job
    job = jobs.get_job(job_id)
    assert job["input"]["hashes"]["md5"] == "5eb63bbbe01eeed093cb22bb8f5acdc3"
    # "file" returns text/plain for this
    assert "text/plain" in job["input"]["detected_mime"]

def test_strings_analyzer():
    job_id = jobs.create_job("test.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"junkjunkjunk picoCTF{f4k3_fl4g} morejunkjunk")
        
    a = StringsAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert any(f["value"] == "picoCTF{f4k3_fl4g}" for f in res["findings"])

def test_exiftool_analyzer():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"fake image data")
        
    a = ExifToolAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] in ("success", "failed")
