import os
import tempfile
import stego_triage.config as config
from stego_triage import jobs, worker, cleanup

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def test_schema_and_atomic_writes():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    manifest = jobs.get_job(job_id)
    assert manifest["schema_version"] == 2
    assert manifest["input"]["display_name"] == "test.png"
    assert manifest["status"] == "queued"

def test_queue_full():
    jobs.queued_jobs = config.MAX_QUEUED_JOBS
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    assert job_id is None

def test_restart_recovery():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    manifest = jobs.get_job(job_id)
    manifest["status"] = "running"
    jobs._write_manifest(job_id, manifest)
    
    w = worker.AnalyzerWorker()
    w.recover_stale_jobs()
    
    recovered = jobs.get_job(job_id)
    assert recovered["status"] == "failed"
    assert "restarted" in recovered["error"]
    
def test_cancellation():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    manifest = jobs.get_job(job_id)
    manifest["status"] = "cancelled"
    jobs._write_manifest(job_id, manifest)
    
    cleanup.delete_job(job_id)
    
    assert jobs.get_job(job_id) is None
