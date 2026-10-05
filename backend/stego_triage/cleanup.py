import os
import shutil
import time
from . import config
from .security import safe_join

def cleanup_jobs():
    if not os.path.exists(config.RUNTIME_ROOT):
        return
    now = time.time()
    for item in os.listdir(config.RUNTIME_ROOT):
        job_dir = safe_join(config.RUNTIME_ROOT, item)
        if not job_dir or not os.path.isdir(job_dir):
            continue
            
        manifest_path = os.path.join(job_dir, "manifest.json")
        try:
            mtime = os.path.getmtime(manifest_path) if os.path.exists(manifest_path) else os.path.getmtime(job_dir)
            if now - mtime > config.JOB_RETENTION_SECONDS:
                shutil.rmtree(job_dir, ignore_errors=True)
        except Exception:
            pass

def delete_job(job_id: str):
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    if job_dir and os.path.isdir(job_dir):
        shutil.rmtree(job_dir, ignore_errors=True)
