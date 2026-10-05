import json
import os
import re
import secrets
import time
import threading
from typing import Dict, Any

from . import config
from .security import safe_join

_jobs_lock = threading.Lock()
active_jobs = 0
queued_jobs = 0
_held: set[str] = set()

def _job_is_live(job_id: str) -> bool:
    job = get_job(job_id)
    return bool(job and job.get("status") in ("queued", "running"))

def _release_dead_held() -> None:
    """Drop slots whose job is gone or already finished. The counter can otherwise stick at full."""
    global queued_jobs
    for job_id in list(_held):
        if _job_is_live(job_id):
            continue
        _held.discard(job_id)
        queued_jobs = max(0, queued_jobs - 1)

def release_slot(job_id: str) -> None:
    global queued_jobs
    with _jobs_lock:
        if job_id not in _held:
            return
        _held.discard(job_id)
        queued_jobs = max(0, queued_jobs - 1)

def current_job() -> Dict[str, Any] | None:
    if not os.path.isdir(config.RUNTIME_ROOT):
        return None
    newest = None
    for name in os.listdir(config.RUNTIME_ROOT):
        job = get_job(name)
        if not job or job.get("status") not in ("queued", "running"):
            continue
        if newest is None or str(job.get("created_at") or "") >= str(newest.get("created_at") or ""):
            newest = job
    return newest

def create_job(filename: str, size: int, mime: str, profile: str, password: str = None, flag_prefix: str = None) -> str:
    global queued_jobs
    with _jobs_lock:
        _release_dead_held()
        if queued_jobs >= config.MAX_QUEUED_JOBS:
            return None
        queued_jobs += 1
        job_id = secrets.token_hex(16)
        _held.add(job_id)

    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    if not job_dir:
        release_slot(job_id)
        return None
    try:
        os.makedirs(job_dir, exist_ok=True)
        os.makedirs(os.path.join(job_dir, "input"), exist_ok=True)
        os.makedirs(os.path.join(job_dir, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(job_dir, "logs"), exist_ok=True)
    except Exception:
        release_slot(job_id)
        raise
    
    now = time.gmtime()
    expiry = time.gmtime(time.time() + config.JOB_RETENTION_SECONDS)
    
    manifest = {
        "schema_version": 2,
        "job_id": job_id,
        "status": "queued",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", now),
        "expiry_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", expiry),
        "input": {
            "display_name": filename,
            "size": size,
            "declared_mime": mime,
            "detected_mime": None,
            "kind": "generic",
            "format_tags": [],
            "hashes": {},
            "safe_preview_url": None
        },
        "profile": profile,
        "password_provided": bool(password),
        "progress": {
            "completed": 0,
            "total": 0,
            "current": None
        },
        "analyzers": [],
        "findings": [],
        "artifact_totals": {
            "count": 0,
            "bytes": 0
        },
        "warnings": []
    }
    prefix = str(flag_prefix or "")
    if re.fullmatch(r"[A-Za-z0-9_]{1,24}", prefix):
        manifest["flag_prefix"] = prefix
    
    if password:
        with open(os.path.join(job_dir, "input", "password.txt"), "w") as f:
            f.write(password)
        
    try:
        _write_manifest(job_id, manifest)
    except Exception:
        release_slot(job_id)
        raise
    return job_id

def get_job(job_id: str, redact_password: bool = True) -> Dict[str, Any] | None:
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    if not job_dir:
        return None
    manifest_path = os.path.join(job_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        return None
    try:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            if redact_password and "password" in manifest:
                del manifest["password"]
            return manifest
    except Exception:
        return None

def analysis_input_path(job_dir: str, job: Dict[str, Any] | None, fallback: str) -> str:
    name = ""
    if isinstance(job, dict):
        name = (job.get("input") or {}).get("analysis_file") or ""
    if not isinstance(name, str) or not name or os.path.basename(name) != name or name.startswith("."):
        return fallback
    candidate = os.path.join(job_dir, "artifacts", name)
    if os.path.isfile(candidate):
        return candidate
    return fallback

def _write_manifest(job_id: str, manifest: Dict[str, Any]):
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    if not job_dir:
        return
    manifest_path = os.path.join(job_dir, "manifest.json")
    temp_path = manifest_path + ".tmp"
    with open(temp_path, "w") as f:
        json.dump(manifest, f, indent=2)
    os.replace(temp_path, manifest_path)
