import os

RUNTIME_ROOT = os.environ.get("RUNTIME_ROOT", "/tmp/runtime")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", 26214400)) # 25 MiB
MAX_PIXELS = int(os.environ.get("MAX_PIXELS", 40000000))
MAX_ACTIVE_JOBS = int(os.environ.get("MAX_ACTIVE_JOBS", 1))
MAX_QUEUED_JOBS = int(os.environ.get("MAX_QUEUED_JOBS", 1))
JOB_RETENTION_SECONDS = int(os.environ.get("JOB_RETENTION_SECONDS", 3 * 3600))
