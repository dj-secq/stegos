import threading
import time
import os
import concurrent.futures
from . import jobs, config
from .security import safe_join
from .analyzers.base import get_analyzers
from .flags import set_flag_prefix

class AnalyzerWorker(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        try:
            self.recover_stale_jobs()
        except Exception:
            pass
        while self.running:
            job_id = None
            try:
                with jobs._jobs_lock:
                    if os.path.exists(config.RUNTIME_ROOT):
                        for d in os.listdir(config.RUNTIME_ROOT):
                            job = jobs.get_job(d)
                            if job and job.get('status') == 'queued':
                                job_id = d
                                job['status'] = 'running'
                                jobs._write_manifest(d, job)
                                break

                if job_id:
                    try:
                        self.process_job(job_id)
                    except Exception as e:
                        self.fail_job(job_id, str(e))
                    finally:
                        jobs.release_slot(job_id)
                else:
                    time.sleep(1)
            except Exception:
                time.sleep(1)

    def recover_stale_jobs(self):
        if not os.path.exists(config.RUNTIME_ROOT):
            return
        with jobs._jobs_lock:
            for d in os.listdir(config.RUNTIME_ROOT):
                job = jobs.get_job(d)
                if job and job.get('status') in ('running', 'queued'):
                    # Fail stale jobs on startup
                    job['status'] = 'failed'
                    job['error'] = 'Service restarted while job was active'
                    jobs._write_manifest(d, job)

    def fail_job(self, job_id, error):
        job = jobs.get_job(job_id)
        if job:
            job['status'] = 'failed'
            job['error'] = error
            jobs._write_manifest(job_id, job)

    def process_job(self, job_id):
        job = jobs.get_job(job_id)
        set_flag_prefix(str((job or {}).get("flag_prefix") or ""))
        try:
            self._process_job(job_id, job)
        finally:
            set_flag_prefix("")

    def _process_job(self, job_id, job):
        job_dir = safe_join(config.RUNTIME_ROOT, job_id)
        input_path = os.path.join(job_dir, "input", "file")

        if not os.path.exists(input_path):
            self.fail_job(job_id, "Input file missing")
            return

        profile = job.get('profile', 'quick')
        all_analyzers = get_analyzers()

        # Filter by profile first
        active_analyzers = []
        for a in all_analyzers:
            if profile == 'quick' and not a.quick:
                continue
            if profile == 'deep' and not (a.quick or a.deep):
                continue
            active_analyzers.append(a)

        job['progress']['total'] = len(active_analyzers)
        jobs._write_manifest(job_id, job)

        has_success = False
        has_failure = False
        completed = 0

        for a in active_analyzers:
            # Re-read job inside loop in case previous analyzers updated it (like profile)
            job = jobs.get_job(job_id, redact_password=False)
            file_kind = job.get("input", {}).get("kind", "generic")
            format_tags = job.get("input", {}).get("format_tags", [])

            if not a.can_run(file_kind, format_tags):
                completed += 1
                job['progress']['completed'] = completed
                jobs._write_manifest(job_id, job)
                continue

            active_input = jobs.analysis_input_path(job_dir, job, input_path)

            job['progress']['current'] = a.name

            res = a._create_result()
            res['status'] = 'running'
            job['analyzers'].append(res)
            jobs._write_manifest(job_id, job)

            password = None
            password_path = os.path.join(job_dir, "input", "password.txt")
            if os.path.exists(password_path):
                with open(password_path, "r") as f:
                    password = f.read()

            context = {
                "password": password, "profile": profile
            }

            try:
                final_res = a.run(active_input, job_dir, context)

                # Re-read job inside loop after a.run in case it updated it (like profile)
                job = jobs.get_job(job_id, redact_password=False)

                job['analyzers'][-1] = final_res

                if final_res.get('findings'):
                    seen = {(item.get('kind'), item.get('value')) for item in job['findings']}
                    for item in final_res['findings']:
                        key = (item.get('kind'), item.get('value'))
                        if key in seen:
                            continue
                        seen.add(key)
                        job['findings'].append(item)

                if final_res.get('status') == 'success':
                    has_success = True
                if final_res.get('status') in ('failed', 'timeout'):
                    has_failure = True

            except Exception as e:
                # Re-read job here as well to ensure consistency
                job = jobs.get_job(job_id, redact_password=False)
                res['status'] = 'failed'
                res['error'] = str(e)
                res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                job['analyzers'][-1] = res
                has_failure = True

            completed += 1
            job['progress']['completed'] = completed
            jobs._write_manifest(job_id, job)

        job = jobs.get_job(job_id, redact_password=False)
        if has_failure:
            if has_success:
                job['status'] = 'partial'
            else:
                job['status'] = 'failed'
        else:
            job['status'] = 'complete'

        job['progress']['current'] = None

        # Remove password file
        password_path = os.path.join(job_dir, "input", "password.txt")
        if os.path.exists(password_path):
            os.remove(password_path)

        jobs._write_manifest(job_id, job)

# Start the worker thread
worker = AnalyzerWorker()
worker.start()

def ensure_worker() -> None:
    """Restart the checker if the background thread has died. A dead thread leaves the only slot occupied."""
    global worker
    if worker is not None and worker.is_alive():
        return
    worker = AnalyzerWorker()
    worker.start()
