import os
import shutil
import time
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import run_bounded

@register
class PdfInfoAnalyzer(Analyzer):
    id = "pdfinfo"
    name = "pdfinfo"
    category = "metadata"
    order = 120
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "pdf" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(["pdfinfo", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0:
            res['status'] = 'success'
            res['summary'] = "Extracted PDF metadata."
            from ..flags import attach_flags
            attach_flags(res, job_dir, "pdfinfo", log_path=log_path)
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "pdfinfo.txt",
                "media_type": "text/plain",
                "size": os.path.getsize(log_path),
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.txt"
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class PdfIdAnalyzer(Analyzer):
    id = "pdfid"
    name = "pdfid"
    category = "metadata"
    order = 121
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "pdf" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        if shutil.which("pdfid") is None:
            res["status"] = "unavailable"
            res["summary"] = "pdfid is not installed in this image."
            res["error"] = None
            res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            return res
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(["pdfid", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0:
            res['status'] = 'success'
            res['summary'] = "Scanned PDF streams and structures."
            from ..flags import attach_flags
            attach_flags(res, job_dir, "pdfid", log_path=log_path)
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "pdfid.txt",
                "media_type": "text/plain",
                "size": os.path.getsize(log_path),
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.txt"
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
