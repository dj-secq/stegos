import os
import hashlib
import json
import time
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import run_bounded
from ..jobs import _write_manifest, get_job
from ..passphrase import filename_candidate
from ..flags import charset_finding

@register
class FileProfileAnalyzer(Analyzer):
    id = "profile"
    name = "File Profile"
    category = "metadata"
    order = 10
    quick = True
    deep = True
    
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        res['status'] = 'running'
        start = time.monotonic()
        
        try:
            # Checksums
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            
            with open(input_path, "rb") as f:
                sample = f.read(65536)
                if sample:
                    md5.update(sample)
                    sha256.update(sample)
                while chunk := f.read(65536):
                    md5.update(chunk)
                    sha256.update(chunk)
                    
            hashes = {
                "md5": md5.hexdigest(),
                "sha256": sha256.hexdigest()
            }
            
            # Use 'file' command to detect MIME
            file_res = run_bounded(["file", "--brief", "--mime-type", input_path], job_dir, os.path.join(job_dir, "logs", "mime.txt"), os.path.join(job_dir, "logs", "mime_err.txt"))
            detected_mime = file_res.stdout_preview.strip() if file_res.exit_code == 0 else "application/octet-stream"
            
            # Simple kind mapping
            kind = "generic"
            format_tags = []
            if detected_mime.startswith("image/"):
                kind = "image"
                format_tags.append("image")
                if "png" in detected_mime: format_tags.append("png")
                elif "jpeg" in detected_mime or "jpg" in detected_mime: format_tags.append("jpeg")
                elif "gif" in detected_mime: format_tags.append("gif")
                elif "bmp" in detected_mime: format_tags.append("bmp")
            elif detected_mime.startswith("audio/"):
                kind = "audio"
                format_tags.append("audio")
            elif detected_mime == "application/pdf":
                kind = "pdf"
                format_tags.append("pdf")
                
            # Update manifest with detected profile
            job_id = os.path.basename(job_dir)
            job = get_job(job_id, redact_password=False)
            if job:
                job["input"]["hashes"] = hashes
                job["input"]["detected_mime"] = detected_mime
                job["input"]["kind"] = kind
                job["input"]["format_tags"] = format_tags
                
                # Check for mismatch
                declared = job["input"].get("declared_mime", "")
                if declared and declared != "application/octet-stream" and not declared.startswith(detected_mime.split('/')[0]):
                    job["warnings"].append(f"MIME mismatch: declared {declared}, detected {detected_mime}")
                    
                _write_manifest(job_id, job)
            
            res['summary'] = f"Detected {detected_mime}, kind: {kind}"
            res['findings'].append({
                "id": "md5",
                "kind": "checksum",
                "confidence": "high",
                "title": "MD5 (CTF comparison)",
                "value": hashes["md5"],
                "evidence": ""
            })
            res['findings'].append({
                "id": "sha256",
                "kind": "checksum",
                "confidence": "high",
                "title": "SHA-256",
                "value": hashes["sha256"],
                "evidence": ""
            })
            res['findings'].append(charset_finding(sample))
            if job:
                named = filename_candidate(job["input"].get("display_name"))
                if named:
                    res['findings'].append(named)
            
            res['status'] = 'success'
        except Exception as e:
            res['status'] = 'failed'
            res['error'] = str(e)
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
