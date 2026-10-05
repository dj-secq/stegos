import os
import time
import json
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import run_bounded

from ..flags import findings_for_text
from ..passphrase import metadata_candidates, strings_candidates

def extract_flags(text: str) -> list:
    return findings_for_text(text, "strings or metadata")

@register
class FileAnalyzer(Analyzer):
    id = "file"
    name = "file"
    category = "metadata"
    order = 20
    quick = True
    deep = True
    
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(["file", "--brief", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0:
            res['status'] = 'success'
            out = run_res.stdout_preview.strip()
            res['summary'] = out[:200] + "..." if len(out) > 200 else out
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "file-output.txt",
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
class ExifToolAnalyzer(Analyzer):
    id = "exiftool"
    name = "ExifTool"
    category = "metadata"
    order = 30
    quick = True
    deep = True
    
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.json")
        run_res = run_bounded(["exiftool", "-j", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0:
            res['status'] = 'success'
            try:
                with open(log_path, "r") as f:
                    data = json.load(f)
                    if data:
                        metadata = data[0]
                        interesting = []
                        for k, v in metadata.items():
                            if k.lower() in ('comment', 'description', 'artist', 'author', 'software'):
                                interesting.append(f"{k}: {v}")
                            # Also look for flags in string values
                            if isinstance(v, str):
                                res['findings'].extend(extract_flags(v))
                        res['findings'].extend(metadata_candidates(metadata))
                        res['summary'] = f"Found {len(metadata)} tags"
                        if interesting:
                            res['summary'] += f" | {', '.join(interesting[:3])}"
            except Exception:
                res['summary'] = "Metadata extracted but could not be parsed as JSON."
                
            res['artifacts'].append({
                "id": f"{self.id}.json",
                "name": "exiftool.json",
                "media_type": "application/json",
                "size": os.path.getsize(log_path),
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.json"
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class IdentifyAnalyzer(Analyzer):
    id = "identify"
    name = "Identify"
    category = "metadata"
    order = 40
    quick = True
    deep = True
    
    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "image"
        
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(["identify", "-verbose", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0:
            res['status'] = 'success'
            out = run_res.stdout_preview.strip()
            # Try to grab the first line for summary
            res['summary'] = out.split('\n')[0][:200] if out else "Image identified."
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "identify.txt",
                "media_type": "text/plain",
                "size": os.path.getsize(log_path),
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.txt"
        else:
            if run_res.timed_out:
                res['status'] = 'timeout'
            else:
                res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class StringsAnalyzer(Analyzer):
    id = "strings"
    name = "Strings"
    category = "metadata"
    order = 50
    quick = True
    deep = True
    
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        # Extract both ascii and utf-16
        run_res = run_bounded(
            ["sh", "-c", f"strings -n 6 -a -t x '{input_path}'; strings -n 6 -a -t x -e l '{input_path}'"],
            job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt")
        )
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0 or os.path.exists(log_path):
            res['status'] = 'success'
            try:
                with open(log_path, "r", errors="replace") as f:
                    content = f.read(1_000_000)
                
                flags = extract_flags(content)
                res['findings'].extend(flags)
                res['findings'].extend(strings_candidates(content))
                
                res['summary'] = f"Found strings. {len(flags)} candidate flags."
            except Exception:
                res['summary'] = "Extracted strings."
                
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "strings.txt",
                "media_type": "text/plain",
                "size": os.path.getsize(log_path),
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.txt"
            res['truncated'] = run_res.stdout_truncated
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
