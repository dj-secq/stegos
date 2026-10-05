import os
import re
import time
import json
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import run_bounded

from ..flags import findings_for_text
from ..passphrase import metadata_candidates, strings_candidates

def extract_flags(text: str) -> list:
    return findings_for_text(text, "strings or metadata")


_STRING_OFFSET = re.compile(r"^[0-9a-fA-F]+$")


def _annotate_strings(findings, content):
    encoding = "ASCII"
    by_line = {}
    for number, line in enumerate(str(content or "").splitlines(), 1):
        if line.startswith("## "):
            encoding = line[3:].strip() or encoding
            continue
        by_line[number] = (encoding, line)
    for item in findings:
        meta = by_line.get(item.get("line"))
        if not meta:
            continue
        label, line = meta
        if label and label != "ASCII":
            item["evidence"] = f"strings, {label}"
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and _STRING_OFFSET.fullmatch(parts[0]):
            item["offset"] = "0x" + parts[0].lower()
    return findings

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
        # ASCII, UTF-16 LE, and UTF-16 BE. Markers keep each pass identifiable.
        quoted = input_path.replace("'", "'\\''")
        command = (
            f"printf '%s\\n' '## ASCII'; strings -n 6 -a -t x '{quoted}'; "
            f"printf '%s\\n' '## UTF-16 LE'; strings -n 6 -a -t x -e l '{quoted}'; "
            f"printf '%s\\n' '## UTF-16 BE'; strings -n 6 -a -t x -e b '{quoted}'"
        )
        run_res = run_bounded(
            ["sh", "-c", command],
            job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt")
        )
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0 or os.path.exists(log_path):
            res['status'] = 'success'
            try:
                with open(log_path, "r", errors="replace") as f:
                    content = f.read(1_000_000)
                
                flags = _annotate_strings(extract_flags(content), content)
                phrases = _annotate_strings(strings_candidates(content), content)
                res['findings'].extend(flags)
                res['findings'].extend(phrases)
                flag_count = sum(1 for item in flags if item.get("kind") == "candidate_flag")
                decode_count = sum(1 for item in flags if item.get("kind") == "encoding")
                res['summary'] = f"Found strings. {flag_count} candidate flags."
                if decode_count:
                    noun = "lead" if decode_count == 1 else "leads"
                    res['summary'] += f" {decode_count} decoded text {noun}."
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
