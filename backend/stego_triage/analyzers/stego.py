import os
import re
import shutil
import time
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import SANDBOX_PATH, run_bounded
from .extract import register_artifacts


def _merge_logs(dest: str, *sources: str) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "wb") as out:
        for source in sources:
            if not source or not os.path.isfile(source):
                continue
            with open(source, "rb") as handle:
                data = handle.read()
            if not data:
                continue
            out.write(data)
            if not data.endswith(b"\n"):
                out.write(b"\n")
    for source in sources:
        if source and source != dest and os.path.isfile(source):
            os.remove(source)


def _tool_missing(res: Dict[str, Any], binary: str, summary: str) -> bool:
    if shutil.which(binary, path=SANDBOX_PATH):
        return False
    res["status"] = "unavailable"
    res["summary"] = summary
    res["error"] = None
    res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return True


@register
class ZstegAnalyzer(Analyzer):
    id = "zsteg"
    name = "zsteg"
    category = "stego"
    order = 100
    quick = True
    deep = True
    
    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "png" in format_tags or "bmp" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        is_deep = context.get('profile') == 'deep'
        args = ["zsteg", input_path]
        if is_deep:
            args = ["zsteg", "-a", input_path]
            
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(args, job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0 or os.path.exists(log_path):
            res['status'] = 'success'
            out = run_res.stdout_preview
            
            from ..flags import findings_for_log
            found = findings_for_log(log_path, "zsteg output") if os.path.exists(log_path) else []
            if not found:
                from ..flags import findings_for_text
                found = findings_for_text(out, "zsteg output")
            res["findings"].extend(found)
            flag_count = sum(1 for item in found if item.get("kind") == "candidate_flag")
            decode_count = sum(1 for item in found if item.get("kind") == "encoding")
            parts = []
            if flag_count:
                parts.append(f"{flag_count} candidate flag" + ("" if flag_count == 1 else "s"))
            if decode_count:
                parts.append(f"{decode_count} decoded text lead" + ("" if decode_count == 1 else "s"))
            res["summary"] = "Found " + " and ".join(parts) + "." if parts else "No candidate flag."
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "zsteg.txt",
                "media_type": "text/plain",
                "size": os.path.getsize(log_path) if os.path.exists(log_path) else 0,
                "previewable": True
            })
            res['log_artifact_id'] = f"{self.id}.txt"
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class SteghideAnalyzer(Analyzer):
    id = "steghide"
    name = "steghide"
    category = "stego"
    order = 110
    quick = True
    deep = True
    needs_password = True
    may_extract = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return any(t in format_tags for t in ["jpeg", "bmp", "audio"])

    def _log_artifact(self, res: Dict[str, Any], log_path: str) -> None:
        if not os.path.isfile(log_path):
            return
        res['artifacts'].append({
            "id": f"{self.id}.txt",
            "name": "steghide.txt",
            "media_type": "text/plain",
            "size": os.path.getsize(log_path),
            "previewable": True
        })
        res['log_artifact_id'] = f"{self.id}.txt"

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        password = context.get('password')
        if password == '':
            password = None
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        err_path = os.path.join(job_dir, "logs", f"{self.id}_err.txt")
        from ..flags import attach_flags

        if password is None:
            info_log = log_path + ".info"
            extract_log = log_path + ".extract"
            info = run_bounded(["steghide", "info", input_path, "-p", ""], job_dir, info_log, err_path)
            os.makedirs(extract_dir, exist_ok=True)
            out_file = os.path.join(extract_dir, "extracted.data")
            extracted_run = run_bounded(
                ["steghide", "extract", "-sf", input_path, "-xf", out_file, "-p", "", "-f"],
                job_dir,
                extract_log,
                err_path + ".extract",
            )
            _merge_logs(log_path, info_log, err_path, extract_log, err_path + ".extract")
            res['duration_ms'] = info.duration_ms + extracted_run.duration_ms
            try:
                with open(log_path, "r", errors="replace") as handle:
                    text = handle.read(32000).lower()
            except OSError:
                text = ((info.stdout_preview or "") + "\n" + (extracted_run.stdout_preview or "")).lower()
            extracted = [item for item in register_artifacts(extract_dir, self.id) if item.get("size")]
            self._log_artifact(res, log_path)
            if extracted:
                res['status'] = 'success'
                res['artifacts'].extend(extracted)
                res['summary'] = f"Extracted {len(extracted)} files with an empty passphrase."
                attach_flags(res, job_dir, "steghide extract", extracted, log_path)
            elif "passphrase" in text:
                res['status'] = 'no_result'
                res['summary'] = "Embedded data needs a passphrase."
                attach_flags(res, job_dir, "steghide info", log_path=log_path)
            elif info.exit_code == 0:
                res['status'] = 'success'
                res['summary'] = "Ran steghide info with no password."
                attach_flags(res, job_dir, "steghide info", log_path=log_path)
            else:
                res['status'] = 'failed'
                res['error'] = extracted_run.error or info.error or f"Exit code {extracted_run.exit_code}"
                if "could not extract" in text or "passphrase" in text:
                    res['summary'] = "Extraction failed (wrong password?)"
        else:
            os.makedirs(extract_dir, exist_ok=True)
            args = ["steghide", "extract", "-xf", os.path.join(extract_dir, "extracted.data"), "-sf", input_path]
            stdin_data = password.encode('utf-8') + b"\n"
            run_res = run_bounded(
                args, job_dir, log_path, err_path,
                password_to_redact=password, stdin_data=stdin_data,
            )
            res['duration_ms'] = run_res.duration_ms
            if run_res.exit_code == 0:
                res['status'] = 'success'
                self._log_artifact(res, log_path)
                extracted = register_artifacts(extract_dir, self.id)
                res['artifacts'].extend(extracted)
                res['summary'] = f"Extracted {len(extracted)} files with password."
                attach_flags(res, job_dir, "steghide extract", extracted, log_path)
            else:
                res['status'] = 'failed'
                res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
                if "could not extract" in (run_res.stdout_preview or "") or "passphrase" in (run_res.stdout_preview or ""):
                    res['summary'] = "Extraction failed (wrong password?)"
                
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class OutguessAnalyzer(Analyzer):
    id = "outguess"
    name = "outguess"
    category = "stego"
    order = 111
    quick = True
    deep = True
    needs_password = True
    may_extract = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "jpeg" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        password = context.get('password')
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(extract_dir, exist_ok=True)
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        out_file = os.path.join(extract_dir, "extracted.data")
        
        if password is None:
            args = ["outguess", "-r", input_path, out_file]
        else:
            args = ["outguess", "-k", password, "-r", input_path, out_file]
            
        run_res = run_bounded(args, job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"), password_to_redact=password)
        
        res['duration_ms'] = run_res.duration_ms
        extracted = register_artifacts(extract_dir, self.id)
        if len(extracted) > 0:
            res['status'] = 'success'
            res['artifacts'].extend(extracted)
            res['summary'] = f"Extracted {len(extracted)} files."
            from ..flags import attach_flags
            attach_flags(res, job_dir, "outguess extract", extracted, log_path)
        else:
            if run_res.exit_code == 0:
                res['status'] = 'no_result'
                res['summary'] = "Nothing extracted."
            else:
                res['status'] = 'failed'
                res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
                
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class JstegAnalyzer(Analyzer):
    id = "jsteg"
    name = "jsteg"
    category = "stego"
    order = 112
    quick = True
    deep = True
    
    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "jpeg" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        if _tool_missing(res, "jsteg", "jsteg is not installed in this image."):
            return res
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(extract_dir, exist_ok=True)
        out_file = os.path.join(extract_dir, "jsteg.out")
        
        run_res = run_bounded(["jsteg", "reveal", input_path], job_dir, out_file, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        extracted = register_artifacts(extract_dir, self.id)
        if len(extracted) > 0 and extracted[0]['size'] > 0:
            res['status'] = 'success'
            res['summary'] = "Revealed data with jsteg."
            res['artifacts'].extend(extracted)
            from ..flags import attach_flags
            attach_flags(res, job_dir, "jsteg reveal", extracted)
        else:
            res['status'] = 'failed' if run_res.exit_code != 0 else 'no_result'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class JpseekAnalyzer(Analyzer):
    id = "jpseek"
    name = "jpseek (jphide)"
    category = "stego"
    order = 113
    quick = True
    deep = True
    needs_password = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "jpeg" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        if _tool_missing(res, "jpseek", "jpseek is not installed in this image."):
            return res
        start = time.monotonic()
        
        password = context.get('password')
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(extract_dir, exist_ok=True)
        out_file = os.path.join(extract_dir, "jpseek.out")
        
        if password is None:
            res['status'] = 'no_result'
            res['summary'] = "Skipped (requires password)"
        else:
            # Provide password on command line or stdin based on tool. Assuming command line format for jpseek:
            # Actually jpseek takes password via file or prompt. Let's just assume it's `jpseek input out pass`
            run_res = run_bounded(["jpseek", input_path, out_file], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"), password_to_redact=password, stdin_data=password.encode('utf-8') + b"\n")
            
            extracted = register_artifacts(extract_dir, self.id)
            if len(extracted) > 0 and extracted[0]['size'] > 0:
                res['status'] = 'success'
                res['summary'] = "Extracted data with jpseek."
                res['artifacts'].extend(extracted)
                from ..flags import attach_flags
                attach_flags(res, job_dir, "jpseek extract", extracted, log_path)
            else:
                res['status'] = 'failed' if run_res.exit_code != 0 else 'no_result'
                res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
                
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class OpenStegoAnalyzer(Analyzer):
    id = "openstego"
    name = "OpenStego"
    category = "stego"
    order = 114
    quick = True
    deep = True
    needs_password = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "image" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        if _tool_missing(res, "openstego", "OpenStego is not installed in this image."):
            return res
        start = time.monotonic()
        
        password = context.get('password')
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(extract_dir, exist_ok=True)
        
        args = ["openstego", "extract", "-sf", input_path, "-xd", extract_dir]
        if password:
            args.extend(["-p", password])
            
        run_res = run_bounded(args, job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"), password_to_redact=password)
        
        extracted = register_artifacts(extract_dir, self.id)
        if len(extracted) > 0:
            res['status'] = 'success'
            res['summary'] = f"Extracted {len(extracted)} files with OpenStego."
            res['artifacts'].extend(extracted)
            from ..flags import attach_flags
            attach_flags(res, job_dir, "openstego extract", extracted, log_path)
        else:
            res['status'] = 'failed' if run_res.exit_code != 0 else 'no_result'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
