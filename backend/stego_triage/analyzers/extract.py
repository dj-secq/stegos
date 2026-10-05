import io
import os
import re
import shutil
import time
import zipfile
from typing import Dict, Any, List
from .base import Analyzer, register
from ..runner import run_bounded

_ZIP_LOCAL = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_INNER_EXTENSIONS = {".png", ".pdf", ".txt"}
_MAX_CARVE_FILES = 100
_MAX_CARVE_BYTES = 100 * 1024 * 1024

_SIGNATURE_LINE = re.compile(r"^\s*\d+\s+0x[0-9a-fA-F]+\s+")
_CARVE_KIND = re.compile(r"\b(?:gzip|zip|png|pdf)\b", re.I)


def signature_wants_extract(text: str) -> bool:
    """True when a binwalk signature row names zip, gzip, png, or pdf.

    Zlib rows are ignored. The match is limited to offset rows so a filename
    that merely contains those words does not start a carve.
    """
    for line in str(text or "").splitlines():
        if _SIGNATURE_LINE.match(line) and _CARVE_KIND.search(line):
            return True
    return False


def _read_log(path: str, limit: int = 1_000_000) -> str:
    try:
        with open(path, "r", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _append_log(dest: str, extra: str) -> None:
    if not os.path.isfile(extra):
        return
    with open(dest, "ab") as out, open(extra, "rb") as handle:
        out.write(b"\n")
        out.write(handle.read())
    os.remove(extra)


def png_text_findings(extract_dir: str) -> List[dict]:
    """Scan carved PNG text chunks, including compressed zTXt."""
    from .structure import iter_png_texts
    from ..flags import findings_for_text

    found = []
    if not os.path.isdir(extract_dir):
        return found
    seen = 0
    for root, _dirs, files in os.walk(extract_dir):
        for name in files:
            if seen >= 40 or len(found) >= 20:
                return found
            path = os.path.join(root, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                with open(path, "rb") as handle:
                    blob = handle.read(8 * 1024 * 1024 + 8)
            except OSError:
                continue
            if not blob.startswith(b"\x89PNG\r\n\x1a\n"):
                continue
            seen += 1
            for key, value in iter_png_texts(blob):
                found.extend(findings_for_text(value[:100000], f"binwalk png text {key}"))
                if len(found) >= 20:
                    return found
    return found

def _safe_member(name: str) -> str:
    base = os.path.basename(str(name or "").replace("\\", "/"))
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return (cleaned or "member.bin")[:80]


def _unsafe_member(name: str) -> bool:
    if str(name or "").startswith(("/", "\\")):
        return True
    parts = [part for part in str(name).replace("\\", "/").split("/") if part not in ("", ".")]
    return not parts or any(part == ".." for part in parts)


def _artifact_budget(job_dir: str) -> tuple[int, int]:
    root = os.path.join(job_dir, "artifacts")
    count = 0
    total = 0
    if not os.path.isdir(root):
        return count, total
    for name in os.listdir(root):
        path = os.path.join(root, name)
        if os.path.isfile(path) and not os.path.islink(path):
            count += 1
            total += os.path.getsize(path)
    return count, total


def _textish(payload: bytes) -> bool:
    sample = payload[:512]
    if not sample or b"\x00" in sample:
        return False
    printable = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in sample)
    return printable >= int(len(sample) * 0.9)


def open_carved_zip(blob: bytes, job_dir: str, prefix: str) -> tuple[list, list]:
    """Open one ZIP level. Save png, pdf, and txt members. Do not run them."""
    from ..flags import findings_for_bytes, findings_for_text
    from ..passphrase import strings_candidates

    artifacts = []
    findings = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return artifacts, findings
    count, total = _artifact_budget(job_dir)
    passphrase = None
    index = 0
    for info in archive.infolist()[:200]:
        name = str(info.filename or "")
        if not name or info.is_dir() or _unsafe_member(name):
            continue
        findings.extend(findings_for_text(name[:180], f"zip member name {name[:120]}"))
        extension = os.path.splitext(name)[1].lower()
        if info.flag_bits & 0x1 or info.file_size <= 0 or info.file_size > 8 * 1024 * 1024:
            continue
        if info.compress_size == 0 or info.file_size / info.compress_size > 100:
            continue
        try:
            payload = archive.read(info)
        except (RuntimeError, zipfile.BadZipFile, OSError, ValueError):
            continue
        if extension == ".txt" or _textish(payload):
            if passphrase is None:
                phrase = next((item for item in strings_candidates(payload[:200_000].decode("utf-8", "replace")) if item["kind"] == "passphrase_candidate"), None)
                if phrase:
                    passphrase = dict(phrase)
                    passphrase["id"] = "passphrase-zip-text"
                    passphrase["evidence"] = f"zip member {name[:120]}"
        if extension not in _INNER_EXTENSIONS:
            continue
        safe = _safe_member(name)
        if count >= _MAX_CARVE_FILES or total + len(payload) > _MAX_CARVE_BYTES:
            continue
        art_id = f"{prefix}_zip_{index}_{safe}"
        target = os.path.join(job_dir, "artifacts", art_id)
        if os.path.lexists(target):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as handle:
            handle.write(payload)
        os.chmod(target, 0o400)
        artifacts.append({
            "id": art_id,
            "name": safe,
            "media_type": "image/png" if extension == ".png" else "application/pdf" if extension == ".pdf" else "text/plain",
            "size": len(payload),
            "previewable": extension == ".png",
        })
        findings.extend(findings_for_bytes(payload[:262144], f"zip member {safe}"))
        count += 1
        total += len(payload)
        index += 1
    if passphrase:
        findings.append(passphrase)
    return artifacts, findings


def harvest_carved_zips(job_dir: str, artifacts: list, prefix: str) -> tuple[list, list]:
    added = []
    findings = []
    saw_passphrase = False
    for item in artifacts or []:
        art_id = str(item.get("id") or "")
        if not art_id or os.path.basename(art_id) != art_id:
            continue
        path = os.path.join(job_dir, "artifacts", art_id)
        if not os.path.isfile(path) or os.path.islink(path):
            continue
        with open(path, "rb") as handle:
            header = handle.read(8)
            if not header.startswith(_ZIP_LOCAL):
                continue
            handle.seek(0)
            blob = handle.read(8 * 1024 * 1024)
        extra, found = open_carved_zip(blob, job_dir, prefix)
        added.extend(extra)
        findings.extend(found)
        if any(entry.get("kind") == "passphrase_candidate" for entry in found):
            saw_passphrase = True
    if saw_passphrase:
        return added, findings
    from ..passphrase import strings_candidates
    for item in artifacts or []:
        name = str(item.get("name") or "")
        art_id = str(item.get("id") or "")
        if not name.lower().endswith(".txt") or os.path.basename(art_id) != art_id:
            continue
        path = os.path.join(job_dir, "artifacts", art_id)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as handle:
            payload = handle.read(200_000)
        if not _textish(payload):
            continue
        phrase = next((entry for entry in strings_candidates(payload.decode("utf-8", "replace")) if entry["kind"] == "passphrase_candidate"), None)
        if not phrase:
            continue
        phrase = dict(phrase)
        phrase["id"] = "passphrase-zip-text"
        phrase["evidence"] = f"zip member {name[:120]}"
        findings.append(phrase)
        break
    return added, findings


def register_artifacts(extract_dir: str, prefix: str, max_files: int = 100, max_bytes: int = 100 * 1024 * 1024) -> List[Dict]:
    artifacts = []
    if not os.path.exists(extract_dir):
        return artifacts
        
    total_bytes = 0
    for root, dirs, files in os.walk(extract_dir):
        for f in files:
            if len(artifacts) >= max_files:
                break
            full_path = os.path.join(root, f)
            if os.path.islink(full_path) or not os.path.isfile(full_path):
                continue
            
            size = os.path.getsize(full_path)
            if total_bytes + size > max_bytes:
                continue
            total_bytes += size
            
            rel_path = os.path.relpath(full_path, extract_dir)
            art_id = f"{prefix}_{len(artifacts)}_{f}"
            
            parent_artifacts = os.path.dirname(extract_dir)
            target = os.path.join(parent_artifacts, art_id)
            os.rename(full_path, target)
            
            artifacts.append({
                "id": art_id,
                "name": rel_path,
                "media_type": "application/octet-stream",
                "size": size,
                "previewable": False
            })
    return artifacts

@register
class BinwalkAnalyzer(Analyzer):
    id = "binwalk"
    name = "Binwalk"
    category = "extraction"
    order = 90
    quick = True
    deep = True
    may_extract = True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        err_path = os.path.join(job_dir, "logs", f"{self.id}_err.txt")
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        is_deep = context.get('profile') == 'deep'
        carve = False
        carve_note = ""
        duration = 0
        
        if is_deep:
            os.makedirs(extract_dir, exist_ok=True)
            run_res = run_bounded(["binwalk", "-e", "-C", extract_dir, input_path], job_dir, log_path, err_path)
            duration = run_res.duration_ms
            carve = run_res.exit_code == 0
        else:
            run_res = run_bounded(["binwalk", input_path], job_dir, log_path, err_path)
            duration = run_res.duration_ms
            scan_text = _read_log(log_path) or (run_res.stdout_preview or "")
            if run_res.exit_code == 0 and signature_wants_extract(scan_text):
                os.makedirs(extract_dir, exist_ok=True)
                ext_log = log_path + ".extract"
                ext = run_bounded(["binwalk", "-e", "-C", extract_dir, input_path], job_dir, ext_log, err_path)
                duration += ext.duration_ms
                carve = True
                if ext.exit_code != 0:
                    _append_log(log_path, ext_log)
                    carve_note = " Carve did not finish."
                elif os.path.exists(ext_log):
                    os.remove(ext_log)
        
        res['duration_ms'] = duration
        if run_res.exit_code == 0:
            res['status'] = 'success'
            out = _read_log(log_path) or (run_res.stdout_preview or "")
            lines = [line for line in out.split('\n') if line.strip() and not line.startswith('DECIMAL')]
            res['summary'] = f"Found {len(lines)} signatures."
            
            if os.path.isfile(log_path):
                res['artifacts'].append({
                    "id": f"{self.id}.txt",
                    "name": "binwalk.txt",
                    "media_type": "text/plain",
                    "size": os.path.getsize(log_path),
                    "previewable": True
                })
                res['log_artifact_id'] = f"{self.id}.txt"
            
            from ..flags import attach_flags
            extracted = []
            text_findings = []
            if carve:
                text_findings = png_text_findings(extract_dir)
                extracted = register_artifacts(extract_dir, self.id)
                res['artifacts'].extend(extracted)
                res['summary'] += f" Extracted {len(extracted)} files."
                if os.path.exists(extract_dir):
                    shutil.rmtree(extract_dir, ignore_errors=True)
            res['summary'] += carve_note
            if extracted:
                attach_flags(res, job_dir, "binwalk output", extracted, log_path)
                extra_artifacts, extra_findings = harvest_carved_zips(job_dir, extracted, self.id)
                res['artifacts'].extend(extra_artifacts)
                res['findings'].extend(extra_findings)
            else:
                attach_flags(res, job_dir, "binwalk output", log_path=log_path)
            res['findings'].extend(text_findings)
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class ForemostAnalyzer(Analyzer):
    id = "foremost"
    name = "Foremost"
    category = "extraction"
    order = 95
    quick = False
    deep = True
    may_extract = True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        extract_dir = os.path.join(job_dir, "artifacts", f"_{self.id}_out")
        os.makedirs(extract_dir, exist_ok=True)
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        args = ["foremost", "-Q", "-o", extract_dir, "-i", input_path]
            
        run_res = run_bounded(args, job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        
        extracted = register_artifacts(extract_dir, self.id)
        if len(extracted) > 0:
            res['status'] = 'success'
            res['summary'] = f"Carved {len(extracted)} files."
            res['artifacts'].extend(extracted)
            from ..flags import attach_flags
            attach_flags(res, job_dir, "foremost carve", extracted, log_path)
        elif run_res.exit_code == 0:
            res['status'] = 'no_result'
            res['summary'] = "No files carved."
        else:
            res['status'] = 'failed'
            res['error'] = run_res.error or f"Exit code {run_res.exit_code}"
            
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)
            
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
