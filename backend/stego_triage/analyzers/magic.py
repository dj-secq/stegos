import os
import time
from typing import Dict, Any, List, Optional, Tuple

from .base import Analyzer, register
from ..flags import findings_for_bytes
from ..jobs import get_job, _write_manifest

MAX_FILE = 32 * 1024 * 1024
MAX_HEAD = 4096
MAX_TRAILING = 64 * 1024

SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "png", "image/png", "repaired.png"),
    (b"\xff\xd8\xff", "jpeg", "image/jpeg", "repaired.jpg"),
    (b"GIF89a", "gif", "image/gif", "repaired.gif"),
    (b"GIF87a", "gif", "image/gif", "repaired.gif"),
    (b"PK\x03\x04", "zip", "application/zip", "repaired.zip"),
    (b"%PDF-", "pdf", "application/pdf", "repaired.pdf"),
    (b"BM", "bmp", "image/bmp", "repaired.bmp"),
    (b"RIFF", "riff", "application/octet-stream", "repaired.riff"),
)

KIND_TAGS = {
    "png": ("image", ["image", "png"], "image/png"),
    "jpeg": ("image", ["image", "jpeg"], "image/jpeg"),
    "gif": ("image", ["image", "gif"], "image/gif"),
    "bmp": ("image", ["image", "bmp"], "image/bmp"),
    "pdf": ("pdf", ["pdf"], "application/pdf"),
    "zip": ("generic", ["zip"], "application/zip"),
    "wave": ("audio", ["audio"], "audio/wav"),
    "webp": ("image", ["image", "webp"], "image/webp"),
    "avi": ("generic", ["avi"], "video/x-msvideo"),
    "riff": ("generic", ["riff"], "application/octet-stream"),
}


def _riff_ok(data: bytes, index: int) -> bool:
    end = index + 12
    if end > len(data):
        return False
    return data[index + 8:index + 12] in (b"WAVE", b"WEBP", b"AVI ")


def earliest_signature(data: bytes):
    head = data[:MAX_HEAD]
    best = None
    for sig, kind, mime, filename in SIGNATURES:
        index = head.find(sig)
        if index < 0:
            continue
        if sig == b"BM" and index > 4:
            continue
        if sig == b"RIFF" and not _riff_ok(data, index):
            continue
        if best is None or index < best[0]:
            best = (index, kind, mime, filename)
    return best


def refine_kind(data: bytes, index: int, kind: str, mime: str, filename: str):
    if kind == "riff" and index + 12 <= len(data):
        fourcc = data[index + 8:index + 12]
        if fourcc == b"WAVE":
            return "wave", "audio/wav", "repaired.wav"
        if fourcc == b"WEBP":
            return "webp", "image/webp", "repaired.webp"
        if fourcc == b"AVI ":
            return "avi", "video/x-msvideo", "repaired.avi"
    return kind, mime, filename


def structural_repair(data: bytes) -> Optional[Tuple[bytes, str, str, str, str]]:
    if len(data) >= 16 and data[12:16] == b"IHDR" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        repaired = b"\x89PNG\r\n\x1a\n" + data[8:]
        return repaired, "Restored the PNG signature in front of IHDR.", "image/png", "repaired.png", "png"
    if len(data) >= 6 and data[3:6] in (b"87a", b"89a") and not data.startswith((b"GIF87a", b"GIF89a")):
        repaired = b"GIF" + data[3:]
        return repaired, "Restored the GIF signature.", "image/gif", "repaired.gif", "gif"
    window = data[:64]
    for name, marker in ((b"JFIF", b"\xff\xe0"), (b"Exif", b"\xff\xe1")):
        found = window.find(name)
        if found < 0 or data.startswith(b"\xff\xd8\xff"):
            continue
        if found >= 4 and data[found - 4] == 0xFF:
            body = data[found - 4:]
        elif found >= 2:
            body = marker + data[found - 2:]
        else:
            continue
        repaired = body if body.startswith(b"\xff\xd8") else b"\xff\xd8" + body
        return repaired, "Restored the JPEG start marker.", "image/jpeg", "repaired.jpg", "jpeg"
    return None


def _meaningful(extra: bytes) -> bool:
    return bool(extra) and len(extra) <= MAX_TRAILING and bool(extra.strip(b"\x00\r\n\t "))


def trailing_bytes(data: bytes) -> Optional[bytes]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        index = data.rfind(b"IEND")
        if index >= 8:
            extra = data[index + 8:]
            if _meaningful(extra):
                return extra
    if data.startswith(b"\xff\xd8\xff"):
        index = data.rfind(b"\xff\xd9")
        if index >= 0:
            extra = data[index + 2:]
            if _meaningful(extra):
                return extra
    if data.startswith((b"GIF87a", b"GIF89a")):
        index = data.rfind(b"\x3b")
        if index >= 6:
            extra = data[index + 1:]
            if _meaningful(extra):
                return extra
    if data.startswith(b"%PDF-"):
        index = data.rfind(b"%%EOF")
        if index >= 0:
            extra = data[index + 5:]
            if _meaningful(extra):
                return extra
    if data.startswith(b"PK\x03\x04"):
        start = max(0, len(data) - (22 + 65535))
        index = data.rfind(b"PK\x05\x06", start)
        if index >= 0 and index + 22 <= len(data):
            comment_len = int.from_bytes(data[index + 20:index + 22], "little")
            end = index + 22 + comment_len
            if end <= len(data):
                extra = data[end:]
                if _meaningful(extra):
                    return extra
    if data.startswith(b"RIFF") and len(data) >= 12:
        declared = int.from_bytes(data[4:8], "little")
        end = 8 + declared
        if 12 <= end < len(data):
            extra = data[end:]
            if _meaningful(extra):
                return extra
    if data.startswith(b"BM") and len(data) >= 6:
        declared = int.from_bytes(data[2:6], "little")
        if 54 <= declared < len(data):
            extra = data[declared:]
            if _meaningful(extra):
                return extra
    return None


def _write(path: str, blob: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(blob)


def _texty(blob: bytes) -> bool:
    sample = blob[:512]
    if not sample or b"\x00" in sample:
        return False
    ok = sum(32 <= byte <= 126 or byte in (9, 10, 13) for byte in sample)
    return ok / len(sample) > 0.85


def publish_repair(job_dir: str, filename: str, kind: str) -> None:
    file_kind, tags, mime = KIND_TAGS.get(kind, ("generic", [kind], "application/octet-stream"))
    job_id = os.path.basename(job_dir)
    job = get_job(job_id, redact_password=False)
    if not job:
        return
    job["input"]["analysis_file"] = filename
    job["input"]["kind"] = file_kind
    job["input"]["format_tags"] = tags
    job["input"]["detected_mime"] = mime
    declared = job["input"].get("declared_mime") or ""
    warnings = [item for item in job.get("warnings") or [] if not str(item).startswith("MIME mismatch:")]
    if declared and declared != "application/octet-stream" and declared.split("/")[0] != mime.split("/")[0]:
        warnings.append(f"MIME mismatch: declared {declared}, repaired copy is {mime}")
    note = "Later checks use the repaired copy. The uploaded file was not modified."
    if note not in warnings:
        warnings.append(note)
    job["warnings"] = warnings
    _write_manifest(job_id, job)


def _stamp(res: Dict[str, Any], start: float, status: str, summary: str) -> Dict[str, Any]:
    res["status"] = status
    res["summary"] = summary
    res["duration_ms"] = int((time.monotonic() - start) * 1000)
    res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return res


@register
class MagicRepairAnalyzer(Analyzer):
    id = "magic_repair"
    name = "Magic byte repair"
    category = "structure"
    order = 12
    quick = True
    deep = True
    may_extract = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return True

    def _save(self, res, job_dir, name, blob, mime, previewable):
        _write(os.path.join(job_dir, "artifacts", name), blob)
        res["artifacts"].append({
            "id": name,
            "name": name,
            "media_type": mime,
            "size": len(blob),
            "previewable": previewable,
        })
        res["findings"].extend(findings_for_bytes(blob[:262144], name))
        if blob.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            from .extract import open_carved_zip
            extra_artifacts, extra_findings = open_carved_zip(blob, job_dir, "magic")
            res["artifacts"].extend(extra_artifacts)
            res["findings"].extend(extra_findings)

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            size = os.path.getsize(input_path)
            with open(input_path, "rb") as handle:
                data = handle.read(MAX_FILE + 1)
            too_big = size > MAX_FILE
            found = earliest_signature(data[:MAX_HEAD] if too_big else data)
            if (
                found
                and not too_big
                and found[1] == "bmp"
                and len(data) >= 16
                and data[12:16] == b"IHDR"
            ):
                found = None
            notes = []
            repaired_name = None
            repaired_kind = None
            if found and found[0] == 0:
                extra = None if too_big else trailing_bytes(data)
                if extra:
                    self._save(res, job_dir, "trailing.bin", extra, "application/octet-stream", _texty(extra))
                    notes.append(f"Saved {len(extra)} trailing bytes after the container end.")
                else:
                    return _stamp(res, start, "no_result", "The file already starts with a known signature.")
            elif found and found[0] > 0:
                index, kind, mime, filename = found
                kind, mime, filename = refine_kind(data, index, kind, mime, filename)
                if too_big:
                    notes.append(f"A {kind.upper()} signature starts at byte {index}. The file is too large to copy here.")
                else:
                    carved = data[index:]
                    self._save(res, job_dir, filename, carved, mime, mime.startswith("image/"))
                    notes.append(
                        f"Dropped {index} bytes before the {kind.upper()} signature. The original file was not modified."
                    )
                    extra = trailing_bytes(carved)
                    if extra:
                        self._save(res, job_dir, "trailing.bin", extra, "application/octet-stream", _texty(extra))
                        notes.append(f"Saved {len(extra)} trailing bytes after the container end.")
                    repaired_name = filename
                    repaired_kind = kind
            else:
                structural = None if too_big else structural_repair(data)
                if structural:
                    repaired, message, mime, filename, kind = structural
                    self._save(res, job_dir, filename, repaired, mime, mime.startswith("image/"))
                    notes.append(message + " The original file was not modified.")
                    extra = trailing_bytes(repaired)
                    if extra:
                        self._save(res, job_dir, "trailing.bin", extra, "application/octet-stream", _texty(extra))
                        notes.append(f"Saved {len(extra)} trailing bytes after the container end.")
                    repaired_name = filename
                    repaired_kind = kind
                elif not notes:
                    return _stamp(res, start, "no_result", "No misplaced signature or trailing bytes to repair.")

            if repaired_name and repaired_kind and not too_big:
                publish_repair(job_dir, repaired_name, repaired_kind)
            if notes:
                res["status"] = "success"
                res["summary"] = " ".join(notes)
                res["findings"].insert(0, {
                    "id": "magic-repair",
                    "kind": "observation",
                    "confidence": "high",
                    "title": "File header repair",
                    "value": res["summary"],
                    "evidence": "",
                })
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        res["duration_ms"] = int((time.monotonic() - start) * 1000)
        res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
