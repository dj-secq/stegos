import os
import struct
import zlib
import time
from typing import Dict, Any, List
from .base import Analyzer, register
from ..flags import findings_for_text
from ..runner import run_bounded

@register
class PngcheckAnalyzer(Analyzer):
    id = "pngcheck"
    name = "pngcheck"
    category = "structure"
    order = 80
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "png" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
        run_res = run_bounded(["pngcheck", "-v", input_path], job_dir, log_path, os.path.join(job_dir, "logs", f"{self.id}_err.txt"))
        
        res['duration_ms'] = run_res.duration_ms
        if run_res.exit_code == 0 or run_res.exit_code == 1 or run_res.exit_code == 2:
            res['status'] = 'success'
            out = run_res.stdout_preview
            
            # Simple parsing
            errors = []
            for number, line in enumerate(out.split('\n'), 1):
                if 'ERROR' in line or 'invalid' in line or 'CRC error' in line or 'illegal' in line:
                    errors.append((number, line.strip()))
            
            if errors:
                res['summary'] = f"Found {len(errors)} structural warnings/errors."
                for number, e in errors[:5]:
                    excerpt = e if len(e) <= 160 else e[:157] + "..."
                    res['findings'].append({
                        "id": f"pngcheck_err_{hash(e)}",
                        "kind": "observation",
                        "confidence": "high",
                        "title": "PNG Structural Error",
                        "value": e,
                        "evidence": "pngcheck",
                        "line": number,
                        "excerpt": excerpt,
                    })
            else:
                res['summary'] = "No structural errors found."
                
            res['artifacts'].append({
                "id": f"{self.id}.txt",
                "name": "pngcheck.txt",
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

def repair_png_ihdr(input_path: str, output_path: str, max_dim: int = 4000) -> str:
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
        
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return "Not a PNG file"
        
    ihdr_start = 8
    length = struct.unpack(">I", data[ihdr_start:ihdr_start+4])[0]
    chunk_type = data[ihdr_start+4:ihdr_start+8]
    if chunk_type != b"IHDR":
        return "IHDR not found where expected"
        
    ihdr_data = data[ihdr_start+8:ihdr_start+8+length]
    crc_expected = struct.unpack(">I", data[ihdr_start+8+length:ihdr_start+12+length])[0]
    
    crc_actual = zlib.crc32(chunk_type + ihdr_data) & 0xffffffff
    
    if crc_expected == crc_actual:
        return None # No repair needed for IHDR
        
    # Let's see if we can brute force width and height
    # Width and height are the first 8 bytes of IHDR data (4 bytes each)
    found = False
    for w in range(1, max_dim):
        for h in range(1, max_dim):
            test_ihdr = struct.pack(">II", w, h) + ihdr_data[8:]
            if zlib.crc32(chunk_type + test_ihdr) & 0xffffffff == crc_expected:
                ihdr_data = test_ihdr
                found = True
                break
        if found: break
        
    if not found:
        # Just fix the CRC directly
        fixed_crc = struct.pack(">I", crc_actual)
        data[ihdr_start+8+length:ihdr_start+12+length] = fixed_crc
        msg = f"Fixed incorrect IHDR CRC to {hex(crc_actual)}"
    else:
        w, h = struct.unpack(">II", ihdr_data[:8])
        data[ihdr_start+8:ihdr_start+8+length] = ihdr_data
        msg = f"Bruteforced dimensions to {w}x{h}"
        
    with open(output_path, "wb") as f:
        f.write(data)
        
    return msg

@register
class PngRepairAnalyzer(Analyzer):
    id = "png_repair"
    name = "PNG Repair"
    category = "structure"
    order = 85
    quick = True
    deep = True
    may_extract = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "png" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        
        try:
            out_name = "repaired.png"
            out_path = os.path.join(job_dir, "artifacts", out_name)
            msg = repair_png_ihdr(input_path, out_path)
            
            if msg is None:
                res['status'] = 'no_result'
                res['summary'] = "Image structure appears valid; no repair needed."
            elif msg.startswith("Not a PNG") or msg.startswith("IHDR not found"):
                res['status'] = 'failed'
                res['error'] = msg
            else:
                res['status'] = 'success'
                res['summary'] = msg
                res['artifacts'].append({
                    "id": out_name,
                    "name": "repaired.png",
                    "media_type": "image/png",
                    "size": os.path.getsize(out_path),
                    "previewable": True
                })
        except Exception as e:
            res['status'] = 'failed'
            res['error'] = str(e)
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res


def _inflate(blob: bytes, limit: int = 262144) -> bytes:
    if not blob or len(blob) > limit:
        return b""
    try:
        return zlib.decompressobj().decompress(blob, limit)
    except zlib.error:
        return b""


def iter_png_texts(data: bytes):
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    pos = 8
    produced = 0
    while pos + 12 <= len(data) and produced < 40:
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        if length > 1_000_000 or pos + 12 + length > len(data):
            return
        ctype = data[pos + 4:pos + 8]
        chunk = data[pos + 8:pos + 8 + length]
        if ctype == b"tEXt" and b"\x00" in chunk:
            key, value = chunk.split(b"\x00", 1)
            yield key.decode("latin1", "replace"), value.decode("latin1", "replace")
            produced += 1
        elif ctype == b"zTXt" and b"\x00" in chunk:
            key, rest = chunk.split(b"\x00", 1)
            if rest[:1] == b"\x00":
                raw = _inflate(rest[1:])
                if raw:
                    yield key.decode("latin1", "replace"), raw.decode("latin1", "replace")
                    produced += 1
        elif ctype == b"iTXt" and b"\x00" in chunk:
            key, rest = chunk.split(b"\x00", 1)
            if len(rest) >= 2:
                comp_flag = rest[0]
                comp_method = rest[1]
                _lang, _sep, more = rest[2:].partition(b"\x00")
                _translated, _sep2, text = more.partition(b"\x00")
                if comp_flag == 1:
                    if comp_method != 0:
                        text = b""
                    else:
                        text = _inflate(text)
                if text:
                    yield key.decode("latin1", "replace"), text.decode("utf-8", "replace")
                    produced += 1
        if ctype == b"IEND":
            return
        pos += 12 + length


@register
class PngTextAnalyzer(Analyzer):
    id = "png_text"
    name = "PNG text chunks"
    category = "structure"
    order = 82
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "png" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            with open(input_path, "rb") as handle:
                data = handle.read(8 * 1024 * 1024)
            texts = list(iter_png_texts(data))
            if not texts:
                res["status"] = "no_result"
                res["summary"] = "No PNG text chunks."
            else:
                res["status"] = "success"
                res["summary"] = f"Read {len(texts)} PNG text chunks."
                for key, value in texts:
                    preview = value if len(value) <= 400 else value[:400] + "..."
                    res["findings"].append({
                        "id": f"png-text-{len(res['findings'])}",
                        "kind": "observation",
                        "confidence": "medium",
                        "title": f"PNG text {key or 'chunk'}",
                        "value": preview,
                        "evidence": "tEXt, zTXt, or iTXt",
                        "excerpt": preview if len(preview) <= 160 else preview[:157] + "...",
                    })
                    res["findings"].extend(findings_for_text(value[:100000], f"PNG text {key}"))
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        res["duration_ms"] = int((time.monotonic() - start) * 1000)
        res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
