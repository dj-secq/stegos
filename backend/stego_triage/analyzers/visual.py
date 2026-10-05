import glob
import os
import shutil
import time
import hashlib
import numpy as np
from PIL import Image, ImageOps
from typing import Dict, Any, List
from .base import Analyzer, register
from .. import config
from ..flags import findings_for_bytes, findings_for_text
from ..runner import run_bounded

def enforce_pixel_limit(img: Image.Image) -> None:
    if img.width * img.height > config.MAX_PIXELS:
        raise ValueError(f"Image exceeds max pixel limit of {config.MAX_PIXELS} ({img.width}x{img.height})")

def prepare_image(path: str) -> Image.Image:
    img = Image.open(path)
    enforce_pixel_limit(img)
    img = ImageOps.exif_transpose(img)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode else "RGB")
    return img

def save_clean_png(img: Image.Image, path: str):
    img.save(path, "PNG", optimize=False)


def pack_plane(plane: np.ndarray, msb_first: bool) -> bytes:
    """Pack one bit plane, row by row, into bytes.

    msb_first puts the left-most pixel in the high bit. lsb_first puts it in
    the low bit, which is the usual LSB stego order.
    """
    flat = np.ascontiguousarray(plane).reshape(-1)
    flat = flat.astype(np.uint8, copy=False) & np.uint8(1)
    usable = (flat.size // 8) * 8
    if usable < 8:
        return b""
    grouped = flat[:usable].reshape(-1, 8).astype(np.uint16)
    if msb_first:
        weights = np.array([128, 64, 32, 16, 8, 4, 2, 1], dtype=np.uint16)
    else:
        weights = np.array([1, 2, 4, 8, 16, 32, 64, 128], dtype=np.uint16)
    return (grouped * weights).sum(axis=1).astype(np.uint8).tobytes()


def _remember_plane(findings: List[dict], seen: set, plane: np.ndarray, evidence: str) -> None:
    if len(findings) >= 20:
        return
    ones = int(np.count_nonzero(plane))
    if ones == 0 or ones == plane.size:
        return
    for msb_first, label in ((True, "msb first"), (False, "lsb first")):
        blob = pack_plane(plane, msb_first)[:1_000_000]
        for hit in findings_for_bytes(blob, f"{evidence}, {label}"):
            key = str(hit.get("value", "")).lower()
            if not key or key in seen:
                continue
            seen.add(key)
            findings.append(hit)
            if len(findings) >= 20:
                return


def zbar_payloads(text: str) -> List[str]:
    payloads = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" in line:
            line = line.split(":", 1)[1].strip()
        if line:
            payloads.append(line)
    return payloads


def _looks_like_pdf(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(5) == b"%PDF-"
    except OSError:
        return False

@register
class PreviewAnalyzer(Analyzer):
    id = "preview"
    name = "Safe Preview"
    category = "visual"
    order = 15
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "image"
        
    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            img = prepare_image(input_path)
            # Create a thumbnail
            img.thumbnail((800, 800))
            out_path = os.path.join(job_dir, "artifacts", "preview.png")
            save_clean_png(img, out_path)
            
            # The preview is just an artifact, but we might also expose it directly
            # via a special manifest property. For now, just add as artifact.
            res['artifacts'].append({
                "id": "preview.png",
                "name": "safe_preview.png",
                "media_type": "image/png",
                "size": os.path.getsize(out_path),
                "previewable": True
            })
            res['status'] = 'success'
            res['summary'] = f"Generated {img.width}x{img.height} safe preview"
        except Exception as e:
            res['status'] = 'failed'
            res['error'] = str(e)
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class BitPlaneAnalyzer(Analyzer):
    id = "bit_planes"
    name = "Bit-plane Decomposer"
    category = "visual"
    order = 60
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "image"

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            img = prepare_image(input_path)
            arr = np.array(img)
            channels = list('RGBA') if img.mode == 'RGBA' else list('RGB')
            
            artifacts = []
            findings = []
            seen = set()
            
            for c_idx, c_name in enumerate(channels):
                c_data = arr[:, :, c_idx]
                for bit in range(8):
                    plane = (c_data >> bit) & 1
                    _remember_plane(findings, seen, plane, f"channel {c_name} bit {bit}")
                    bit_data = plane * 255
                    out_img = Image.fromarray(bit_data.astype('uint8'), 'L')
                    out_name = f"plane_{c_name}_{bit}.png"
                    out_path = os.path.join(job_dir, "artifacts", out_name)
                    save_clean_png(out_img, out_path)
                    
                    artifacts.append({
                        "id": out_name,
                        "name": f"Channel {c_name} Bit {bit}",
                        "media_type": "image/png",
                        "size": os.path.getsize(out_path),
                        "previewable": True,
                        "channel": c_name,
                        "bit": bit,
                    })
            
            # Same bit across R, G, and B, row by row. Column walks stay out of this pass.
            if arr.ndim == 3 and arr.shape[2] >= 3:
                for bit in range(8):
                    stream = ((arr[:, :, :3] >> bit) & 1).reshape(-1)
                    _remember_plane(findings, seen, stream, f"RGB interleaved bit {bit}")

            # Superimposed RGB planes
            for bit in range(8):
                # (R_bit << 7) | (G_bit << 7) | (B_bit << 7) -> actually we map bit to max intensity
                # AperiSolve style superimposed: R=R_bit*255, G=G_bit*255, B=B_bit*255
                rgb_data = np.zeros((img.height, img.width, 3), dtype='uint8')
                for c_idx in range(3):
                    rgb_data[:, :, c_idx] = ((arr[:, :, c_idx] >> bit) & 1) * 255
                
                out_img = Image.fromarray(rgb_data, 'RGB')
                out_name = f"plane_RGB_{bit}.png"
                out_path = os.path.join(job_dir, "artifacts", out_name)
                save_clean_png(out_img, out_path)
                
                artifacts.append({
                    "id": out_name,
                    "name": f"Superimposed RGB Bit {bit}",
                    "media_type": "image/png",
                    "size": os.path.getsize(out_path),
                    "previewable": True,
                    "channel": "RGB",
                    "bit": bit,
                })
                
            res['artifacts'] = artifacts
            res['findings'] = findings
            res['status'] = 'success'
            res['summary'] = f"Generated {len(artifacts)} bit planes."
            if findings:
                noun = "candidate flag" if len(findings) == 1 else "candidate flags"
                res['summary'] += f" Found {len(findings)} {noun}."
        except Exception as e:
            res['status'] = 'failed'
            res['error'] = str(e)
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res

@register
class ColorRemapAnalyzer(Analyzer):
    id = "color_remaps"
    name = "Color Remapping"
    category = "visual"
    order = 70
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "image"

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            img = prepare_image(input_path)
            arr = np.array(img)
            
            # Deterministic seed from file hash
            file_hash = hashlib.sha256()
            with open(input_path, "rb") as f:
                while chunk := f.read(65536):
                    file_hash.update(chunk)
            
            seed = int.from_bytes(file_hash.digest()[:4], "little")
            rng = np.random.default_rng(seed)
            
            artifacts = []
            
            for i in range(8):
                # Generate a random 256x3 palette
                palette = rng.integers(0, 256, (256, 3)).astype('uint8')
                
                # Apply palette to each channel independently or just hash the colors
                # Simple approach: xor the channels and map
                if img.mode == 'RGBA':
                    rgb = arr[:, :, :3]
                    a = arr[:, :, 3:4]
                else:
                    rgb = arr[:, :, :3]
                    
                # A simple remap: take R^G^B as index into palette
                idx = rgb[:, :, 0] ^ rgb[:, :, 1] ^ rgb[:, :, 2]
                idx = (idx + i * 31) % 256 # shift for variety
                
                remapped = palette[idx]
                
                if img.mode == 'RGBA':
                    remapped = np.concatenate([remapped, a], axis=2)
                    out_img = Image.fromarray(remapped, 'RGBA')
                else:
                    out_img = Image.fromarray(remapped, 'RGB')
                    
                out_name = f"remap_{i}.png"
                out_path = os.path.join(job_dir, "artifacts", out_name)
                save_clean_png(out_img, out_path)
                
                artifacts.append({
                    "id": out_name,
                    "name": f"Color Remap {i+1}",
                    "media_type": "image/png",
                    "size": os.path.getsize(out_path),
                    "previewable": True
                })
                
            res['artifacts'] = artifacts
            res['status'] = 'success'
            res['summary'] = f"Generated 8 color remaps."
        except Exception as e:
            res['status'] = 'failed'
            res['error'] = str(e)
            
        res['duration_ms'] = int((time.monotonic() - start) * 1000)
        res['finished_at'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res


@register
class ZbarAnalyzer(Analyzer):
    id = "zbar"
    name = "zbarimg"
    category = "visual"
    order = 58
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "image" or "pdf" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        page_dir = os.path.join(job_dir, "artifacts", "_zbar_pages")
        try:
            if shutil.which("zbarimg") is None:
                res["status"] = "no_result"
                res["summary"] = "zbarimg is not installed."
                return res
            images, prepare_error = self._prepare_images(input_path, job_dir, page_dir)
            if prepare_error:
                res["status"] = prepare_error["status"]
                res["summary"] = prepare_error.get("summary", "")
                res["error"] = prepare_error.get("error")
                return res
            raw_parts = []
            payloads = []
            errors = []
            for image in images:
                log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
                run_res = run_bounded(
                    ["zbarimg", "-q", image],
                    job_dir,
                    log_path,
                    os.path.join(job_dir, "logs", f"{self.id}_err.txt"),
                )
                text = run_res.stdout_preview or ""
                if text:
                    raw_parts.append(text)
                if run_res.exit_code == 0:
                    payloads.extend(zbar_payloads(text))
                elif run_res.exit_code not in (0, 4):
                    errors.append(run_res.error or f"zbarimg exit {run_res.exit_code}")
            joined = "\n".join(payloads)
            if joined:
                res["findings"].extend(findings_for_text(joined[:100000], "zbarimg"))
            raw = "\n".join(raw_parts).strip()
            if raw:
                log_path = os.path.join(job_dir, "logs", f"{self.id}.txt")
                with open(log_path, "w", encoding="utf-8") as handle:
                    handle.write(raw)
                    handle.write("\n")
                res["artifacts"].append({
                    "id": f"{self.id}.txt",
                    "name": "zbar.txt",
                    "media_type": "text/plain",
                    "size": os.path.getsize(log_path),
                    "previewable": True,
                })
                res["log_artifact_id"] = f"{self.id}.txt"
            if payloads:
                res["status"] = "success"
                res["summary"] = f"Decoded {len(payloads)} barcode payload(s)."
            elif errors:
                res["status"] = "failed"
                res["error"] = errors[0]
                res["summary"] = "zbarimg could not read the file."
            else:
                res["status"] = "no_result"
                res["summary"] = "No barcode decoded."
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        finally:
            res["duration_ms"] = int((time.monotonic() - start) * 1000)
            res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            if os.path.isdir(page_dir):
                shutil.rmtree(page_dir, ignore_errors=True)
        return res

    def _prepare_images(self, input_path: str, job_dir: str, page_dir: str):
        if not _looks_like_pdf(input_path):
            return [input_path], None
        if shutil.which("pdftoppm") is None:
            return [], {"status": "no_result", "summary": "pdftoppm is not installed.", "error": None}
        os.makedirs(page_dir, exist_ok=True)
        prefix = os.path.join(page_dir, "page")
        run_res = run_bounded(
            ["pdftoppm", "-png", "-r", "100", "-f", "1", "-l", "8", input_path, prefix],
            job_dir,
            os.path.join(job_dir, "logs", "zbar-pages.txt"),
            os.path.join(job_dir, "logs", "zbar-pages_err.txt"),
        )
        pages = sorted(glob.glob(os.path.join(page_dir, "page*.png")))[:8]
        if run_res.exit_code != 0 or not pages:
            return [], {
                "status": "failed",
                "summary": "Could not render PDF pages for barcode scanning.",
                "error": run_res.error or f"pdftoppm exit {run_res.exit_code}",
            }
        return pages, None
