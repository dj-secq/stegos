import os
import shutil
import struct
import time
import wave
from typing import Dict, Any, List, Optional, Tuple

from PIL import Image, ImageDraw

from .base import Analyzer, register
from ..runner import run_bounded

MAX_SECONDS = 30
WAVE_WIDTH = 960
WAVE_HEIGHT = 240


def _stamp(res: Dict[str, Any], started: float) -> None:
    res["duration_ms"] = int((time.monotonic() - started) * 1000)
    res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _missing_sox(res: Dict[str, Any]) -> bool:
    if shutil.which("sox"):
        return False
    res["status"] = "unavailable"
    res["summary"] = "sox is not installed in this image."
    res["error"] = None
    return True


def _wav_facts(path: str) -> Optional[dict]:
    try:
        with wave.open(path, "rb") as handle:
            rate = handle.getframerate() or 1
            frames = handle.getnframes()
            return {
                "channels": handle.getnchannels(),
                "rate": rate,
                "width": handle.getsampwidth(),
                "frames": frames,
                "seconds": frames / rate,
            }
    except (wave.Error, EOFError, OSError):
        return None


def _soxi_int(path: str, job_dir: str, flag: str) -> Optional[int]:
    if not shutil.which("soxi"):
        return None
    log_path = os.path.join(job_dir, "logs", f"soxi{flag}.txt")
    err_path = os.path.join(job_dir, "logs", f"soxi{flag}_err.txt")
    result = run_bounded(["soxi", flag, path], job_dir, log_path, err_path, timeout_secs=15)
    try:
        return int(float(result.stdout_preview.strip()))
    except (TypeError, ValueError):
        return None


def _channel_count(path: str, job_dir: str) -> int:
    facts = _wav_facts(path)
    if facts:
        return max(1, int(facts["channels"]))
    counted = _soxi_int(path, job_dir, "-c")
    return counted if counted and counted > 0 else 1


def _sample_rate(path: str, job_dir: str) -> Optional[int]:
    facts = _wav_facts(path)
    if facts:
        return int(facts["rate"])
    return _soxi_int(path, job_dir, "-r")


def _duration_seconds(path: str, job_dir: str) -> Optional[float]:
    facts = _wav_facts(path)
    if facts:
        return float(facts["seconds"])
    if not shutil.which("soxi"):
        return None
    log_path = os.path.join(job_dir, "logs", "soxi-d.txt")
    err_path = os.path.join(job_dir, "logs", "soxi-d_err.txt")
    result = run_bounded(["soxi", "-D", path], job_dir, log_path, err_path, timeout_secs=15)
    try:
        return float(result.stdout_preview.strip())
    except (TypeError, ValueError):
        return None


def _ensure_wav(path: str, job_dir: str) -> Tuple[Optional[str], bool, Optional[str]]:
    """Return a WAV path, whether it was trimmed to 30 seconds, and an error."""
    facts = _wav_facts(path)
    if facts:
        return path, facts["seconds"] > MAX_SECONDS, None
    if not shutil.which("sox"):
        return None, False, "sox is not installed in this image."
    out_path = os.path.join(job_dir, "logs", "waveform-src.wav")
    log_path = os.path.join(job_dir, "logs", "waveform-src.txt")
    err_path = os.path.join(job_dir, "logs", "waveform-src_err.txt")
    result = run_bounded(
        ["sox", path, out_path, "trim", "0", str(MAX_SECONDS)],
        job_dir,
        log_path,
        err_path,
        timeout_secs=60,
    )
    if result.exit_code != 0 or not os.path.isfile(out_path):
        return None, False, result.error or "sox could not read this audio."
    original = _duration_seconds(path, job_dir)
    trimmed = original is None or original > MAX_SECONDS
    return out_path, trimmed, None


def _mono_samples(path: str, max_frames: int) -> Optional[Tuple[List[int], dict, bool]]:
    facts = _wav_facts(path)
    if not facts or facts["width"] not in (1, 2) or facts["frames"] <= 0:
        return None
    limit = min(facts["frames"], max_frames)
    with wave.open(path, "rb") as handle:
        raw = handle.readframes(limit)
    channels = facts["channels"]
    if facts["width"] == 1:
        values = [byte - 128 for byte in raw]
    else:
        count = len(raw) // 2
        values = list(struct.unpack("<" + "h" * count, raw[: count * 2]))
    if channels > 1:
        mixed = []
        for index in range(0, len(values) - channels + 1, channels):
            window = values[index : index + channels]
            mixed.append(sum(window) // channels)
        values = mixed
    return values, facts, limit < facts["frames"]


def _draw_waveform(samples: List[int], out_path: str) -> None:
    image = Image.new("RGB", (WAVE_WIDTH, WAVE_HEIGHT), (20, 18, 16))
    draw = ImageDraw.Draw(image)
    mid = WAVE_HEIGHT // 2
    draw.line((0, mid, WAVE_WIDTH - 1, mid), fill=(74, 67, 58))
    if samples:
        step = max(1, len(samples) // WAVE_WIDTH)
        peak = 1
        for index in range(0, len(samples), step):
            peak = max(peak, abs(samples[index]))
        for x in range(WAVE_WIDTH):
            chunk = samples[x * step : (x + 1) * step]
            if not chunk:
                break
            low = min(chunk) / peak
            high = max(chunk) / peak
            y0 = int(mid - high * (mid - 8))
            y1 = int(mid - low * (mid - 8))
            draw.line((x, y0, x, y1), fill=(196, 132, 74))
    image.save(out_path, "PNG")


def _artifact(path: str, artifact_id: str, name: str) -> dict:
    return {
        "id": artifact_id,
        "name": name,
        "media_type": "image/png",
        "size": os.path.getsize(path),
        "previewable": True,
    }


@register
class SpectrogramAnalyzer(Analyzer):
    id = "spectrogram"
    name = "Spectrogram"
    category = "visual"
    order = 130
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "audio"

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        if _missing_sox(res):
            _stamp(res, start)
            return res
        try:
            total = _channel_count(input_path, job_dir)
            draw_count = min(2, total)
            rate = _sample_rate(input_path, job_dir)
            duration = _duration_seconds(input_path, job_dir)
            truncated = duration is not None and duration > MAX_SECONDS
            drawn = 0
            for channel in range(1, draw_count + 1):
                out_name = "spectrogram.png" if draw_count == 1 else f"spectrogram_{channel}.png"
                out_path = os.path.join(job_dir, "artifacts", out_name)
                log_path = os.path.join(job_dir, "logs", f"{self.id}_{channel}.txt")
                err_path = os.path.join(job_dir, "logs", f"{self.id}_{channel}_err.txt")
                result = run_bounded(
                    ["sox", input_path, "-n", "trim", "0", str(MAX_SECONDS), "remix", str(channel), "spectrogram", "-o", out_path],
                    job_dir,
                    log_path,
                    err_path,
                    timeout_secs=60,
                )
                if result.exit_code == 0 and os.path.isfile(out_path):
                    label = "Spectrogram" if draw_count == 1 else f"Channel {channel} spectrogram"
                    res["artifacts"].append(_artifact(out_path, out_name, label))
                    drawn += 1
                elif not res["error"]:
                    res["error"] = result.error or f"Exit code {result.exit_code}"
            if drawn:
                res["status"] = "success"
                res["error"] = None
                noun = "spectrogram" if drawn == 1 else "spectrograms"
                bits = [f"Drew {drawn} {noun}"]
                if rate:
                    bits.append(f"{rate} Hz")
                bits.append(f"{total} channel" if total == 1 else f"{total} channels")
                if total > 2:
                    bits.append("channels after the second were skipped")
                if truncated:
                    bits.append("pictures stop at 30 seconds")
                res["summary"] = ". ".join(bits) + "."
            else:
                res["status"] = "failed"
                res["summary"] = "sox could not draw a spectrogram."
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        _stamp(res, start)
        return res


@register
class WaveformAnalyzer(Analyzer):
    id = "waveform"
    name = "Waveform"
    category = "visual"
    order = 131
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return file_kind == "audio"

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            wav_path, trimmed, error = _ensure_wav(input_path, job_dir)
            if not wav_path:
                if error and "not installed" in error:
                    res["status"] = "unavailable"
                    res["error"] = None
                else:
                    res["status"] = "failed"
                    res["error"] = error
                res["summary"] = error or "No waveform."
                _stamp(res, start)
                return res
            facts = _wav_facts(wav_path)
            if not facts or facts["frames"] <= 0:
                res["status"] = "no_result"
                res["summary"] = "No audio samples."
                _stamp(res, start)
                return res
            if facts["width"] not in (1, 2):
                res["status"] = "no_result"
                res["summary"] = f"Waveform skipped for {facts['width'] * 8}-bit samples."
                _stamp(res, start)
                return res
            max_frames = max(1, int(facts["rate"]) * MAX_SECONDS)
            loaded = _mono_samples(wav_path, max_frames)
            if not loaded:
                res["status"] = "no_result"
                res["summary"] = "No audio samples."
                _stamp(res, start)
                return res
            samples, used, cut = loaded
            out_name = "waveform.png"
            out_path = os.path.join(job_dir, "artifacts", out_name)
            _draw_waveform(samples, out_path)
            res["artifacts"].append(_artifact(out_path, out_name, "Waveform"))
            res["status"] = "success"
            channel_count = used["channels"]
            bits = [
                f"{used['rate']} Hz",
                "1 channel" if channel_count == 1 else f"{channel_count} channels, mixed",
            ]
            if trimmed or cut:
                bits.append("picture stops at 30 seconds")
            res["summary"] = "Waveform. " + ". ".join(bits) + "."
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
            res["summary"] = "Waveform failed."
        _stamp(res, start)
        return res
