import os
import time
from typing import Any, Dict, List

from PIL import Image

from .base import Analyzer, register
from .visual import enforce_pixel_limit, save_clean_png

FRAME_CAP = 32


@register
class GifFrameAnalyzer(Analyzer):
    id = "gif_frames"
    name = "GIF frames"
    category = "visual"
    order = 62
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return "gif" in format_tags

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            image = Image.open(input_path)
            if (image.format or "").upper() != "GIF":
                res["status"] = "no_result"
                res["summary"] = "Not a GIF."
            else:
                count = int(getattr(image, "n_frames", 1) or 1)
                written = min(count, FRAME_CAP)
                for index in range(written):
                    image.seek(index)
                    delay = int(image.info.get("duration") or 0)
                    frame = image.convert("RGBA")
                    enforce_pixel_limit(frame)
                    out_name = f"gif_frame_{index:02d}.png"
                    out_path = os.path.join(job_dir, "artifacts", out_name)
                    save_clean_png(frame, out_path)
                    res["artifacts"].append({
                        "id": out_name,
                        "name": f"Frame {index}",
                        "media_type": "image/png",
                        "size": os.path.getsize(out_path),
                        "previewable": True,
                        "frame": index,
                        "delay_ms": delay,
                    })
                res["status"] = "success"
                noun = "frame" if written == 1 else "frames"
                res["summary"] = f"{written} {noun}."
                if count > written:
                    skipped = count - written
                    res["summary"] += f" {skipped} later frames were skipped."
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
            res["summary"] = "GIF frames failed."
        res["duration_ms"] = int((time.monotonic() - start) * 1000)
        res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res
