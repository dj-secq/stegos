import time
from typing import Dict, Any, List, Optional

from .base import Analyzer, register
from ..flags import findings_for_text

ZERO_WIDTH = {
    "\u200b": "U+200B",
    "\u200c": "U+200C",
    "\u200d": "U+200D",
    "\ufeff": "U+FEFF",
}
ZERO_WIDTH_BITS = {"\u200b": "0", "\u200c": "1"}
UNUSUAL_SPACES = {
    "\u00a0": "U+00A0",
    "\u2000": "U+2000",
    "\u2001": "U+2001",
    "\u2002": "U+2002",
    "\u2003": "U+2003",
    "\u2004": "U+2004",
    "\u2005": "U+2005",
    "\u2006": "U+2006",
    "\u2007": "U+2007",
    "\u2008": "U+2008",
    "\u2009": "U+2009",
    "\u200a": "U+200A",
    "\u202f": "U+202F",
    "\u205f": "U+205F",
    "\u3000": "U+3000",
}


def _looks_binary(data: bytes) -> bool:
    return b"\x00" in data[:4096] and len(data) > 4096


def _ascii_from_bits(bits: str) -> Optional[str]:
    usable = len(bits) - (len(bits) % 8)
    if usable < 64:
        return None
    chars = []
    for index in range(0, usable, 8):
        byte = int(bits[index : index + 8], 2)
        if byte < 32 or byte > 126:
            return None
        chars.append(chr(byte))
    if len(chars) < 8:
        return None
    return "".join(chars)


def _preview(text: str) -> str:
    return text if len(text) <= 180 else text[:180] + "..."


def _read_text(input_path: str):
    with open(input_path, "rb") as handle:
        data = handle.read(1_000_000)
    if _looks_binary(data):
        return None
    return data.decode("utf-8", "replace")


def decode_trailing_whitespace(text: str):
    lines = text.splitlines()[:5000]
    bits = []
    counts = []
    for line in lines:
        if not line.endswith((" ", "\t")):
            continue
        trail = line[len(line.rstrip(" \t")):]
        if len(trail) == 1 and trail in (" ", "\t"):
            bits.append("1" if trail == "\t" else "0")
        spaces = len(line) - len(line.rstrip(" "))
        if spaces and line.endswith(" ") and 32 <= spaces <= 126:
            counts.append(spaces)

    found = []
    usable = len(bits) - (len(bits) % 8)
    if usable >= 64:
        chars = []
        valid = True
        for index in range(0, usable, 8):
            byte = int("".join(bits[index:index + 8]), 2)
            if byte < 32 or byte > 126:
                valid = False
                break
            chars.append(chr(byte))
        if valid and len(chars) >= 8:
            found.append("".join(chars))
    if len(counts) >= 8:
        found.append("".join(chr(count) for count in counts))
    unique = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


@register
class WhitespaceAnalyzer(Analyzer):
    id = "whitespace"
    name = "Trailing whitespace"
    category = "stego"
    order = 55
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        start = time.monotonic()
        try:
            with open(input_path, "rb") as handle:
                data = handle.read(1_000_000)
            if b"\x00" in data[:4096] and len(data) > 4096:
                res["status"] = "no_result"
                res["summary"] = "Skipped binary input."
            else:
                decoded = decode_trailing_whitespace(data.decode("latin1", "replace"))
                if not decoded:
                    res["status"] = "no_result"
                    res["summary"] = "No trailing-whitespace message."
                else:
                    res["status"] = "success"
                    res["summary"] = f"Decoded {len(decoded)} trailing-whitespace messages."
                    for item in decoded:
                        preview = item if len(item) <= 180 else item[:180] + "..."
                        res["findings"].append({
                            "id": f"ws-{len(res['findings'])}",
                            "kind": "observation",
                            "confidence": "medium",
                            "title": "Trailing whitespace decoded",
                            "value": preview,
                            "evidence": "spaces and tabs at line ends",
                        })
                        res["findings"].extend(findings_for_text(item, "trailing whitespace"))
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        res["duration_ms"] = int((time.monotonic() - start) * 1000)
        res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return res


def _finish(res: Dict[str, Any], started: float) -> Dict[str, Any]:
    res["duration_ms"] = int((time.monotonic() - started) * 1000)
    res["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return res


def decode_zero_width(text: str):
    counts = {label: 0 for label in ZERO_WIDTH.values()}
    bits = []
    for char in text:
        label = ZERO_WIDTH.get(char)
        if not label:
            continue
        counts[label] += 1
        bit = ZERO_WIDTH_BITS.get(char)
        if bit is not None:
            bits.append(bit)
    present = {label: count for label, count in counts.items() if count}
    primary = "".join(bits)
    swapped = "".join("1" if bit == "0" else "0" for bit in bits)
    decoded = _ascii_from_bits(primary)
    mapping = "U+200B is 0 and U+200C is 1"
    if decoded is None and ("U+200B" in present and "U+200C" in present):
        alternate = _ascii_from_bits(swapped)
        if alternate:
            decoded = alternate
            mapping = "U+200B is 1 and U+200C is 0"
    return present, decoded, mapping


def decode_unusual_spaces(text: str):
    counts = {label: 0 for label in UNUSUAL_SPACES.values()}
    ordinary = 0
    bits = []
    unusual_chars = {char for char in text if char in UNUSUAL_SPACES}
    single = next(iter(unusual_chars)) if len(unusual_chars) == 1 else None
    for char in text:
        if char == " ":
            ordinary += 1
            if single:
                bits.append("0")
        elif char in UNUSUAL_SPACES:
            counts[UNUSUAL_SPACES[char]] += 1
            if single:
                bits.append("1")
    present = {label: count for label, count in counts.items() if count}
    decoded = _ascii_from_bits("".join(bits)) if single and ordinary else None
    label = UNUSUAL_SPACES.get(single, "")
    return present, ordinary, decoded, label


@register
class ZeroWidthAnalyzer(Analyzer):
    id = "zero_width"
    name = "Zero-width"
    category = "stego"
    order = 56
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        started = time.monotonic()
        try:
            text = _read_text(input_path)
            if text is None:
                res["status"] = "no_result"
                res["summary"] = "Skipped binary input."
                return _finish(res, started)
            present, decoded, mapping = decode_zero_width(text)
            if not present:
                res["status"] = "no_result"
                res["summary"] = "No zero-width characters."
                return _finish(res, started)
            listed = ", ".join(f"{label} × {count}" for label, count in present.items())
            res["findings"].append({
                "id": "zw-count",
                "kind": "observation",
                "confidence": "medium",
                "title": "Zero-width characters",
                "value": listed,
                "evidence": "U+200B, U+200C, U+200D, and U+FEFF in file order",
            })
            if decoded:
                res["findings"].append({
                    "id": "zw-text",
                    "kind": "observation",
                    "confidence": "medium",
                    "title": "Zero-width decoded",
                    "value": _preview(decoded),
                    "evidence": mapping + ". U+200D and U+FEFF are separators",
                })
                res["findings"].extend(findings_for_text(decoded, "zero-width"))
                res["summary"] = f"Decoded a zero-width message. {listed}."
            else:
                res["summary"] = f"Counted zero-width characters. {listed}."
            res["status"] = "success"
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        return _finish(res, started)


@register
class UnusualSpaceAnalyzer(Analyzer):
    id = "unusual_spaces"
    name = "Unusual spaces"
    category = "stego"
    order = 57
    quick = True
    deep = True

    def can_run(self, file_kind: str, format_tags: List[str]) -> bool:
        return True

    def run(self, input_path: str, job_dir: str, context: Dict[str, Any]) -> Dict[str, Any]:
        res = self._create_result()
        started = time.monotonic()
        try:
            text = _read_text(input_path)
            if text is None:
                res["status"] = "no_result"
                res["summary"] = "Skipped binary input."
                return _finish(res, started)
            present, ordinary, decoded, label = decode_unusual_spaces(text)
            if not present:
                res["status"] = "no_result"
                res["summary"] = "No unusual spaces."
                return _finish(res, started)
            listed = ", ".join(f"{name} × {count}" for name, count in present.items())
            value = listed
            if ordinary:
                value += f", ordinary spaces × {ordinary}"
            res["findings"].append({
                "id": "sp-count",
                "kind": "observation",
                "confidence": "medium",
                "title": "Unusual spaces",
                "value": value,
                "evidence": "space separators mixed with U+0020",
            })
            if decoded:
                res["findings"].append({
                    "id": "sp-text",
                    "kind": "observation",
                    "confidence": "medium",
                    "title": "Unusual spaces decoded",
                    "value": _preview(decoded),
                    "evidence": f"U+0020 is 0 and {label} is 1, in file order",
                })
                res["findings"].extend(findings_for_text(decoded, "unusual spaces"))
                res["summary"] = "Decoded a space pattern. " + listed + "."
            else:
                res["summary"] = "Counted unusual spaces. " + listed + "."
            res["status"] = "success"
        except Exception as exc:
            res["status"] = "failed"
            res["error"] = str(exc)
        return _finish(res, started)
