"""Flag leads. Each service keeps a copy so its container can import it locally."""

import base64
import contextvars
import os
import re
import uuid

MAX_TEXT = 1_000_000
MAX_HITS = 20
COLLECT_CAP = 200
KNOWN = ("flag", "ctf", "htb", "picoctf", "thm", "h4g")

_HEX_CONTIG = re.compile(r"(?i)(?:0x)?[0-9a-f]{16,400}")
_HEX_SPACED = re.compile(r"(?i)(?:0x)?[0-9a-f]{2}(?:[ \t\r\n]+[0-9a-f]{2}){7,200}")
_HEX_COLON = re.compile(r"(?i)[0-9a-f]{2}(?::[0-9a-f]{2}){7,200}")
_B64_CONTIG = re.compile(r"[A-Za-z0-9+/]{8,400}={0,2}")
_B64_SPACED = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}(?:[ \t\r\n]+[A-Za-z0-9+/]{4,}={0,2})+")
_B32 = re.compile(r"[A-Za-z2-7]{8,400}={0,6}")
_PERCENT = re.compile(r"%([0-9a-fA-F]{2})")
_ENTITY = re.compile(r"&#(x[0-9a-fA-F]{1,6}|\d{1,7});", re.I)


def _pattern(prefix: str) -> re.Pattern[str]:
    names = list(KNOWN)
    extra = str(prefix or "")
    if re.fullmatch(r"[A-Za-z0-9_]{1,24}", extra) and extra.lower() not in names:
        names.append(extra)
    body = "|".join(re.escape(name) for name in names)
    return re.compile(rf"(?i)((?:{body})\{{[ -~]{{1,200}}?\}})")


def _needle(prefix: str) -> str:
    extra = str(prefix or "")
    if re.fullmatch(r"[A-Za-z0-9_]{1,24}", extra):
        return extra.lower() + "{"
    return ""


def _prefer(hits: list[dict[str, str]], prefix: str) -> list[dict[str, str]]:
    needle = _needle(prefix)
    if not needle:
        return hits
    return sorted(hits, key=lambda hit: 0 if hit["value"].lower().startswith(needle) else 1)


def _printable(data: bytes) -> bool:
    return bool(data) and all(32 <= byte <= 126 for byte in data)


def _decode_hex(token: str) -> str | None:
    cleaned = re.sub(r"[\s:]+", "", token)
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) < 16 or len(cleaned) > 400 or len(cleaned) % 2 or re.search(r"[^A-Fa-f0-9]", cleaned):
        return None
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError:
        return None
    if not _printable(raw):
        return None
    return raw.decode("ascii")


def _decode_base64(token: str) -> str | None:
    cleaned = re.sub(r"\s+", "", token)
    if len(cleaned) < 8 or len(cleaned) > 400 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cleaned):
        return None
    pad = (-len(cleaned)) % 4
    try:
        raw = base64.b64decode(cleaned + ("=" * pad), validate=False)
    except Exception:
        return None
    if not _printable(raw):
        return None
    return raw.decode("ascii")


def _decode_base32(token: str) -> str | None:
    cleaned = re.sub(r"\s+", "", token).upper()
    if len(cleaned) < 8 or len(cleaned) > 400 or not re.fullmatch(r"[A-Z2-7]+={0,6}", cleaned):
        return None
    pad = (-len(cleaned)) % 8
    try:
        raw = base64.b32decode(cleaned + ("=" * pad), casefold=True)
    except Exception:
        return None
    if not _printable(raw):
        return None
    return raw.decode("ascii")


def _percent_decode(text: str) -> str | None:
    if "%" not in text:
        return None
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        code = int(match.group(1), 16)
        if 32 <= code <= 126:
            changed = True
            return chr(code)
        return match.group(0)

    decoded = _PERCENT.sub(repl, text)
    if not changed:
        return None
    return decoded


def _entity_decode(text: str) -> str | None:
    if "&#" not in text:
        return None
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        raw = match.group(1)
        code = int(raw[1:], 16) if raw[0] in "xX" else int(raw)
        if 32 <= code <= 126:
            changed = True
            return chr(code)
        return match.group(0)

    decoded = _ENTITY.sub(repl, text)
    if not changed:
        return None
    return decoded


def _is_sep(char: str) -> bool:
    return char in " \t\r\n."


def _layers():
    return (
        (_HEX_CONTIG, _decode_hex, "hex"),
        (_HEX_SPACED, _decode_hex, "hex"),
        (_HEX_COLON, _decode_hex, "hex"),
        (_B64_CONTIG, _decode_base64, "base64"),
        (_B64_SPACED, _decode_base64, "base64"),
        (_B32, _decode_base32, "base32"),
    )


def search(text: str, prefix: str = "") -> list[dict[str, str]]:
    source = str(text or "")[:MAX_TEXT]
    intact = _pattern(prefix)
    hits: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(value: str, detail: str) -> None:
        key = value.lower()
        if key in seen or len(hits) >= COLLECT_CAP:
            return
        seen.add(key)
        hits.append({"value": value, "detail": detail})

    def add_intact(blob: str, detail: str) -> None:
        for match in intact.finditer(blob):
            add(match.group(1), detail)
            if len(hits) >= COLLECT_CAP:
                return

    add_intact(source, "intact")

    length = len(source)
    index = 0
    while index < length and len(hits) < COLLECT_CAP:
        if _is_sep(source[index]):
            index += 1
            continue
        look = index + 1
        while look < length and _is_sep(source[look]):
            look += 1
        if look == index + 1 or look >= length or ord(source[look]) < 32 or ord(source[look]) > 126:
            index += 1
            continue
        collapsed = []
        cursor = index
        span = 0
        while cursor < length and span < 2400 and len(collapsed) < 280:
            char = source[cursor]
            if _is_sep(char):
                cursor += 1
                span += 1
                continue
            if ord(char) < 32 or ord(char) > 126:
                break
            nxt = cursor + 1
            if nxt < length and not _is_sep(source[nxt]) and 32 <= ord(source[nxt]) <= 126:
                break
            collapsed.append(char)
            cursor += 1
            span += 1
        found = intact.search("".join(collapsed))
        if found:
            add(found.group(1), "split")
        index = max(index + 1, cursor)

    def second_layer(decoded: str) -> None:
        for pattern, decode, detail in _layers():
            for match in pattern.finditer(decoded):
                if len(hits) >= COLLECT_CAP:
                    return
                inner = decode(match.group(0))
                if inner and intact.search(inner):
                    add_intact(inner, detail)
        percent = _percent_decode(decoded)
        if percent and intact.search(percent):
            add_intact(percent, "url")
        entity = _entity_decode(decoded)
        if entity and intact.search(entity):
            add_intact(entity, "entity")

    for pattern, decode, detail in _layers():
        for match in pattern.finditer(source):
            if len(hits) >= COLLECT_CAP:
                break
            decoded = decode(match.group(0))
            if not decoded:
                continue
            if intact.search(decoded):
                add_intact(decoded, detail)
                continue
            second_layer(decoded)

    percent = _percent_decode(source)
    if percent:
        add_intact(percent, "url")
    entity = _entity_decode(source)
    if entity:
        add_intact(entity, "entity")
    return _prefer(hits, prefix)[:MAX_HITS]


def search_bytes(data: bytes, prefix: str = "") -> list[dict[str, str]]:
    if not data:
        return []
    sample = data[:MAX_TEXT]
    texts = [sample.decode("utf-8", "replace")]
    if b"\x00" in sample[:4096]:
        texts.append(sample.decode("utf-16le", "replace"))
        texts.append(sample.decode("utf-16be", "replace"))
    hits: list[dict[str, str]] = []
    seen: set[str] = set()
    for text in texts:
        for hit in search(text, prefix):
            key = hit["value"].lower()
            if key in seen:
                continue
            seen.add(key)
            hits.append(hit)
    return _prefer(hits, prefix)[:MAX_HITS]


_FLAG_PREFIX = contextvars.ContextVar("stego_flag_prefix", default="")
_TITLES = {
    "intact": "Candidate CTF flag",
    "split": "Candidate flag, characters were split",
    "hex": "Candidate flag inside hex",
    "base64": "Candidate flag inside base64",
    "base32": "Candidate flag inside base32",
    "url": "Candidate flag inside url encoding",
    "entity": "Candidate flag inside html entity",
}


def set_flag_prefix(value: str) -> None:
    _FLAG_PREFIX.set(str(value or ""))


def _to_findings(hits, evidence):
    return [
        {
            "id": f"flag-{uuid.uuid4().hex[:8]}",
            "kind": "candidate_flag",
            "confidence": "high",
            "title": _TITLES.get(hit["detail"], "Candidate CTF flag"),
            "value": hit["value"],
            "evidence": evidence,
        }
        for hit in hits
    ]


def findings_for_text(text, evidence=""):
    return _to_findings(search(text, _FLAG_PREFIX.get()), evidence)


def findings_for_bytes(data, evidence=""):
    if not data:
        return []
    return _to_findings(search_bytes(data, _FLAG_PREFIX.get()), evidence)


def findings_for_artifacts(job_dir, artifacts, evidence, limit=262144):
    found = []
    root = os.path.join(job_dir, "artifacts")
    for artifact in artifacts or []:
        art_id = artifact.get("id") or ""
        if not isinstance(art_id, str) or os.path.basename(art_id) != art_id or art_id.startswith("."):
            continue
        path = os.path.join(root, art_id)
        size = artifact.get("size") or 0
        if os.path.isfile(path) and 0 < size <= limit:
            with open(path, "rb") as handle:
                found.extend(findings_for_bytes(handle.read(limit), evidence))
    return found


def findings_for_log(log_path, evidence):
    if not log_path or not os.path.exists(log_path):
        return []
    with open(log_path, "r", errors="replace") as handle:
        return findings_for_text(handle.read(MAX_TEXT), evidence)


def attach_flags(result, job_dir, evidence, artifacts=None, log_path=None):
    result["findings"].extend(findings_for_artifacts(job_dir, artifacts, evidence))
    result["findings"].extend(findings_for_log(log_path, evidence))
