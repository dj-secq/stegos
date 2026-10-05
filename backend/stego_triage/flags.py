"""Flag leads. Each service keeps a copy so its container can import it locally."""

import base64
import contextvars
import os
import re
import uuid

MAX_TEXT = 1_000_000
MAX_HITS = 20
MAX_DECODE_LEADS = 8
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
_PERCENT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_ENTITY_RUN = re.compile(r"(?:&#(?:x[0-9A-Fa-f]{1,6}|\d{1,7});){4,}", re.I)


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


def _looks_encoded(token: str, detail: str) -> bool:
    if detail == "hex":
        return True
    cleaned = re.sub(r"\s+", "", token)
    if detail == "base64":
        if "=" in cleaned:
            return True
        letters = [char for char in cleaned if char.isalpha()]
        mixed = any(char.isupper() for char in letters) and any(char.islower() for char in letters)
        marked = any(char.isdigit() or char in "+/" for char in cleaned)
        return mixed or marked
    if detail == "base32":
        return "=" in cleaned or any(char.isdigit() for char in cleaned)
    return True


def _worth_text(text: str) -> bool:
    if not text or len(text) < 8 or len(text) > 200 or len(set(text)) < 3:
        return False
    useful = sum(char.isalnum() or char in " _{}" for char in text)
    return useful >= len(text) * 0.6


def _locate(text: str, start, end):
    if start is None or not text:
        return None, None
    start = max(0, min(int(start), len(text)))
    end = max(start, min(int(end if end is not None else start), len(text)))
    line = text.count("\n", 0, start) + 1
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start)
    if line_end < 0:
        line_end = len(text)
    raw = text[line_start:line_end].strip("\r")
    if len(raw) > 160:
        local = max(0, start - line_start)
        begin = max(0, local - 70)
        snippet = raw[begin:begin + 157].strip()
        if begin:
            snippet = "..." + snippet
        if begin + 157 < len(raw):
            snippet += "..."
        raw = snippet
    excerpt = raw.strip()
    return line, excerpt or None


def search(text: str, prefix: str = "") -> list[dict[str, str]]:
    source = str(text or "")[:MAX_TEXT]
    intact = _pattern(prefix)
    flags: list[dict[str, str]] = []
    decodes: list[dict[str, str]] = []
    seen_flags: set[str] = set()
    seen_decodes: set[str] = set()

    def add_flag(value: str, detail: str, start: int, end: int) -> None:
        key = value.lower()
        if key in seen_flags or len(flags) >= COLLECT_CAP:
            return
        seen_flags.add(key)
        flags.append({
            "value": value,
            "detail": detail,
            "kind": "candidate_flag",
            "start": start,
            "end": end,
        })

    def add_decode(value: str, detail: str, start: int, end: int) -> None:
        key = value.lower()
        if key in seen_decodes or key in seen_flags or len(decodes) >= MAX_DECODE_LEADS:
            return
        if not _worth_text(value):
            return
        seen_decodes.add(key)
        decodes.append({
            "value": value,
            "detail": detail,
            "kind": "encoding",
            "start": start,
            "end": end,
        })

    def add_intact(blob: str, detail: str, start: int, end: int) -> None:
        for match in intact.finditer(blob):
            add_flag(match.group(1), detail, start, end)
            if len(flags) >= COLLECT_CAP:
                return

    for match in intact.finditer(source):
        add_flag(match.group(1), "intact", match.start(1), match.end(1))

    length = len(source)
    index = 0
    while index < length and len(flags) < COLLECT_CAP:
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
            add_flag(found.group(1), "split", index, cursor)
        index = max(index + 1, cursor)

    def consider(decoded: str, detail: str, start: int, end: int, token: str) -> None:
        if intact.search(decoded):
            add_intact(decoded, detail, start, end)
            return
        promoted = False
        best_value = None
        best_detail = None

        def remember(inner: str, inner_detail: str) -> None:
            nonlocal promoted, best_value, best_detail
            if not inner:
                return
            if intact.search(inner):
                add_intact(inner, inner_detail, start, end)
                promoted = True
                return
            if _worth_text(inner) and (best_value is None or len(inner) > len(best_value)):
                best_value = inner
                best_detail = inner_detail

        for pattern, decode, inner_detail in _layers():
            for match in pattern.finditer(decoded):
                inner = decode(match.group(0))
                if inner and _looks_encoded(match.group(0), inner_detail):
                    remember(inner, inner_detail)
                elif inner and intact.search(inner):
                    remember(inner, inner_detail)
        percent = _percent_decode(decoded)
        if percent and percent != decoded:
            remember(percent, "url")
        entity = _entity_decode(decoded)
        if entity and entity != decoded:
            remember(entity, "entity")
        if promoted:
            return
        if best_value:
            add_decode(best_value, best_detail or detail, start, end)
            return
        if _looks_encoded(token, detail):
            add_decode(decoded, detail, start, end)

    for pattern, decode, detail in _layers():
        for match in pattern.finditer(source):
            if len(flags) >= COLLECT_CAP and len(decodes) >= MAX_DECODE_LEADS:
                break
            token = match.group(0)
            decoded = decode(token)
            if not decoded:
                continue
            consider(decoded, detail, match.start(), match.end(), token)

    percent = _percent_decode(source)
    if percent:
        start, end = (0, 0)
        located = _PERCENT.search(source)
        if located:
            start, end = located.start(), located.end()
        add_intact(percent, "url", start, end)
    entity = _entity_decode(source)
    if entity:
        start, end = (0, 0)
        located = _ENTITY.search(source)
        if located:
            start, end = located.start(), located.end()
        add_intact(entity, "entity", start, end)

    for pattern, decode, detail in ((_PERCENT_RUN, _percent_decode, "url"), (_ENTITY_RUN, _entity_decode, "entity")):
        for match in pattern.finditer(source):
            if len(decodes) >= MAX_DECODE_LEADS:
                break
            decoded = decode(match.group(0))
            if decoded and not intact.search(decoded):
                add_decode(decoded, detail, match.start(), match.end())

    ordered = _prefer(flags, prefix)[:MAX_HITS]
    ordered.extend(decodes[:MAX_DECODE_LEADS])
    return ordered


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
_ENCODE_TITLES = {
    "hex": "Hex decoded to text",
    "base64": "Base64 decoded to text",
    "base32": "Base32 decoded to text",
    "url": "URL encoding decoded to text",
    "entity": "HTML entity decoded to text",
}


def set_flag_prefix(value: str) -> None:
    _FLAG_PREFIX.set(str(value or ""))


def _to_findings(hits, evidence, text=""):
    findings = []
    for hit in hits:
        kind = hit.get("kind") or "candidate_flag"
        if kind == "encoding":
            title = _ENCODE_TITLES.get(hit.get("detail"), "Decoded text")
            confidence = "low"
        else:
            title = _TITLES.get(hit.get("detail"), "Candidate CTF flag")
            confidence = "high"
        item = {
            "id": f"flag-{uuid.uuid4().hex[:8]}",
            "kind": kind,
            "confidence": confidence,
            "title": title,
            "value": hit["value"],
            "evidence": evidence,
        }
        if text and hit.get("start") is not None:
            line, excerpt = _locate(text, hit.get("start"), hit.get("end"))
            if line:
                item["line"] = line
            if excerpt:
                item["excerpt"] = excerpt
        findings.append(item)
    return findings


def findings_for_text(text, evidence=""):
    source = str(text or "")[:MAX_TEXT]
    return _to_findings(search(source, _FLAG_PREFIX.get()), evidence, source)


def findings_for_bytes(data, evidence=""):
    if not data:
        return []
    sample = data[:MAX_TEXT]
    texts = [sample.decode("utf-8", "replace")]
    if b"\x00" in sample[:4096]:
        texts.append(sample.decode("utf-16le", "replace"))
        texts.append(sample.decode("utf-16be", "replace"))
    found = []
    seen = set()
    for text in texts:
        for item in findings_for_text(text, evidence):
            key = (item.get("kind"), str(item.get("value", "")).lower())
            if key in seen:
                continue
            seen.add(key)
            found.append(item)
    flags = [item for item in found if item.get("kind") == "candidate_flag"]
    decodes = [item for item in found if item.get("kind") == "encoding"]
    return flags[:MAX_HITS] + decodes[:MAX_DECODE_LEADS]


def _mostly_printable(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(32 <= byte <= 126 for byte in data)
    return printable >= len(data) * 0.8


def _utf16_label(sample: bytes):
    if len(sample) < 32:
        return None
    pairs = len(sample) // 2
    even_nul = sum(1 for index in range(0, pairs * 2, 2) if sample[index] == 0)
    odd_nul = sum(1 for index in range(1, pairs * 2, 2) if sample[index] == 0)
    if odd_nul > pairs * 0.6 and even_nul < pairs * 0.2:
        other = bytes(sample[index] for index in range(0, pairs * 2, 2))
        if _mostly_printable(other):
            return "UTF-16 LE"
    if even_nul > pairs * 0.6 and odd_nul < pairs * 0.2:
        other = bytes(sample[index] for index in range(1, pairs * 2, 2))
        if _mostly_printable(other):
            return "UTF-16 BE"
    return None


def charset_label(data: bytes) -> str:
    sample = data[:65536]
    if sample.startswith(b"\xff\xfe\x00\x00"):
        return "UTF-32 LE"
    if sample.startswith(b"\x00\x00\xfe\xff"):
        return "UTF-32 BE"
    if sample.startswith(b"\xff\xfe"):
        return "UTF-16 LE"
    if sample.startswith(b"\xfe\xff"):
        return "UTF-16 BE"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "UTF-8"
    wide = _utf16_label(sample)
    if wide:
        return wide
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    return "UTF-8"


def charset_finding(data: bytes) -> dict:
    return {
        "id": "charset",
        "kind": "encoding",
        "confidence": "medium",
        "title": "Character encoding",
        "value": charset_label(data),
        "evidence": "byte order mark, UTF-16 layout, or a UTF-8 decode of the start of the file",
    }


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
