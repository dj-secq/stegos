"""Passphrase and hash labels already written on a carrier. Display only."""

import os
import re

_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
_PRINTABLE = re.compile(r"^[\x20-\x7e]+$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+=-]{3,31}$")
_CAMERA = re.compile(r"(?i)^(?:img|dsc|pxl|screenshot)[-_]?\d+$")
_OFFSET = re.compile(r"^[0-9a-fA-F]+$")

_GENERIC = {
    "image", "img", "photo", "picture", "file", "upload", "test", "sample",
    "document", "scan", "screenshot", "download", "untitled", "new", "copy",
    "output", "input", "challenge",
}
_NOISE = _GENERIC | {
    "jfif", "exif", "photoshop", "adobe", "ihdr", "idat", "iend", "plte",
    "png", "gif87a", "gif89a", "8bim", "xmp", "xml", "http", "https",
    "jpeg", "jpg", "tiff", "gimp", "paint", "canva", "icc", "profile",
    "rgb", "truecolor", "data", "comment", "created", "datetime", "software",
}
_TAG_NAMES = {"passphrase", "password", "passwd", "passphrase", "pass", "secret", "pwd"}


def _item(kind, title, value, evidence, item_id, line=None, offset=None, excerpt=None):
    item = {
        "id": item_id,
        "kind": kind,
        "confidence": "low",
        "title": title,
        "value": value,
        "evidence": evidence,
    }
    if line:
        item["line"] = line
    if offset:
        item["offset"] = offset
    if excerpt:
        item["excerpt"] = excerpt
    return item


def classify(value):
    text = str(value or "").strip()
    if _HEX32.fullmatch(text):
        return "hash"
    if not _TOKEN.fullmatch(text):
        return None
    lowered = text.lower()
    if lowered in _NOISE or text.isdigit() or _CAMERA.fullmatch(text):
        return None
    if "{" in text or "}" in text:
        return None
    return "passphrase"


def filename_candidate(filename):
    base = os.path.basename(str(filename or "").replace("\\", "/"))
    stem, _ext = os.path.splitext(base)
    kind = classify(stem)
    if kind == "hash":
        return _item(
            "hash_candidate",
            "Hash for Identify Hash Type from the filename",
            stem,
            "filename",
            "hash-filename",
        )
    if kind == "passphrase":
        return _item(
            "passphrase_candidate",
            "Passphrase candidate from the filename",
            stem,
            "filename",
            "passphrase-filename",
        )
    return None


def _tag_key(name):
    return str(name or "").split(":")[-1].strip().lower()


def tag_candidate(name, value):
    key = _tag_key(name)
    if key not in _TAG_NAMES and "passphrase" not in key:
        return None
    text = str(value or "").strip()
    if not text or len(text) > 64 or not _PRINTABLE.fullmatch(text):
        return None
    excerpt = f"{key}: {text}"
    if len(excerpt) > 160:
        excerpt = excerpt[:157] + "..."
    if _HEX32.fullmatch(text):
        return _item(
            "hash_candidate",
            "Hash for Identify Hash Type from a metadata tag",
            text,
            f"metadata tag {key}",
            "hash-tag",
            excerpt=excerpt,
        )
    return _item(
        "passphrase_candidate",
        "Passphrase candidate from a metadata tag",
        text,
        f"metadata tag {key}",
        "passphrase-tag",
        excerpt=excerpt,
    )


def metadata_candidates(metadata):
    passphrase = None
    digest = None
    for key, value in (metadata or {}).items():
        if not isinstance(value, str):
            continue
        item = tag_candidate(key, value)
        if not item:
            continue
        if item["kind"] == "hash_candidate" and digest is None:
            digest = item
        elif item["kind"] == "passphrase_candidate" and passphrase is None:
            passphrase = item
        if passphrase and digest:
            break
    return [item for item in (passphrase, digest) if item]


def _string_body(line):
    parts = line.strip().split(None, 1)
    if len(parts) == 2 and _OFFSET.fullmatch(parts[0]):
        return parts[1].strip()
    return line.strip()


def strings_candidates(text):
    passphrase = None
    digest = None
    for number, raw in enumerate(str(text or "").splitlines(), 1):
        body = _string_body(raw)
        kind = classify(body)
        parts = raw.strip().split(None, 1)
        offset = "0x" + parts[0].lower() if len(parts) == 2 and _OFFSET.fullmatch(parts[0]) else None
        excerpt = raw.strip()
        if len(excerpt) > 160:
            excerpt = excerpt[:157] + "..."
        if kind == "hash" and digest is None:
            digest = _item(
                "hash_candidate",
                "Hash for Identify Hash Type from strings",
                body,
                "strings",
                "hash-strings",
                line=number,
                offset=offset,
                excerpt=excerpt,
            )
        elif kind == "passphrase" and passphrase is None:
            passphrase = _item(
                "passphrase_candidate",
                "Passphrase candidate from strings",
                body,
                "strings",
                "passphrase-strings",
                line=number,
                offset=offset,
                excerpt=excerpt,
            )
        if passphrase and digest:
            break
    return [item for item in (passphrase, digest) if item]
