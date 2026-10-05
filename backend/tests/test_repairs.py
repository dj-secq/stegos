import io
import os
import struct
import tempfile
import zipfile
import zlib

import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.magic import (
    MagicRepairAnalyzer,
    structural_repair,
    trailing_bytes,
)
from stego_triage.analyzers.structure import PngTextAnalyzer
from stego_triage.analyzers.text import WhitespaceAnalyzer, decode_trailing_whitespace
from stego_triage.flags import attach_flags, findings_for_text

TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082"
)


def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name


def teardown_module(module):
    module.temp_dir.cleanup()


def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0


def _job_file(name, blob):
    job_id = jobs.create_job(name, len(blob), "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(blob)
    job = jobs.get_job(job_id, redact_password=False)
    job["status"] = "complete"
    jobs._write_manifest(job_id, job)
    return job_id, job_dir, input_path


def _chunk(ctype, payload):
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", zlib.crc32(ctype + payload) & 0xFFFFFFFF)


def test_shared_flag_shapes():
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parent / "flag_shapes.py"
    spec = importlib.util.spec_from_file_location("flag_shapes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from stego_triage.flags import search, search_bytes
    module.assert_scanner(search, search_bytes)


def test_nulls_do_not_hide_a_utf16_flag():
    from stego_triage.flags import findings_for_bytes, set_flag_prefix
    blob = b"\x00" * 5000 + "H4G{after-nul}".encode("utf-16le")
    assert any(item["value"] == "H4G{after-nul}" for item in findings_for_bytes(blob))
    set_flag_prefix("ZZZ")
    try:
        assert any(item["value"] == "ZZZ{custom}" for item in findings_for_text("ZZZ{custom}"))
    finally:
        set_flag_prefix("")
    assert findings_for_text("ZZZ{custom}") == []


def test_encoding_lead_keeps_the_line_and_a_second_place():
    from stego_triage.flags import charset_finding
    from stego_triage.worker import merge_findings

    hexed = findings_for_text("before\n666c61677b68697d\nafter")
    flag = next(item for item in hexed if item["value"] == "flag{hi}")
    assert flag["line"] == 2
    assert "666c61677b68697d" in flag["excerpt"]

    decoded = findings_for_text("see 68656c6c6f776f726c64 here")
    lead = next(item for item in decoded if item["kind"] == "encoding")
    assert lead["value"] == "helloworld"
    assert lead["line"] == 1
    assert "68656c6c6f776f726c64" in lead["excerpt"]
    assert not any(item["kind"] == "candidate_flag" for item in decoded)

    assert charset_finding(b"hello").get("value") == "UTF-8"
    assert charset_finding(b"\xff\xfe" + "Hi".encode("utf-16le")[2:]).get("value") == "UTF-16 LE"
    wide = "H4G{wide-text-sample}".encode("utf-16le")
    assert charset_finding(wide)["value"] == "UTF-16 LE"
    assert charset_finding(b"\x89PNG\r\n\x1a\n" + bytes(64))["value"] == "binary"

    merged = []
    merge_findings(merged, [{"kind": "candidate_flag", "value": "flag{a}", "evidence": "one", "line": 2}], "strings")
    merge_findings(merged, [{"kind": "candidate_flag", "value": "flag{a}", "evidence": "two", "line": 9}], "zsteg")
    assert len(merged) == 1
    assert [item["analyzer_id"] for item in merged[0]["locations"]] == ["strings", "zsteg"]


def test_flag_scan_split_wrapped_and_plain_text():
    split = findings_for_text("prefix f l a g { s p l i t } suffix")
    assert any(item["value"] == "flag{split}" and "split" in item["title"] for item in split)

    wrapped = findings_for_text("ZmxhZ3t3cmFwcGVkfQ==")
    assert any(item["value"] == "flag{wrapped}" and "base64" in item["title"] for item in wrapped)

    hexed = findings_for_text("666c61677b68697d")
    assert any(item["value"] == "flag{hi}" and "hex" in item["title"] for item in hexed)

    intact = findings_for_text("see picoCTF{f4k3_fl4g} here")
    assert any(item["value"] == "picoCTF{f4k3_fl4g}" for item in intact)

    contest = findings_for_text("see H4G{round} here")
    assert any(item["value"].lower() == "h4g{round}" for item in contest)
    contest_split = findings_for_text("H 4 G { s p l i t }")
    assert any(item["value"].lower() == "h4g{split}" and "split" in item["title"] for item in contest_split)

    assert findings_for_text("The flag is not split across this sentence.") == []


def test_attach_flags_reads_a_carved_file():
    job_id, job_dir, _input_path = _job_file("note.txt", b"flag{carved}")
    art_id = "carve.txt"
    with open(os.path.join(job_dir, "artifacts", art_id), "wb") as handle:
        handle.write(b"flag{carved}")
    result = {"findings": []}
    attach_flags(result, job_dir, "foremost carve", [{"id": art_id, "size": 12}])
    assert result["findings"][0]["value"] == "flag{carved}"
    assert jobs.analysis_input_path(job_dir, {"input": {"analysis_file": "../file"}}, "fallback") == "fallback"
    assert jobs.analysis_input_path(job_dir, {"input": {"analysis_file": art_id}}, "fallback").endswith(art_id)
    assert job_id


def test_structural_repairs_and_trailing_containers():
    broken = b"\x00" * 8 + TINY_PNG[8:]
    repaired, _message, mime, _name, kind = structural_repair(broken)
    assert kind == "png"
    assert mime == "image/png"
    assert repaired == TINY_PNG

    jpeg = structural_repair(b"\x00\x00\xff\xe0\x00\x10JFIF\x00rest")
    assert jpeg[0].startswith(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert structural_repair(b"XXXX\x00\x10JFIF\x00rest")[0].startswith(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert structural_repair(b"XXX89arest")[0].startswith(b"GIF89a")

    assert trailing_bytes(TINY_PNG) is None
    assert trailing_bytes(TINY_PNG + b"flag{trail}") == b"flag{trail}"
    assert trailing_bytes(b"GIF89a" + b"\x00" * 8 + b"\x3bflag{gifend}").endswith(b"flag{gifend}")
    assert b"flag{pdfend}" in trailing_bytes(b"%PDF-1.4\n%%EOF\nflag{pdfend}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("a.txt", "hi")
    assert trailing_bytes(buffer.getvalue() + b"flag{zipend}") == b"flag{zipend}"


def test_magic_repair_carves_prefix_and_keeps_original():
    original = b"XXXX" + TINY_PNG
    _job_id, job_dir, input_path = _job_file("broken.png", original)
    stale = jobs.get_job(os.path.basename(job_dir), redact_password=False)
    stale["input"]["declared_mime"] = "image/png"
    stale["warnings"] = ["MIME mismatch: declared image/png, detected application/octet-stream"]
    jobs._write_manifest(os.path.basename(job_dir), stale)
    result = MagicRepairAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    repaired = os.path.join(job_dir, "artifacts", "repaired.png")
    with open(repaired, "rb") as handle:
        assert handle.read(8) == b"\x89PNG\r\n\x1a\n"
    with open(input_path, "rb") as handle:
        assert handle.read() == original
    job = jobs.get_job(os.path.basename(job_dir), redact_password=False)
    assert job["input"]["analysis_file"] == "repaired.png"
    assert "png" in job["input"]["format_tags"]
    assert not any(str(item).startswith("MIME mismatch:") for item in job["warnings"])


def test_magic_repair_saves_trailing_flag_without_replacing_png():
    original = TINY_PNG + b"flag{trail}"
    _job_id, job_dir, input_path = _job_file("appended.png", original)
    result = MagicRepairAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert any(item["value"] == "flag{trail}" for item in result["findings"])
    with open(os.path.join(job_dir, "artifacts", "trailing.bin"), "rb") as handle:
        assert handle.read() == b"flag{trail}"
    with open(input_path, "rb") as handle:
        assert handle.read() == original
    job = jobs.get_job(os.path.basename(job_dir), redact_password=False)
    assert "analysis_file" not in job["input"]


def test_magic_repair_ignores_a_normal_png():
    _job_id, job_dir, input_path = _job_file("ok.png", TINY_PNG)
    result = MagicRepairAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "no_result"
    assert result["artifacts"] == []


def test_png_text_chunks_include_compressed_text():
    text = _chunk(b"tEXt", b"Comment\x00flag{chunk}")
    ztext = _chunk(b"zTXt", b"Note\x00\x00" + zlib.compress(b"flag{ziptext}"))
    png = TINY_PNG[:-12] + text + ztext + TINY_PNG[-12:]
    _job_id, job_dir, input_path = _job_file("text.png", png)
    result = PngTextAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    values = [item["value"] for item in result["findings"]]
    assert "flag{chunk}" in values
    assert "flag{ziptext}" in values


def test_trailing_whitespace_decodes_a_flag():
    lines = []
    for char in "flag{ws!!}":
        for shift in range(7, -1, -1):
            bit = (ord(char) >> shift) & 1
            lines.append("x" + ("\t" if bit else " "))
    encoded = "\n".join(lines)
    assert any(item == "flag{ws!!}" for item in decode_trailing_whitespace(encoded))
    assert decode_trailing_whitespace("Just a normal sentence.\nNothing hidden here.\n") == []

    _job_id, job_dir, input_path = _job_file("hidden.txt", encoded.encode("ascii"))
    result = WhitespaceAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert any(item["value"] == "flag{ws!!}" for item in result["findings"])
