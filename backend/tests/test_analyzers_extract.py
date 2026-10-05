import gzip
import io
import os
import shutil
import tempfile
import struct
import zipfile
import zlib
import pytest
import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.structure import PngcheckAnalyzer, PngRepairAnalyzer
from stego_triage.analyzers.extract import BinwalkAnalyzer, ForemostAnalyzer, signature_wants_extract

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def create_broken_png(path):
    # Create a 1x1 valid PNG then break its IHDR CRC
    valid = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDAT\x08\xd7c\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0\x00\x00\x00\x00IEND\xaeB`\x82"
    broken = valid.replace(b"\x90wS\xde", b"\x00\x00\x00\x00") # Break CRC
    with open(path, "wb") as f:
        f.write(broken)

def test_png_repair():
    job_id = jobs.create_job("broken.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_broken_png(input_path)
    
    a = PngRepairAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert len(res["artifacts"]) == 1
    
    # check that the repaired file has valid CRC
    repair_path = os.path.join(job_dir, "artifacts", res["artifacts"][0]["id"])
    with open(repair_path, "rb") as f:
        data = f.read()
    assert b"\x90wS\xde" in data

def _png_chunk(ctype, data):
    return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", zlib.crc32(ctype + data) & 0xFFFFFFFF)


def _ztxt_png(text):
    compressed = zlib.compress(text.encode("ascii"))
    png = b"\x89PNG\r\n\x1a\n"
    png += _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
    png += _png_chunk(b"zTXt", b"Comment\x00\x00" + compressed)
    png += _png_chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
    png += _png_chunk(b"IEND", b"")
    return png


def test_signature_gate_names_zip_gzip_png_and_pdf_only():
    assert signature_wants_extract("4             0x4             Zip archive data, at least v2.0 to extract")
    assert signature_wants_extract("0             0x0             gzip compressed data, from Unix")
    assert signature_wants_extract("0             0x0             PNG image, 1 x 1, 8-bit/color RGB, non-interlaced")
    assert signature_wants_extract('0             0x0             PDF document, version: "1.4"')
    assert not signature_wants_extract("117           0x75            Zlib compressed data, default compression")
    assert not signature_wants_extract("the file is named notes.zip and should not carve")


def _need_binwalk():
    if shutil.which("binwalk") is None:
        pytest.skip("binwalk is not installed")


def test_quick_binwalk_carves_a_named_zip_and_png_text():
    _need_binwalk()
    png = _ztxt_png("H4G{png-text}")
    assert b"H4G{png-text}" not in png
    job_id = jobs.create_job("carrier.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    note = os.path.join(job_dir, "note.txt")
    inner = os.path.join(job_dir, "inner.png")
    with open(note, "wb") as handle:
        handle.write(b"H4G{zip-note}\n")
    with open(inner, "wb") as handle:
        handle.write(png)
    archive = os.path.join(job_dir, "bundle.zip")
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.write(inner, "inner.png")
        bundle.write(note, "note.txt")
    with open(archive, "rb") as handle:
        payload = handle.read()
    with open(input_path, "wb") as handle:
        handle.write(b"JUNK" + payload)

    res = BinwalkAnalyzer().run(input_path, job_dir, {"profile": "quick"})
    values = [item["value"] for item in res["findings"]]
    assert "H4G{zip-note}" in values
    assert "H4G{png-text}" in values
    assert "Extracted" in res["summary"]


def test_quick_binwalk_leaves_plain_text_and_zlib_alone():
    _need_binwalk()
    job_id = jobs.create_job("plain.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(b"hello plain text\n")
    res = BinwalkAnalyzer().run(input_path, job_dir, {"profile": "quick"})
    extra = [item for item in res["artifacts"] if item["id"] != "binwalk.txt"]
    assert extra == []


def test_quick_binwalk_does_not_carve_plain_zlib():
    _need_binwalk()
    job_id = jobs.create_job("zlib.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(zlib.compress(b"hello plain text"))
    res = BinwalkAnalyzer().run(input_path, job_dir, {"profile": "quick"})
    extra = [item for item in res["artifacts"] if item["id"] != "binwalk.txt"]
    assert extra == []
    assert not any(item["value"] == "H4G{zlib}" for item in res["findings"])


def test_quick_binwalk_carves_gzip():
    _need_binwalk()
    job_id = jobs.create_job("packed.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(gzip.compress(b"H4G{gzip-note}\n"))
    res = BinwalkAnalyzer().run(input_path, job_dir, {"profile": "quick"})
    assert any(item["value"] == "H4G{gzip-note}" for item in res["findings"])


def test_open_carved_zip_saves_one_level_and_one_passphrase():
    from stego_triage.analyzers.extract import open_carved_zip
    job_id = jobs.create_job("carrier.bin", 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    os.makedirs(os.path.join(job_dir, "artifacts"), exist_ok=True)
    png = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000a49444154789c63000100000500010d0a2db40000000049454e44ae426082")
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as handle:
        handle.writestr("hidden.txt", "flag{too_deep}\n")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as handle:
        handle.writestr("secret.txt", "flag{zip_level}\npassword=hunter2\n")
        handle.writestr("pixel.png", png)
        handle.writestr("notes/drop.js", "alert(1)\n")
        handle.writestr("inner.zip", nested.getvalue())
    artifacts, findings = open_carved_zip(outer.getvalue(), job_dir, "magic")
    names = [item["name"] for item in artifacts]
    assert names == ["secret.txt", "pixel.png"]
    values = [item["value"] for item in findings]
    assert "flag{zip_level}" in values
    assert "flag{too_deep}" not in values
    assert any(item["kind"] == "passphrase_candidate" and item["value"] == "password=hunter2" for item in findings)
    saved = os.path.join(job_dir, "artifacts", next(item["id"] for item in artifacts if item["name"] == "pixel.png"))
    assert open(saved, "rb").read().startswith(b"\x89PNG")
    assert not os.access(saved, os.X_OK)
    assert not os.path.exists(os.path.join(job_dir, "input", "password.txt"))


def test_binwalk():
    job_id = jobs.create_job("test.bin", 100, "application/octet-stream", "deep")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"junkjunk\x1f\x8b\x08\x08junkjunk") # fake gzip signature
        
    a = BinwalkAnalyzer()
    res = a.run(input_path, job_dir, {"profile": "deep"})
    # binwalk might or might not succeed depending on test env, but we shouldn't crash
    assert res["status"] in ("success", "failed", "no_result")
