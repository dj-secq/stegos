import os
import pathlib
import tempfile
import numpy as np
from PIL import Image
import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.visual import (
    PreviewAnalyzer,
    BitPlaneAnalyzer,
    ColorRemapAnalyzer,
    ZbarAnalyzer,
    pack_plane,
    zbar_payloads,
)
from stego_triage.runner import RunResult

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def create_test_image(path, mode="RGB"):
    img = Image.fromarray(np.random.randint(0, 256, (10, 10, 3 if mode == "RGB" else 4), dtype=np.uint8), mode)
    img.save(path, "PNG")

def test_preview_analyzer():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path)
    
    a = PreviewAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert len(res["artifacts"]) == 1
    assert os.path.exists(os.path.join(job_dir, "artifacts", res["artifacts"][0]["id"]))

def test_bit_planes():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path, "RGBA")
    
    a = BitPlaneAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    # 4 channels * 8 planes + 8 superimposed = 40 images
    assert len(res["artifacts"]) == 40
    assert all("channel" in item and "bit" in item for item in res["artifacts"])
    red_lsb = next(item for item in res["artifacts"] if item["id"] == "plane_R_0.png")
    assert red_lsb["channel"] == "R" and red_lsb["bit"] == 0
    overlay = next(item for item in res["artifacts"] if item["id"] == "plane_RGB_0.png")
    assert overlay["channel"] == "RGB" and overlay["bit"] == 0

def _image_with_channel_bits(path, text, msb_first):
    bits = []
    for byte in text.encode("ascii"):
        shifts = range(7, -1, -1) if msb_first else range(8)
        for shift in shifts:
            bits.append((byte >> shift) & 1)
    width = 32
    height = max(1, (len(bits) + width - 1) // width)
    arr = np.zeros((height, width, 3), dtype=np.uint8)
    for index, bit in enumerate(bits):
        y, x = divmod(index, width)
        arr[y, x, 0] = bit
    Image.fromarray(arr, "RGB").save(path, "PNG")


def test_bit_plane_packs_channel_bits():
    assert pack_plane(np.array([[0, 1, 0, 0, 1, 0, 0, 0]], dtype=np.uint8), True) == b"H"
    assert pack_plane(np.array([[0, 0, 0, 1, 0, 0, 1, 0]], dtype=np.uint8), False) == b"H"

    job_id = jobs.create_job("lsb.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    _image_with_channel_bits(input_path, "H4G{plane}", msb_first=True)
    res = BitPlaneAnalyzer().run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert len(res["artifacts"]) == 32
    assert any(item["value"] == "H4G{plane}" and "msb first" in item["evidence"] for item in res["findings"])


def test_bit_plane_packs_lsb_first():
    job_id = jobs.create_job("lsb2.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    _image_with_channel_bits(input_path, "H4G{lowbit}", msb_first=False)
    res = BitPlaneAnalyzer().run(input_path, job_dir, {})
    assert any(item["value"] == "H4G{lowbit}" and "lsb first" in item["evidence"] for item in res["findings"])


def test_rgb_interleaved_bit_is_scanned():
    text = b"flag{rgb}"
    bits = [((byte >> shift) & 1) for byte in text for shift in range(7, -1, -1)]
    assert len(bits) == 72
    pixels = [(bits[index] * 255, bits[index + 1] * 255, bits[index + 2] * 255) for index in range(0, 72, 3)]
    job_id = jobs.create_job("rgb.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    image = Image.new("RGB", (24, 1))
    image.putdata(pixels)
    image.save(input_path, "PNG")
    res = BitPlaneAnalyzer().run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert len(res["artifacts"]) == 32
    assert any(item["value"] == "flag{rgb}" and "RGB interleaved" in item["evidence"] and "msb first" in item["evidence"] for item in res["findings"])


def test_bit_plane_respects_the_pixel_cap(monkeypatch):
    monkeypatch.setattr(config, "MAX_PIXELS", 1)
    job_id = jobs.create_job("big.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path)
    res = BitPlaneAnalyzer().run(input_path, job_dir, {})
    assert res["status"] == "failed"
    assert "pixel" in res["error"].lower()


def test_zbar_payloads_keep_colons_in_the_value():
    assert zbar_payloads("QR-Code:https://example.test/H4G{x}\nEAN-13:123") == [
        "https://example.test/H4G{x}",
        "123",
    ]


def test_zbar_scans_an_image_payload(monkeypatch):
    job_id = jobs.create_job("code.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path)
    calls = []

    def fake_which(name):
        return "/usr/bin/" + name

    def fake_run(argv, job_dir, stdout_path, stderr_path, **kwargs):
        calls.append(argv)
        result = RunResult()
        result.exit_code = 0
        result.duration_ms = 1
        result.stdout_preview = "QR-Code:H4G{from-qr}\n"
        return result

    monkeypatch.setattr("stego_triage.analyzers.visual.shutil.which", fake_which)
    monkeypatch.setattr("stego_triage.analyzers.visual.run_bounded", fake_run)
    res = ZbarAnalyzer().run(input_path, job_dir, {})
    assert calls[0][:2] == ["zbarimg", "-q"]
    assert any(item["value"] == "H4G{from-qr}" for item in res["findings"])
    assert res["status"] == "success"


def test_zbar_scans_a_rendered_pdf_page(monkeypatch):
    job_id = jobs.create_job("code.pdf", 100, "application/pdf", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(b"%PDF-1.4\n")

    def fake_which(name):
        return "/usr/bin/" + name

    def fake_run(argv, job_dir, stdout_path, stderr_path, **kwargs):
        result = RunResult()
        result.exit_code = 0
        result.duration_ms = 1
        if argv[0] == "pdftoppm":
            prefix = argv[-1]
            os.makedirs(os.path.dirname(prefix), exist_ok=True)
            with open(prefix + "-1.png", "wb") as handle:
                handle.write(b"png")
            result.stdout_preview = ""
            return result
        result.stdout_preview = "QR-Code:H4G{page}\n"
        return result

    monkeypatch.setattr("stego_triage.analyzers.visual.shutil.which", fake_which)
    monkeypatch.setattr("stego_triage.analyzers.visual.run_bounded", fake_run)
    res = ZbarAnalyzer().run(input_path, job_dir, {})
    assert any(item["value"] == "H4G{page}" for item in res["findings"])
    assert not os.path.isdir(os.path.join(job_dir, "artifacts", "_zbar_pages"))


def test_zbar_reports_a_missing_binary(monkeypatch):
    job_id = jobs.create_job("code.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path)
    monkeypatch.setattr("stego_triage.analyzers.visual.shutil.which", lambda name: None)
    res = ZbarAnalyzer().run(input_path, job_dir, {})
    assert res["status"] == "no_result"
    assert "zbarimg" in res["summary"]


def test_stego_image_installs_zbar_tools():
    dockerfile = pathlib.Path(__file__).resolve().parents[2].joinpath("Dockerfile").read_text()
    assert "zbar-tools" in dockerfile


def test_color_remaps():
    job_id = jobs.create_job("test.png", 100, "image/png", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    create_test_image(input_path, "RGB")
    
    a = ColorRemapAnalyzer()
    res = a.run(input_path, job_dir, {})
    assert res["status"] == "success"
    assert len(res["artifacts"]) == 8
