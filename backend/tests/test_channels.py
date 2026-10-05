import os
import shutil
import struct
import tempfile
import wave

import pytest
from PIL import Image

import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.audio import SpectrogramAnalyzer, WaveformAnalyzer
from stego_triage.analyzers.frames import GifFrameAnalyzer
from stego_triage.analyzers.profile import FileProfileAnalyzer
from stego_triage.analyzers.stego import JpseekAnalyzer, JstegAnalyzer, OpenStegoAnalyzer
from stego_triage.analyzers.text import UnusualSpaceAnalyzer, ZeroWidthAnalyzer


def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name


def teardown_module(module):
    module.temp_dir.cleanup()


def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0


def _job(name):
    job_id = jobs.create_job(name, 100, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    return job_dir, os.path.join(job_dir, "input", "file")


def _write_wav(path, channels=1, rate=8000, seconds=0.05, amplitude=8000):
    frames = int(rate * seconds)
    samples = []
    for index in range(frames):
        value = amplitude if (index // 20) % 2 == 0 else -amplitude
        samples.extend([value] * channels)
    payload = struct.pack("<" + "h" * len(samples), *samples)
    with wave.open(path, "wb") as handle:
        handle.setnchannels(channels)
        handle.setsampwidth(2)
        handle.setframerate(rate)
        handle.writeframes(payload)


def _bits(text, one):
    bits = []
    for byte in text.encode("ascii"):
        for shift in range(7, -1, -1):
            bits.append(one if (byte >> shift) & 1 else " ")
    return "".join(bits)


def test_missing_password_tools_are_unavailable(monkeypatch):
    monkeypatch.setattr("stego_triage.analyzers.stego.shutil.which", lambda _name, path=None: None)
    _job_dir, input_path = _job("photo.jpg")
    with open(input_path, "wb") as handle:
        handle.write(b"\xff\xd8\xff\xd9")
    for analyzer in (JstegAnalyzer(), JpseekAnalyzer(), OpenStegoAnalyzer()):
        result = analyzer.run(input_path, _job_dir, {"password": "secret"})
        assert result["status"] == "unavailable"
        assert not result["error"]
        assert "not installed" in result["summary"]


def test_waveform_and_spectrogram_on_a_wav():
    job_dir, input_path = _job("tone.wav")
    _write_wav(input_path, channels=2)
    wave_result = WaveformAnalyzer().run(input_path, job_dir, {})
    assert wave_result["status"] == "success"
    assert any(item["id"] == "waveform.png" for item in wave_result["artifacts"])
    assert "Hz" in wave_result["summary"]
    assert "30 seconds" not in wave_result["summary"]

    spec = SpectrogramAnalyzer().run(input_path, job_dir, {})
    if shutil.which("sox"):
        assert spec["status"] == "success"
        assert len(spec["artifacts"]) == 2
        assert "2 channels" in spec["summary"]
    else:
        assert spec["status"] == "unavailable"
        assert not spec["error"]


def test_zero_width_decodes_and_skips_binary():
    job_dir, input_path = _job("note.txt")
    bits = []
    for byte in b"H4G{zwsp}":
        for shift in range(7, -1, -1):
            bits.append("\u200c" if (byte >> shift) & 1 else "\u200b")
    with open(input_path, "w", encoding="utf-8") as handle:
        handle.write("Hello" + "".join(bits) + "\u200d")
    result = ZeroWidthAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert any(item["value"] == "H4G{zwsp}" for item in result["findings"])
    assert any("U+200B" in item["value"] and "U+200D" in item["value"] for item in result["findings"])

    jobs.queued_jobs = 0
    binary_dir, binary_path = _job("bin.dat")
    with open(binary_path, "wb") as handle:
        handle.write(b"\x00" + ("\u200b".encode("utf-8") * 80) + b"\x00" * 5000)
    skipped = ZeroWidthAnalyzer().run(binary_path, binary_dir, {})
    assert skipped["status"] == "no_result"


def test_unusual_spaces_count_and_decode():
    job_dir, input_path = _job("spaces.txt")
    payload = _bits("H4G{emsp}", "\u2003")
    with open(input_path, "w", encoding="utf-8") as handle:
        handle.write("go" + payload)
    result = UnusualSpaceAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert any("U+2003" in item["value"] for item in result["findings"])
    assert any(item["value"] == "H4G{emsp}" for item in result["findings"])

    jobs.queued_jobs = 0
    binary_dir, binary_path = _job("spaces.bin")
    with open(binary_path, "wb") as handle:
        handle.write(b"\x00" + (" \u2003".encode("utf-8") * 40) + b"\x00" * 5000)
    assert UnusualSpaceAnalyzer().run(binary_path, binary_dir, {}).get("status") == "no_result"


def test_gif_frames_list_delays_and_png_skips():
    job_dir, input_path = _job("anim.gif")
    first = Image.new("RGB", (4, 4), (255, 0, 0))
    second = Image.new("RGB", (4, 4), (0, 0, 255))
    first.save(input_path, save_all=True, append_images=[second], duration=[40, 80], loop=0, format="GIF")
    result = GifFrameAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert [item["frame"] for item in result["artifacts"]] == [0, 1]
    assert [item["delay_ms"] for item in result["artifacts"]] == [40, 80]
    assert all(os.path.isfile(os.path.join(job_dir, "artifacts", item["id"])) for item in result["artifacts"])

    assert GifFrameAnalyzer().can_run("image", ["image", "png"]) is False


def test_profile_tags_a_gif():
    if not shutil.which("file"):
        pytest.skip("file is not installed")
    job_dir, input_path = _job("still.gif")
    Image.new("RGB", (2, 2), (0, 255, 0)).save(input_path, format="GIF")
    result = FileProfileAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    job_id = os.path.basename(job_dir)
    assert "gif" in jobs.get_job(job_id)["input"]["format_tags"]
