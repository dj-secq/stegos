import os
import tempfile

import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.metadata import StringsAnalyzer
from stego_triage.analyzers.profile import FileProfileAnalyzer
from stego_triage.passphrase import (
    filename_candidate,
    metadata_candidates,
    strings_candidates,
)

HEX32 = "5d41402abc4b2a76b9719d911017c592"


def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name


def teardown_module(module):
    module.temp_dir.cleanup()


def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0


def _values(items, kind):
    return [item["value"] for item in items if item["kind"] == kind]


def test_filename_stem_is_a_passphrase_candidate():
    item = filename_candidate("hunter2.jpg")
    assert item["kind"] == "passphrase_candidate"
    assert item["value"] == "hunter2"
    assert item["evidence"] == "filename"


def test_filename_hash_is_not_a_passphrase_candidate():
    item = filename_candidate(f"{HEX32}.jpg")
    assert item["kind"] == "hash_candidate"
    assert item["value"] == HEX32
    assert "Identify Hash Type" in item["title"]


def test_generic_filename_is_skipped():
    assert filename_candidate("image.jpg") is None
    assert filename_candidate("IMG_0001.png") is None
    assert filename_candidate("test.bin") is None


def test_metadata_tag_names_the_passphrase():
    found = metadata_candidates({
        "Comment": "a camera note",
        "Passphrase": "open sesame",
        "Software": "GIMP",
    })
    assert _values(found, "passphrase_candidate") == ["open sesame"]
    assert _values(found, "hash_candidate") == []


def test_metadata_hash_tag_is_labeled_for_hash_identification():
    found = metadata_candidates({"Password": HEX32})
    assert _values(found, "hash_candidate") == [HEX32]
    assert _values(found, "passphrase_candidate") == []


def test_strings_keeps_one_token_and_one_hash():
    text = "\n".join([
        "1a Photoshop",
        "30 JFIF",
        "40 hunter2",
        "50 another-token",
        f"60 {HEX32}",
        "70 secondhashshouldnotappear " + ("ab" * 16),
    ])
    found = strings_candidates(text)
    assert _values(found, "passphrase_candidate") == ["hunter2"]
    assert _values(found, "hash_candidate") == [HEX32]
    assert all("rockyou" not in item["value"].lower() for item in found)


def test_profile_records_the_filename_candidate():
    job_id = jobs.create_job("hunter2.jpg", 11, "image/jpeg", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as handle:
        handle.write(b"hello world")
    result = FileProfileAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    assert any(
        item["value"] == "hunter2" and item["kind"] == "passphrase_candidate"
        for item in result["findings"]
    )


def test_strings_analyzer_labels_one_candidate():
    job_id = jobs.create_job("carrier.bin", 80, "application/octet-stream", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    blob = b"Photoshop\x00hunter2\x00fromstrings\x00" + HEX32.encode() + b"\x00"
    with open(input_path, "wb") as handle:
        handle.write(blob)
    result = StringsAnalyzer().run(input_path, job_dir, {})
    assert result["status"] == "success"
    passwords = _values(result["findings"], "passphrase_candidate")
    hashes = _values(result["findings"], "hash_candidate")
    assert passwords == ["hunter2"]
    assert hashes == [HEX32]
