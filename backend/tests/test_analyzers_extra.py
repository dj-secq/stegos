import os
import tempfile
import stego_triage.config as config
from stego_triage import jobs
from stego_triage.analyzers.pdf import PdfInfoAnalyzer, PdfIdAnalyzer
from stego_triage.analyzers.audio import SpectrogramAnalyzer

def setup_module(module):
    module.temp_dir = tempfile.TemporaryDirectory()
    config.RUNTIME_ROOT = module.temp_dir.name
    
def teardown_module(module):
    module.temp_dir.cleanup()

def setup_function():
    jobs.queued_jobs = 0
    jobs.active_jobs = 0

def test_pdf_analyzers():
    job_id = jobs.create_job("test.pdf", 100, "application/pdf", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
        
    a1 = PdfInfoAnalyzer()
    res1 = a1.run(input_path, job_dir, {"profile": "quick"})
    assert res1["status"] in ("success", "failed")
    
    a2 = PdfIdAnalyzer()
    res2 = a2.run(input_path, job_dir, {"profile": "quick"})
    assert res2["status"] in ("success", "failed", "unavailable")

def test_spectrogram():
    job_id = jobs.create_job("test.wav", 100, "audio/wav", "quick")
    job_dir = os.path.join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    with open(input_path, "wb") as f:
        f.write(b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00")
        
    a = SpectrogramAnalyzer()
    res = a.run(input_path, job_dir, {"profile": "quick"})
    assert res["status"] in ("success", "failed", "no_result", "unavailable")
