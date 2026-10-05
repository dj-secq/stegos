import os
from flask import Flask, request, jsonify, send_from_directory, send_file
from werkzeug.utils import secure_filename

from . import config
from . import jobs
from . import cleanup
from . import worker
from .security import safe_join

PACKAGE_ROOT = os.path.dirname(__file__)
FRONTEND_CANDIDATES = (
    os.path.abspath(os.path.join(PACKAGE_ROOT, '..', 'frontend')),
    os.path.abspath(os.path.join(PACKAGE_ROOT, '..', '..', 'frontend')),
)
DEFAULT_FRONTEND_ROOT = next(
    (path for path in FRONTEND_CANDIDATES if os.path.isdir(path)),
    FRONTEND_CANDIDATES[-1],
)
FRONTEND_ROOT = os.environ.get('FRONTEND_ROOT', DEFAULT_FRONTEND_ROOT)

app = Flask(__name__, static_folder=FRONTEND_ROOT, static_url_path='')
os.makedirs(config.RUNTIME_ROOT, exist_ok=True)

@app.before_request
def cleanup_check():
    import random
    if random.random() < 0.05:
        cleanup.cleanup_jobs()

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({
        "status": "ok",
        "version": "0.2.0",
        "active_jobs": jobs.active_jobs,
        "queue_depth": jobs.queued_jobs,
        "max_upload_bytes": config.MAX_UPLOAD_BYTES
    })

@app.route('/api/jobs', methods=['POST'])
def create_job():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Empty filename"}), 400
        
    if request.content_length and request.content_length > config.MAX_UPLOAD_BYTES:
        return jsonify({"error": "File too large"}), 413
        
    profile = request.form.get('profile', 'quick')
    if profile not in ['quick', 'deep']:
        profile = 'quick'
        
    password = request.form.get('password')
    flag_prefix = request.form.get('flag_prefix')
        
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    
    if size > config.MAX_UPLOAD_BYTES:
        return jsonify({"error": "File too large"}), 413
        
    worker.ensure_worker()
    job_id = jobs.create_job(secure_filename(file.filename), size, file.content_type, profile, password, flag_prefix)
    if not job_id:
        current = jobs.current_job()
        payload = {"error": "An analysis is already running."}
        if current and current.get("job_id"):
            payload["job_id"] = current["job_id"]
            payload["status_url"] = f"/api/jobs/{current['job_id']}"
        return jsonify(payload), 429
        
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    input_path = os.path.join(job_dir, "input", "file")
    file.save(input_path)
    
    return jsonify({
        "job_id": job_id,
        "status": "queued",
        "created_at": jobs.get_job(job_id)['created_at'],
        "status_url": f"/api/jobs/{job_id}"
    }), 202

@app.route('/api/jobs/current', methods=['GET'])
def current_job():
    worker.ensure_worker()
    current = jobs.current_job()
    if not current:
        return "", 204
    return jsonify(current)

@app.route('/api/jobs/<job_id>', methods=['GET'])
def get_job(job_id):
    manifest = jobs.get_job(job_id, redact_password=True)
    if not manifest:
        return jsonify({"error": "Not found"}), 404
    return jsonify(manifest)

@app.route('/api/jobs/<job_id>', methods=['DELETE'])
def delete_job(job_id):
    manifest = jobs.get_job(job_id, redact_password=False)
    if manifest and manifest.get('status') in ['running', 'queued']:
        manifest['status'] = 'cancelled'
        jobs._write_manifest(job_id, manifest)
    jobs.release_slot(job_id)
    cleanup.delete_job(job_id)
    return '', 204

@app.route('/api/jobs/<job_id>/input', methods=['GET'])
def get_input(job_id):
    manifest = jobs.get_job(job_id)
    if not manifest:
        return jsonify({"error": "Not found"}), 404
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    input_path = safe_join(job_dir, "input", "file") if job_dir else None
    if not input_path or not os.path.isfile(input_path):
        return jsonify({"error": "File not found on disk"}), 404
    info = manifest.get("input") or {}
    mime = info.get("detected_mime") or "application/octet-stream"
    inline = isinstance(mime, str) and mime.startswith("audio/")
    return send_file(
        input_path,
        mimetype=mime if inline else "application/octet-stream",
        as_attachment=not inline,
        download_name=info.get("display_name") or "upload",
    )

@app.route('/api/jobs/<job_id>/artifacts/<artifact_id>', methods=['GET'])
def get_artifact(job_id, artifact_id):
    manifest = jobs.get_job(job_id)
    if not manifest:
        return jsonify({"error": "Not found"}), 404
        
    valid_artifact = False
    is_preview = request.args.get('preview') == 'true'
    
    for analyzer in manifest.get('analyzers', []):
        if analyzer.get('log_artifact_id') == artifact_id:
            valid_artifact = True
            break
        for art in analyzer.get('artifacts', []):
            if art.get('id') == artifact_id:
                valid_artifact = True
                break
                
    if not valid_artifact:
        return jsonify({"error": "Artifact not found"}), 404
        
    job_dir = safe_join(config.RUNTIME_ROOT, job_id)
    artifact_path = safe_join(job_dir, "artifacts", artifact_id)
    log_path = safe_join(job_dir, "logs", artifact_id)
    
    if artifact_path and os.path.exists(artifact_path):
        return send_file(artifact_path, as_attachment=not is_preview)
    if log_path and os.path.exists(log_path):
        return send_file(log_path, as_attachment=not is_preview)
        
    return jsonify({"error": "File not found on disk"}), 404
