import os
import time
import subprocess
import signal
import select
from typing import Dict, Any, List, Optional

SANDBOX_PATH = "/usr/local/bin:/usr/bin:/bin"


class RunResult:
    def __init__(self):
        self.exit_code: int = -1
        self.signal: int = 0
        self.duration_ms: int = 0
        self.stdout_path: str = ""
        self.stderr_path: str = ""
        self.stdout_preview: str = ""
        self.stdout_truncated: bool = False
        self.timed_out: bool = False
        self.error: Optional[str] = None

def run_bounded(
    argv: List[str],
    cwd: str,
    stdout_path: str,
    stderr_path: str,
    env: Optional[Dict[str, str]] = None,
    timeout_secs: int = 60,
    max_output_bytes: int = 2 * 1024 * 1024, # 2 MiB
    preview_bytes: int = 16384,
    password_to_redact: Optional[str] = None,
    stdin_data: Optional[bytes] = None
) -> RunResult:
    res = RunResult()
    res.stdout_path = stdout_path
    res.stderr_path = stderr_path
    
    start_time = time.monotonic()
    
    safe_env = {"PATH": SANDBOX_PATH}
    if env: safe_env.update(env)
        
    try:
        proc = subprocess.Popen(
            argv, cwd=cwd, env=safe_env,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=os.setsid, shell=False
        )
        
        
        if stdin_data is not None:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
            
        out_f = open(stdout_path, "wb")
        err_f = open(stderr_path, "wb")
        
        out_written = 0
        err_written = 0
        
        poll_obj = select.poll()
        poll_obj.register(proc.stdout, select.POLLIN)
        poll_obj.register(proc.stderr, select.POLLIN)
        
        killed = False
        
        while True:
            if time.monotonic() - start_time > timeout_secs:
                res.timed_out = True
                break
                
            events = poll_obj.poll(500) # 500ms
            
            if not events:
                if proc.poll() is not None:
                    break
                continue
                
            for fd, event in events:
                if fd == proc.stdout.fileno():
                    chunk = proc.stdout.read(4096)
                    if not chunk:
                        poll_obj.unregister(proc.stdout)
                    elif out_written < max_output_bytes:
                        # Write up to max_output_bytes
                        to_write = min(len(chunk), max_output_bytes - out_written)
                        if to_write > 0:
                            if password_to_redact:
                                chunk = chunk.replace(password_to_redact.encode(), b"***REDACTED***")
                            out_f.write(chunk[:to_write])
                            out_written += to_write
                        if out_written >= max_output_bytes:
                            res.stdout_truncated = True
                elif fd == proc.stderr.fileno():
                    chunk = proc.stderr.read(4096)
                    if not chunk:
                        poll_obj.unregister(proc.stderr)
                    elif err_written < max_output_bytes:
                        to_write = min(len(chunk), max_output_bytes - err_written)
                        if to_write > 0:
                            if password_to_redact:
                                chunk = chunk.replace(password_to_redact.encode(), b"***REDACTED***")
                            err_f.write(chunk[:to_write])
                            err_written += to_write
                            
            if proc.poll() is not None:
                # read remaining if any
                pass
                
        out_f.close()
        err_f.close()
        
        if res.timed_out or out_written >= max_output_bytes:
            # Terminate if timed out or if output limits were reached and we want to stop it
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=1.0)
                except Exception:
                    pass
        else:
            proc.wait(timeout=1.0)
            
        if proc.returncode is not None:
            if proc.returncode < 0:
                res.signal = -proc.returncode
            else:
                res.exit_code = proc.returncode
                
    except Exception as e:
        res.error = str(e)
        
    res.duration_ms = int((time.monotonic() - start_time) * 1000)
    
    try:
        if os.path.exists(stdout_path):
            with open(stdout_path, "rb") as f:
                res.stdout_preview = f.read(preview_bytes).decode('utf-8', errors='replace')
    except Exception:
        pass
        
    return res
