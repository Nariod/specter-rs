"""specter-rs test harness server (v2).

Endpoints:
  GET  /job            -> the queued run job (job.json in the shared dir)
  GET  /job?wait=N&last=<id>
                        -> long-poll: hold up to N seconds waiting for a
                           job whose id differs from <last>, then return
                           it (or {"action": "none"} on timeout)
  GET  /control        -> the queued control (control.json; consumed on
                           read - log/stop signals for the agent)
  GET  /<file>         -> any file from the shared directory
  POST /report         -> agent report (dumped into reports/)

Usage:  python3 server.py [port]   (default 8888, binds 0.0.0.0)
"""
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SHARED = Path(os.environ.get("SPT_HARNESS_DIR", "/tmp/spt-demo-serve"))
REPORTS = SHARED / "reports"

# Signaled when job.json changes (long-poll wake-up).
_job_event = threading.Event()


def _fire_event():
    _job_event.set()
    _job_event.clear()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[harness] %s - %s\n" % (self.address_string(), fmt % args))
        sys.stdout.flush()

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        params = {}
        for part in query.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v

        if path == "/job":
            wait = float(params.get("wait", 0) or 0)
            last = params.get("last", "")
            deadline = time.time() + min(wait, 60.0)
            while True:
                job_file = SHARED / "job.json"
                if job_file.exists():
                    try:
                        job = json.loads(job_file.read_text())
                        if str(job.get("id", "")) != last:
                            self._send(200, json.dumps(job).encode(), "application/json")
                            return
                    except (ValueError, OSError):
                        pass
                if time.time() >= deadline:
                    self._send(200, b'{"action": "none"}', "application/json")
                    return
                _job_event.wait(timeout=1.0)
            return

        if path == "/control":
            ctrl_file = SHARED / "control.json"
            if ctrl_file.exists():
                body = ctrl_file.read_bytes()
                try:
                    ctrl_file.unlink()
                except OSError:
                    pass
                self._send(200, body, "application/json")
                return
            self._send(200, b'{"action": "none"}', "application/json")
            return

        name = path.lstrip("/")
        target = (SHARED / name).resolve()
        if not str(target).startswith(str(SHARED.resolve())) or not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = "application/json" if name.endswith(".json") else "application/octet-stream"
        self._send(200, target.read_bytes(), ctype)

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/report":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        REPORTS.mkdir(exist_ok=True)
        out = REPORTS / ("report-%s.json" % stamp)
        out.write_bytes(body)
        self._send(200, b'{"ok": true}', "application/json")
        sys.stdout.write("[harness] report saved: %s (%d bytes)\n" % (out.name, len(body)))
        sys.stdout.flush()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    SHARED.mkdir(exist_ok=True)
    REPORTS.mkdir(exist_ok=True)
    # Watch job.json for changes (long-poll wake-ups). Small directories,
    # a 0.5 s stat poll inside the server process is plenty.
    def watcher():
        last_mtime = None
        while True:
            try:
                mtime = (SHARED / "job.json").stat().st_mtime_ns
            except OSError:
                mtime = None
            if mtime != last_mtime:
                last_mtime = mtime
                _fire_event()
            time.sleep(0.5)

    threading.Thread(target=watcher, daemon=True).start()
    print("[harness] serving %s on 0.0.0.0:%d (v2: long-poll + control)" % (SHARED, port))
    sys.stdout.flush()
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
