#!/usr/bin/env python3
"""specter-rs demo harness server.

Serves the test payloads and the job queue to the Windows test VM over the
tailnet, and collects the run reports (specter.log, WER crash events, exit
codes) the agent posts back. Lab automation only: plain HTTP, no auth - the
whole tailnet is the lab.

  GET  /job        -> the queued job (job.json in the shared dir)
  GET  /<file>     -> any file from the shared directory
  POST /report      -> saves the JSON report + prints a one-line summary

Usage:  python3 server.py [port]   (default 8888, binds 0.0.0.0)
"""
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SHARED = Path(os.environ.get("SPT_HARNESS_DIR", "/tmp/spt-demo-serve"))
REPORTS = SHARED / "reports"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stdout.write("[harness] %s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/job":
            job_file = SHARED / "job.json"
            body = job_file.read_bytes() if job_file.exists() else b'{"action": "none"}'
            self._send(200, body, "application/json")
            return
        name = path.lstrip("/")
        target = (SHARED / name).resolve()
        if not str(target).startswith(str(SHARED.resolve())) or not target.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = "application/json" if name.endswith(".json") else "application/octet-stream"
        self._send(200, target.read_bytes(), ctype)

    def do_POST(self):
        if self.path.split("?")[0] != "/report":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        out = REPORTS / ("report-%s.json" % stamp)
        REPORTS.mkdir(parents=True, exist_ok=True)
        out.write_bytes(body)
        try:
            r = json.loads(body)
            summary = "id=%s name=%s alive=%s exit=%s log=%dB wer=%s" % (
                r.get("id"), r.get("name"), r.get("alive"),
                r.get("exit_code"), len(r.get("specter_log") or ""),
                "yes" if r.get("wer") else "no",
            )
        except Exception as e:
            summary = "unparseable report: %s" % e
        sys.stdout.write("[harness] REPORT %s -> %s\n" % (out.name, summary))
        sys.stdout.flush()
        self._send(200, b"ok", "text/plain")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("[harness] serving %s on 0.0.0.0:%d (reports in %s)" % (SHARED, port, REPORTS))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
