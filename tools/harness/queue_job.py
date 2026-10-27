#!/usr/bin/env python3
"""Queue a run job for the Windows test agent.

Usage:
  python3 queue_job.py --name specter-demo-apc.exe \
      --url http://100.126.19.5:8888/specter-demo-apc.exe \
      --timeout-ms 60000 [--id <id>]

Writes job.json into the harness shared directory: the agent polls it,
runs the payload once, and posts the diagnostics back.
"""
import argparse
import json
import os
import time
from pathlib import Path

SHARED = Path(os.environ.get("SPT_HARNESS_DIR", "/tmp/spt-demo-serve"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="local file name on the agent side")
    ap.add_argument("--url", required=True, help="download URL of the payload")
    ap.add_argument("--timeout-ms", type=int, default=60000)
    ap.add_argument("--id", default=None, help="job id (default: timestamp)")
    args = ap.parse_args()

    job = {
        "id": args.id or ("job-%d" % int(time.time())),
        "action": "run",
        "name": args.name,
        "blob_url": args.url,
        "timeout_ms": args.timeout_ms,
    }
    SHARED.mkdir(parents=True, exist_ok=True)
    (SHARED / "job.json").write_text(json.dumps(job))
    print("[queue] %s" % json.dumps(job))


if __name__ == "__main__":
    main()
