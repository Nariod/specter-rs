"""Queue a job or a control for the Windows test agent (v2).

Usage:
  # run job (unchanged): the agent downloads and runs the payload once,
  # kills it at timeout_ms, and posts the diagnostics.
  python3 queue_job.py --name specter-demo.exe \
      --url http://100.126.19.5:8888/specter-demo.exe \
      --timeout-ms 600000 [--id <id>]

  # live log fetch: tails specter.log on the VM WITHOUT touching the
  # running beacon, posts it back within seconds.
  python3 queue_job.py --action log --id log-1

  # stop the running payload now (diagnostics report follows).
  python3 queue_job.py --action stop --id stop-1

Writes job.json (run) or control.json (log/stop) into the harness shared
directory; the agent consumes them.
"""
import argparse
import json
import os

SHARED = os.environ.get("SPT_HARNESS_DIR", "/tmp/spt-demo-serve")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--action", default="run", help="run | log | stop")
    ap.add_argument("--name", default="", help="payload file name (run)")
    ap.add_argument("--url", default="", help="payload URL (run)")
    ap.add_argument("--timeout-ms", type=int, default=60000, help="kill delay (run)")
    ap.add_argument("--id", default="", help="unique job/control id")
    args = ap.parse_args()

    if args.action == "run":
        if not args.name or not args.url or not args.id:
            raise SystemExit("run needs --name, --url and --id")
        job = {
            "id": args.id,
            "action": "run",
            "name": args.name,
            "blob_url": args.url,
            "timeout_ms": args.timeout_ms,
        }
        out = os.path.join(SHARED, "job.json")
    elif args.action in ("log", "stop"):
        if not args.id:
            raise SystemExit("log/stop needs --id")
        job = {"id": args.id, "action": args.action}
        out = os.path.join(SHARED, "control.json")
    else:
        raise SystemExit("action must be run, log or stop")

    with open(out, "w") as f:
        json.dump(job, f)
    print("[queue] %s" % json.dumps(job))


if __name__ == "__main__":
    main()
