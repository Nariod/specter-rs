#!/usr/bin/env python3
"""Drive a live specter-rs session over the AdaptixC2 v1.2 teamserver REST API
and run a battery of BOF tests (`execute bof`) against it.

Usage:
  python3 api_bof_test.py [--process specter-r07.exe] [--bof-dir DIR] [--async]

- logs in with the teamserver password (debug profile: user "", password "pass")
- picks the most recently active agent whose a_process matches --process
- sends `execute bof <file>` (or `execute bof -a <file>` with --async) for every
  *.o in --bof-dir (default /tmp/spt-demo-serve), via POST /endpoint/agent/command/raw
- prints each command's ack; BOF output lands in the session console and in
  specter.log on the VM (bof: exec / bof: done) — fetch it with:
      python3 queue_job.py --action log --id mylog
"""
import argparse
import base64
import json
import ssl
import time
import urllib.request

BASE = "https://localhost:4321/endpoint"
PASSWORD = "pass"
VERSION = "1.2"


def api(method, path, body=None, token=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    if token:
        req.add_header("Authorization", "Bearer " + token)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
        return json.loads(r.read().decode())


def login():
    r = api("POST", "/login", {"username": "", "password": PASSWORD, "version": VERSION})
    return r["access_token"]


def pick_agent(token, process_name):
    agents = api("GET", "/agent/list", token=token)
    cands = [a for a in agents if process_name in (a.get("a_process") or "")]
    if not cands:
        raise SystemExit("no agent matching process %r (have: %s)" % (
            process_name, ", ".join(sorted({a.get("a_process") for a in agents}))))
    cands.sort(key=lambda a: -a.get("a_last_tick", 0))
    return cands[0]


def send_cmd(token, agent_id, cmdline):
    return api("POST", "/agent/command/raw", {"id": agent_id, "cmdline": cmdline}, token=token)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--process", default="specter-r")
    ap.add_argument("--bof-dir", default="/tmp/spt-demo-serve")
    ap.add_argument("--async", action="store_true", dest="asynf", help="pass -a (async BOF pool)")
    ap.add_argument("--only", default="", help="substring filter on the .o file name")
    args = ap.parse_args()

    import glob
    import os

    bofs = sorted(glob.glob(os.path.join(args.bof_dir, "*.o")))
    if args.only:
        bofs = [b for b in bofs if args.only in os.path.basename(b)]
    if not bofs:
        raise SystemExit("no .o files in %s" % args.bof_dir)

    token = login()
    agent = pick_agent(token, args.process)
    print("agent: %s (%s) last_tick_age=%ss" % (
        agent["a_id"], agent.get("a_process"),
        int(time.time()) - agent.get("a_last_tick", 0)))

    for bof in bofs:
        flag = " -a" if args.asynf else ""
        cmdline = "execute bof%s %s" % (flag, bof)
        r = send_cmd(token, agent["a_id"], cmdline)
        print("[%s] %s -> ok=%s %s" % (
            os.path.basename(bof), cmdline, r.get("ok"), str(r.get("message"))[:120]))
        time.sleep(2)


if __name__ == "__main__":
    main()
