#!/usr/bin/env python3
"""Run a battery of BOF tests (`execute bof`) against a live specter-rs session
through the AdaptixC2 v1.2 teamserver REST API.

Usage:
  python3 api_bof_test.py [--process specter-r13] [--bof-dir DIR] [--async]

Flow per BOF:
  1. POST /endpoint/otp/generate {"type":"tmp_upload","data":{"id":name}} -> otp
  2. POST /endpoint/otp/upload/temp?otp=... (multipart "file")             -> stocke le .o
  3. POST /endpoint/agent/command/execute {id, cmdline:"execute bof x",
     data: {"bof": {"__file_ref": name}}}                                   -> le serveur
     base64-encore le .o dans les args, l'axscript du plugin packe la tache.

BOF output lands in the session console (AdaptixC2 client) and in specter.log
on the implant ("bof: exec" / "bof: done"); fetch the log with:
  python3 queue_job.py --action log --id mylog
"""
import argparse
import json
import os
import ssl
import glob
import time
import urllib.request

BASE = "https://localhost:4321/endpoint"
PASSWORD = "pass"
VERSION = "1.2"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def api(method, path, body=None, token=None, raw_body=None, ctype="application/json"):
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": ctype})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
        return json.loads(r.read().decode())


def api_upload(path, token, otp, file_path, file_name):
    # multipart/form-data with field "file"
    boundary = "----vibebofboundary"
    with open(file_path, "rb") as f:
        content = f.read()
    body = (
        ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
         "Content-Type: application/octet-stream\r\n\r\n" % (boundary, file_name)).encode()
        + content + ("\r\n--%s--\r\n" % boundary).encode()
    )
    req = urllib.request.Request(BASE + path + "?otp=" + otp, data=body, method="POST",
                                 headers={"Content-Type": "multipart/form-data; boundary=" + boundary,
                                          "Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, context=CTX, timeout=120) as r:
        return r.status


def login():
    return api("POST", "/login", {"username": "", "password": PASSWORD, "version": VERSION})["access_token"]


def agents(token):
    return api("GET", "/agent/list", token=token)


def pick_agent(token, process_name):
    cands = [a for a in agents(token) if process_name in (a.get("a_process") or "")]
    if not cands:
        raise SystemExit("no agent matching %r (have: %s)" % (
            process_name, ", ".join(sorted({a.get("a_process") for a in agents(token)}))))
    cands.sort(key=lambda a: -a.get("a_last_tick", 0))
    return cands


def send_bof(token, agent_id, bof_path, async_mode):
    name = os.path.basename(bof_path)
    otp = api("POST", "/otp/generate", {"type": "tmp_upload", "data": {"id": name}}, token=token)["message"]
    api_upload("/otp/upload/temp", token, otp, bof_path, name)
    flag = "-a " if async_mode else ""
    body = {
        "id": agent_id, "ui": False,
        "cmdline": "execute bof %splaceholder" % flag,
        "data": json.dumps({"bof": {"__file_ref": name}}),
        "hook_id": "", "handler_id": "", "wait_answer": False,
    }
    return api("POST", "/agent/command/execute", body, token=token)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--process", default="specter-r")
    ap.add_argument("--bof-dir", default="/tmp/bofs_all")
    ap.add_argument("--async", action="store_true", dest="asynf")
    ap.add_argument("--only", default="")
    ap.add_argument("--all-agents", action="store_true", help="send to every matching agent")
    args = ap.parse_args()

    bofs = sorted(glob.glob(os.path.join(args.bof_dir, "*.o")))
    if args.only:
        bofs = [b for b in bofs if args.only in os.path.basename(b)]
    if not bofs:
        raise SystemExit("no .o in %s" % args.bof_dir)

    token = login()
    targets = pick_agent(token, args.process)
    if not args.all_agents:
        targets = targets[:1]
    print("agents:", [a["a_id"] for a in targets], "| bofs:", len(bofs))

    for agent in targets:
        for bof in bofs:
            r = send_bof(token, agent["a_id"], bof, args.asynf)
            print("[%s] %s -> ok=%s %s" % (agent["a_id"][:8], os.path.basename(bof),
                                           r.get("ok"), str(r.get("message"))[:100]))
            time.sleep(1)


if __name__ == "__main__":
    main()
