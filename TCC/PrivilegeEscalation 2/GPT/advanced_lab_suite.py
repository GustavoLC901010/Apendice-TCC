
#!/usr/bin/env python3
"""
advanced_lab_suite.py — Safer "Realistic" Security Lab Toolkit
===========================================================
This toolbox is intentionally *realistic-looking* but remains SAFE and BENIGN.
It simulates stealthy behaviors without causing harm:

- "simulate_advanced": copies files from SRC to DST, obfuscates filenames (base64),
  encodes file contents in base64 (no encryption), can run multithreaded, and writes a
  sandbox-only "persistence marker" (never modifies system autostart).
- "beacon_test": sends base64-encoded heartbeat messages to localhost only (no external network).
- "audit" and "honeypot" are present and write detailed JSONL logs.

USAGE examples (run in an isolated VM with test data):
  python advanced_lab_suite.py simulate_advanced --src /tmp/lab_src --dst /tmp/lab_out --threads 4 --max-files 200 --sandbox /tmp/sandbox_marker
  python advanced_lab_suite.py beacon_test --host 127.0.0.1 --port 2222 --count 5 --interval 0.5
  python advanced_lab_suite.py audit --jsonl audit.jsonl
  python advanced_lab_suite.py honeypot --log honeypot.jsonl --port 2222

SAFETY: The script will never alter files outside the specified DST or SANDBOX paths,
never write to system startup locations, and never connect off-host. Use responsibly.
"""

import argparse, base64, json, os, random, shutil, socket, sqlite3, string, sys, threading, time
from datetime import datetime
from pathlib import Path
from queue import Queue

# ------------- utilities -------------

def utc_now():
    return datetime.utcnow().isoformat() + "Z"

def append_jsonl(path, obj):
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\\n")

def safe_rel(root, child):
    try:
        return str(Path(child).relative_to(root))
    except Exception:
        return str(child)

# ------------- simulate_advanced -------------

def obfuscate_name(name):
    # base64 urlsafe without padding, to simulate stealthy filename encoding
    b = base64_encode(name.encode("utf-8")).rstrip("=")
    return b + Path(name).suffix

def base64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def worker_copy(queue, src_root, dst_root, jsonl, sandbox_marker):
    while True:
        item = queue.get()
        if item is None:
            break
        src = item
        rel = safe_rel(src_root, src)
        try:
            # read, encode, write to dst with obfuscated name
            data = src.read_bytes()
            enc = base64.b64encode(data)
            obf = base64.urlsafe_b64encode(rel.encode("utf-8")).decode("ascii").rstrip("=")
            dest = dst_root / (obf + src.suffix + ".locked")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(enc)
            rec = {"ts": utc_now(), "action": "COPY_OBFUSCATED", "src": rel, "dst": str(dest.relative_to(dst_root))}
            print(rec)
            append_jsonl(jsonl, rec)
            # optionally write a sandbox persistence marker (safe): only inside sandbox_marker path
            if sandbox_marker:
                marker = Path(sandbox_marker) / "marker.txt"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text("SIMULATED_MARKER: " + utc_now(), encoding="utf-8")
        except Exception as e:
            append_jsonl(jsonl, {"ts": utc_now(), "action": "ERROR", "src": str(src), "error": str(e)})
        finally:
            queue.task_done()

def simulate_advanced(args):
    src = Path(args.src).resolve()
    dst = Path(args.dst).resolve()
    sandbox = Path(args.sandbox).resolve() if args.sandbox else None
    max_files = int(args.max_files) if args.max_files else None
    threads = int(args.threads) if args.threads else 2
    jsonl = args.jsonl

    if not src.is_dir():
        print("Source must be directory:", src); sys.exit(1)
    dst.mkdir(parents=True, exist_ok=True)
    if sandbox and not str(sandbox).startswith(str(dst)) and not sandbox.exists():
        # sandbox must be under dst or pre-existing; prevent writing to arbitrary system paths
        print("Sandbox marker must be inside destination or pre-exist. Please choose a safe sandbox path."); sys.exit(1)

    files = [p for p in src.rglob("*") if p.is_file()]
    if max_files:
        files = files[:max_files]
    q = Queue()
    for f in files:
        q.put(f)

    workers = []
    for _ in range(max(1, threads)):
        t = threading.Thread(target=worker_copy, args=(q, src, dst, jsonl, str(sandbox) if sandbox else None), daemon=True)
        t.start()
        workers.append(t)

    q.join()
    for _ in workers:
        q.put(None)
    for t in workers:
        t.join()
    print("simulate_advanced: done. total:", len(files))

# ------------- beacon_test -------------

def beacon_test(args):
    host = args.host
    port = int(args.port)
    count = int(args.count)
    interval = float(args.interval)
    jsonl = args.jsonl
    for i in range(count):
        msg = {"ts": utc_now(), "id": i, "rand": random.randint(0, 999999)}
        payload = base64.b64encode(json.dumps(msg).encode("utf-8"))
        try:
            # only to localhost or 127.0.0.1 allowed for safety
            if host not in ("127.0.0.1", "localhost", "::1"):
                print("Beacon host must be localhost for safety."); return
            with socket.create_connection((host, port), timeout=1) as s:
                s.sendall(payload + b"\\n")
                _ = s.recv(128)
            rec = {"ts": utc_now(), "event": "BEACON_SENT", "to": f"{host}:{port}", "payload_b64": payload.decode("ascii")[:80]}
            print(rec)
            append_jsonl(jsonl, rec)
        except Exception as e:
            append_jsonl(jsonl, {"ts": utc_now(), "event": "BEACON_ERROR", "error": str(e)})
        time.sleep(interval)

# ------------- audit (simple) -------------

def audit_command(args):
    # lightweight process snapshot using ps fallback to avoid extra deps
    jsonl = args.jsonl
    prev = {}
    print("audit starting...")
    try:
        while True:
            out = os.popen("ps -eo pid,comm,user").read().strip().splitlines()[1:]
            now = {}
            for line in out:
                parts = line.strip().split(None, 2)
                if len(parts) >= 3:
                    pid = int(parts[0])
                    now[pid] = {"name": parts[1], "user": parts[2]}
            new = set(now) - set(prev)
            ended = set(prev) - set(now)
            for pid in new:
                rec = {"ts": utc_now(), "event": "NEW_PROC", "pid": pid, **now[pid]}
                print(rec); append_jsonl(jsonl, rec)
            for pid in ended:
                rec = {"ts": utc_now(), "event": "END_PROC", "pid": pid, **prev[pid]}
                print(rec); append_jsonl(jsonl, rec)
            prev = now
            time.sleep(2)
    except KeyboardInterrupt:
        print("audit stopped.")

# ------------- honeypot -------------

def honeypot_command(args):
    host = args.host; port = int(args.port); jsonl = args.jsonl
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port)); s.listen(10)
        print("honeypot listening on", f"{host}:{port}")
        while True:
            try:
                cli, addr = s.accept()
            except KeyboardInterrupt:
                print("stopped"); break
            with cli:
                cli.settimeout(2.0)
                try:
                    data = cli.recv(1024)
                    if data:
                        rec = {"ts": utc_now(), "peer": f"{addr[0]}:{addr[1]}", "first": data.splitlines()[0][:200].decode("latin1", "replace")}
                        print(rec); append_jsonl(jsonl, rec)
                    cli.sendall(b"221 BYE\\r\\n")
                except Exception as e:
                    append_jsonl(jsonl, {"ts": utc_now(), "event": "HONEY_ERROR", "error": str(e)})

# ------------- main -------------

def build_parser():
    p = argparse.ArgumentParser(description="Advanced safe lab toolkit (benign)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sa = sub.add_parser("simulate_advanced"); 
    sa.add_argument("--src", required=True); sa.add_argument("--dst", required=True); sa.add_argument("--threads", default=2); sa.add_argument("--max-files", default=None); sa.add_argument("--sandbox", default=None); sa.add_argument("--jsonl", default=None)
    sb = sub.add_parser("beacon_test"); sb.add_argument("--host", default="127.0.0.1"); sb.add_argument("--port", default=2222); sb.add_argument("--count", default=5); sb.add_argument("--interval", default=0.5); sb.add_argument("--jsonl", default=None)
    aa = sub.add_parser("audit"); aa.add_argument("--jsonl", default="audit_adv.jsonl")
    hh = sub.add_parser("honeypot"); hh.add_argument("--host", default="0.0.0.0"); hh.add_argument("--port", default=2222); hh.add_argument("--jsonl", default="honeypot_adv.jsonl")
    return p

def main():
    p = build_parser(); args = p.parse_args()
    if args.cmd == "simulate_advanced":
        simulate_advanced(args)
    elif args.cmd == "beacon_test":
        beacon_test(args)
    elif args.cmd == "audit":
        audit_command(args)
    elif args.cmd == "honeypot":
        honeypot_command(args)

if __name__ == "__main__":
    main()
