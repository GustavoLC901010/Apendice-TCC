#!/usr/bin/env python3
"""
advanced_lab_suite_v2.py — Highly Realistic but SAFE Security Lab Toolkit v2
=======================================================================
This toolkit increases "realism" while remaining strictly BENIGN and SAFE.
It is intended for defensive training and research in isolated lab environments (VMs).
DO NOT run on production systems or point at sensitive directories.

Key constraints (SAFETY):
- NEVER writes to system autostart locations (no /etc, no registry). Any "persistence"
  artifacts are confined to a user-specified sandbox directory.
- NEVER deletes or modifies original files; simulate by copying and encoding only.
- NEVER connects to external networks. Beaconing/C2 is written to local files or localhost only.
- NEVER attempts privilege escalation, exploit usage, or disabling of security tools.
- Use only in VMs or isolated environments you control.

Features added in v2:
- VM/analysis checks (reads DMI/cpuinfo for VM indicators; only logs findings).
- Simulated "persistence marker" inside sandbox (user-supplied) to illustrate persistence attempts.
- Encoded local "beacon log" to imitate C2 traffic without network exfiltration.
- More realistic obfuscation: hashed filenames, fake extensions (.jpg/.tmp/.dat), and map.json for reversion.
- Timing jitter, random sleeps, multithreaded copying for realistic I/O patterns.
- Final consolidated timeline/report (JSON) merging audit, simulate, honeypot, and beacon events.
- Strict safety guard: will refuse to run simulate/persistence unless a sandbox directory is provided.
"""

import argparse, base64, json, os, random, shutil, socket, sqlite3, string, sys, threading, time, hashlib
from datetime import datetime
from pathlib import Path
from queue import Queue

# ---------------- utilities ----------------

def utc_now():
    return datetime.utcnow().isoformat() + "Z"

def log_jsonl(path, obj):
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

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

# ---------------- VM / analysis checks ----------------

def vm_checks():
    findings = []
    # check /sys/class/dmi/id/product_name and bios_vendor if available
    for p in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/board_vendor"]:
        try:
            if os.path.exists(p):
                v = open(p, "r", errors="ignore").read().strip().lower()
                for marker in ["virtualbox", "vmware", "kvm", "qemu", "microsoft corporation", "bochs"]:
                    if marker in v:
                        findings.append(f"marker:{marker} in {p} -> {v[:100]}")
        except Exception:
            pass
    # check cpuinfo for hypervisor strings
    try:
        if os.path.exists("/proc/cpuinfo"):
            c = open("/proc/cpuinfo", "r", errors="ignore").read().lower()
            for marker in ["hypervisor", "vmware", "virtualbox", "kvm", "qemu"]:
                if marker in c:
                    findings.append(f"cpu_marker:{marker}")
    except Exception:
        pass
    # hostname heuristics
    hn = ""
    try:
        hn = os.uname().nodename.lower()
        for marker in ["vbox", "vm", "virtual", "testlab"]:
            if marker in hn:
                findings.append(f"hostname_marker:{hn}")
    except Exception:
        pass
    return findings

# ---------------- simulate (realistic but safe) ----------------

def obf_name_hash(relpath: str) -> str:
    # produce deterministic obfuscated name based on path and a salt
    salt = "labv2_salt_2025"
    h = hashlib.sha256((salt + relpath).encode("utf-8")).hexdigest()[:16]
    # pick fake extension
    ext = random.choice([".jpg", ".tmp", ".dat", ".png"])
    return h + ext

def worker_simulate(q: Queue, src_root: Path, dst_root: Path, jsonl: str, sandbox: Path, map_obj: dict, jitter: float):
    while True:
        item = q.get()
        if item is None:
            q.task_done(); break
        src = item
        rel = safe_rel(src_root, src)
        try:
            data = src.read_bytes()
            # encode content in base64 (NOT encryption)
            enc = base64.b64encode(data)
            obfn = obf_name_hash(rel)
            dest = dst_root / Path(rel).parent / obfn
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(enc)
            # record mapping for revertibility
            map_obj[str(dest.relative_to(dst_root))] = {"orig": rel, "obf": obfn, "size": len(data), "ts": utc_now()}
            rec = {"ts": utc_now(), "action": "COPY_OBF_HASH", "src": rel, "dst": str(dest.relative_to(dst_root))}
            print(rec); log_jsonl(jsonl, rec)
            # simulated persistence marker only inside sandbox path (explicit)
            if sandbox:
                marker = sandbox / "fake_autorun_marker.txt"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.write_text("PERSIST_MARKER:" + sha256_text(str(dest.relative_to(dst_root))) + " " + utc_now(), encoding="utf-8")
            # jitter
            if jitter and jitter > 0:
                time.sleep(random.random() * jitter)
        except Exception as e:
            log_jsonl(jsonl, {"ts": utc_now(), "action": "ERROR", "src": str(src), "error": str(e)})
        finally:
            q.task_done()

def simulate_realistic(args):
    src = Path(args.src).resolve()
    dst = Path(args.dst).resolve()
    jsonl = args.jsonl
    sandbox = Path(args.sandbox).resolve() if args.sandbox else None
    threads = max(1, int(args.threads))
    max_files = int(args.max_files) if args.max_files else None
    jitter = float(args.jitter)

    # Safety guard: require sandbox and require sandbox resides under dst to avoid arbitrary system writes
    if not sandbox:
        print("[simulate] ERROR: sandbox path required for realistic simulation. Provide --sandbox inside destination.")
        sys.exit(1)
    if not str(sandbox).startswith(str(dst)) and not sandbox.exists():
        print("[simulate] ERROR: sandbox must be inside destination or pre-existing. Refusing to run to protect system.")
        sys.exit(1)
    if not src.is_dir():
        print("[simulate] src must be directory"); sys.exit(1)
    dst.mkdir(parents=True, exist_ok=True)

    files = [p for p in src.rglob("*") if p.is_file()]
    if max_files:
        files = files[:max_files]
    q = Queue()
    for f in files:
        q.put(f)

    manager_map = {}
    workers = []
    for _ in range(threads):
        t = threading.Thread(target=worker_simulate, args=(q, src, dst, jsonl, sandbox, manager_map, jitter), daemon=True)
        t.start(); workers.append(t)

    q.join()
    for _ in workers: q.put(None)
    for t in workers: t.join()

    # write map.json to dst for reversion
    map_path = dst / "map.json"
    map_path.write_text(json.dumps(manager_map, ensure_ascii=False, indent=2), encoding="utf-8")
    log_jsonl(jsonl, {"ts": utc_now(), "action": "SIM_COMPLETE", "total": len(manager_map)})
    print("[simulate] complete. map.json written. total:", len(manager_map))

# ---------------- beacon (local-only encoded C2 log) ----------------

def beacon_local_log(beacon_path: Path, count: int, interval: float):
    beacon_path.parent.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        payload = {"ts": utc_now(), "id": i, "rand": random.randint(0, 999999), "note": "local_beacon"}
        b = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        # append to local-only file
        with beacon_path.open("a", encoding="utf-8") as f:
            f.write(b + "\\n")
        print({"ts": utc_now(), "event": "BEACON_WRITE", "path": str(beacon_path), "id": i})
        time.sleep(interval)

# ---------------- audit (enhanced) ----------------

def audit_loop(jsonl):
    prev = {}
    vm_findings = vm_checks()
    if vm_findings:
        log_jsonl(jsonl, {"ts": utc_now(), "event": "VM_INDICATORS", "findings": vm_findings})
        print("[audit] VM/analysis markers found:", vm_findings)
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
                print(rec); log_jsonl(jsonl, rec)
            for pid in ended:
                rec = {"ts": utc_now(), "event": "END_PROC", "pid": pid, **prev[pid]}
                print(rec); log_jsonl(jsonl, rec)
            prev = now
            time.sleep(2)
    except KeyboardInterrupt:
        print("[audit] stopped by user.")

# ---------------- honeypot (unchanged but logs JSON) ----------------

def honeypot(jsonl, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port)); s.listen(20)
        print("[honeypot] listening on", f"{host}:{port}")
        while True:
            try:
                cli, addr = s.accept()
            except KeyboardInterrupt:
                print("[honeypot] stopped"); break
            with cli:
                cli.settimeout(3.0)
                try:
                    data = cli.recv(2048)
                    if data:
                        first = data.splitlines()[0][:500].decode("latin1", "replace")
                        rec = {"ts": utc_now(), "peer": f"{addr[0]}:{addr[1]}", "first": first}
                        print(rec); log_jsonl(jsonl, rec)
                    cli.sendall(b"221 BYE\\r\\n")
                except Exception as e:
                    log_jsonl(jsonl, {"ts": utc_now(), "event": "HONEY_ERR", "err": str(e)})

# ---------------- report (merge logs into timeline) ----------------

def build_report(dst, logs, outpath):
    timeline = []
    for p in logs:
        if not p or not Path(p).exists(): continue
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    timeline.append(json.loads(line))
                except Exception:
                    pass
    # sort by timestamp if present
    timeline.sort(key=lambda x: x.get("ts",""))
    out = {"ts": utc_now(), "report_of": [str(p) for p in logs], "events": timeline, "summary": {"events": len(timeline)}}
    outpath.parent.mkdir(parents=True, exist_ok=True)
    outpath.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print("[report] written to", outpath)

# ---------------- main / CLI ----------------

def build_parser():
    p = argparse.ArgumentParser(description="Advanced Lab Suite v2 (safe realistic simulation)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sa = sub.add_parser("simulate_realistic")
    sa.add_argument("--src", required=True); sa.add_argument("--dst", required=True); sa.add_argument("--threads", default=4); sa.add_argument("--max-files", default=None); sa.add_argument("--jitter", default=0.2); sa.add_argument("--sandbox", required=True); sa.add_argument("--jsonl", default="sim_real.jsonl")
    sb = sub.add_parser("beacon_local"); sb.add_argument("--beacon", default="beacon_local.log"); sb.add_argument("--count", default=10); sb.add_argument("--interval", default=0.3)
    aa = sub.add_parser("audit"); aa.add_argument("--jsonl", default="audit_real.jsonl")
    hh = sub.add_parser("honeypot"); hh.add_argument("--host", default="0.0.0.0"); hh.add_argument("--port", default=2222); hh.add_argument("--jsonl", default="honeypot_real.jsonl")
    rp = sub.add_parser("report"); rp.add_argument("--logs", nargs="+", required=True); rp.add_argument("--out", default="report.json")
    return p

def main():
    p = build_parser(); args = p.parse_args()
    if args.cmd == "simulate_realistic":
        simulate_realistic(args)
    elif args.cmd == "beacon_local":
        beacon_local_log(Path(args.beacon), int(args.count), float(args.interval))
    elif args.cmd == "audit":
        audit_loop(args.jsonl)
    elif args.cmd == "honeypot":
        honeypot(args.jsonl, args.host, int(args.port))
    elif args.cmd == "report":
        build_report(Path("."), args.logs, Path(args.out))

if __name__ == "__main__":
    main()
