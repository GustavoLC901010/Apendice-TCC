
#!/usr/bin/env python3
"""
lab_suite.py — Safe Security Lab Toolkit (All-in-One)
====================================================
Subcommands (all SAFE & BENIGN):
  audit      -> Monitor creation/termination of processes. Logs JSONL and (optionally) SQLite.
  simulate   -> "Ransomware-like" *visual* simulation (copies files to a separate folder and renames with .locked).
  honeypot   -> Minimal TCP listener that logs inbound connections and first line received.

IMPORTANT SAFETY NOTES:
- This toolkit is strictly educational. It does NOT encrypt, delete, exfiltrate, or persist.
- The simulate command ONLY copies from a source directory you specify into a separate destination you own.
- Use in a lab / VM you control. Never point it at directories with real or sensitive data.

Dependencies:
- Standard library. Optional: 'psutil' for richer process auditing (falls back to limited mode if unavailable).

Usage examples:
  python lab_suite.py audit --interval 2 --jsonl audit.jsonl --sqlite audit.db
  python lab_suite.py simulate --src /tmp/lab_src --dst /tmp/lab_out --max-files 100
  python lab_suite.py honeypot --host 0.0.0.0 --port 2222 --log honeypot.log --sqlite lab.db
"""

import argparse
import json
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Iterable, Tuple, Optional

# --------------------------- Utilities ---------------------------

def utc_now() -> str:
    return datetime.utcnow().isoformat() + "Z"

def ensure_sqlite(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            ts TEXT,
            event TEXT,
            pid INTEGER,
            name TEXT,
            user TEXT,
            cmd TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS simulation_events (
            ts TEXT,
            action TEXT,
            src TEXT,
            dst TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS honeypot_events (
            ts TEXT,
            peer TEXT,
            first_line TEXT
        )
    """)
    conn.commit()

def append_jsonl(path: Optional[Path], record: Dict[str, Any]):
    if path is None:
        return
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def safe_rel_path(root: Path, child: Path) -> Path:
    # Return child's path relative to root if possible, else full
    try:
        return child.relative_to(root)
    except Exception:
        return child

# --------------------------- AUDIT ---------------------------

def have_psutil() -> bool:
    try:
        import psutil  # type: ignore
        return True
    except Exception:
        return False

def proc_snapshot_psutil() -> Dict[int, Dict[str, Any]]:
    import psutil  # type: ignore
    snap = {}
    for p in psutil.process_iter(['name', 'username', 'cmdline', 'cpu_percent', 'memory_info']):
        info = p.info
        snap[p.pid] = {
            "name": info.get("name"),
            "user": info.get("username"),
            "cmd": " ".join(info.get("cmdline") or []) if info.get("cmdline") else "",
            "cpu": info.get("cpu_percent"),
            "rss": getattr(info.get("memory_info"), "rss", None)
        }
    return snap

def proc_snapshot_fallback() -> Dict[int, Dict[str, Any]]:
    # Unix-only fallback using `ps`. Limited fields, but avoids extra deps.
    try:
        out = subprocess.check_output(["ps", "-eo", "pid,comm,user"], text=True, stderr=subprocess.DEVNULL)
        lines = out.strip().splitlines()[1:]
        snap = {}
        for line in lines:
            parts = line.strip().split(None, 2)
            if len(parts) >= 3:
                pid = int(parts[0])
                snap[pid] = {"name": parts[1], "user": parts[2], "cmd": "", "cpu": None, "rss": None}
        return snap
    except Exception:
        # Last resort: empty snapshot
        return {}

def audit_command(args: argparse.Namespace):
    interval = float(args.interval)
    jsonl_path = Path(args.jsonl) if args.jsonl else None
    sqlite_path = Path(args.sqlite) if args.sqlite else None

    conn = None
    if sqlite_path:
        conn = sqlite3.connect(sqlite_path)
        ensure_sqlite(conn)

    use_psutil = have_psutil()
    print(f"[audit] starting (interval={interval}s) psutil={'yes' if use_psutil else 'no-fallback'}")
    snapshot = proc_snapshot_psutil if use_psutil else proc_snapshot_fallback

    prev = snapshot()
    print(f"[audit] initial processes: {len(prev)}")
    try:
        while True:
            time.sleep(interval)
            now = snapshot()

            new_pids = set(now) - set(prev)
            end_pids = set(prev) - set(now)

            for pid in new_pids:
                rec = {
                    "ts": utc_now(),
                    "event": "NEW",
                    "pid": pid,
                    **now[pid],
                }
                print(f"{rec['ts']} [NEW] pid={pid} name={rec['name']} user={rec['user']} cmd='{rec['cmd']}' cpu={rec.get('cpu')} rss={rec.get('rss')}")
                append_jsonl(jsonl_path, rec)
                if conn:
                    conn.execute(
                        "INSERT INTO process_events (ts, event, pid, name, user, cmd) VALUES (?, ?, ?, ?, ?, ?)",
                        (rec["ts"], rec["event"], rec["pid"], rec["name"], rec["user"], rec["cmd"]),
                    )
                    conn.commit()

            for pid in end_pids:
                info = prev.get(pid, {"name": None, "user": None, "cmd": ""})
                rec = {
                    "ts": utc_now(),
                    "event": "END",
                    "pid": pid,
                    "name": info.get("name"),
                    "user": info.get("user"),
                    "cmd": info.get("cmd"),
                }
                print(f"{rec['ts']} [END] pid={pid} name={rec['name']} user={rec['user']} cmd='{rec['cmd']}'")
                append_jsonl(jsonl_path, rec)
                if conn:
                    conn.execute(
                        "INSERT INTO process_events (ts, event, pid, name, user, cmd) VALUES (?, ?, ?, ?, ?, ?)",
                        (rec["ts"], rec["event"], rec["pid"], rec["name"], rec["user"], rec["cmd"]),
                    )
                    conn.commit()

            prev = now
    except KeyboardInterrupt:
        print("[audit] stopped.")
    finally:
        if conn:
            conn.close()

# --------------------------- SIMULATE ---------------------------

def list_files_recursive(root: Path):
    for p in root.rglob("*"):
        if p.is_file():
            yield p

def simulate_command(args: argparse.Namespace):
    src = Path(args.src).resolve()
    dst = Path(args.dst).resolve()
    max_files = int(args.max_files) if args.max_files else None
    random_delay = float(args.random_delay)
    jsonl_path = Path(args.jsonl) if args.jsonl else None
    sqlite_path = Path(args.sqlite) if args.sqlite else None

    if not src.is_dir():
        print(f"[simulate] invalid source directory: {src}")
        sys.exit(1)
    if dst.exists() and not dst.is_dir():
        print(f"[simulate] destination exists and is not a directory: {dst}")
        sys.exit(1)
    dst.mkdir(parents=True, exist_ok=True)

    conn = None
    if sqlite_path:
        conn = sqlite3.connect(sqlite_path)
        ensure_sqlite(conn)

    files = list(list_files_recursive(src))
    total = len(files) if max_files is None else min(len(files), max_files)
    print(f"[simulate] copying {total} files from {src} -> {dst} ( originals remain untouched )")

    count = 0
    for f in files:
        if max_files is not None and count >= max_files:
            break
        rel = safe_rel_path(src, f)
        new_name = f"{f.stem}.locked{f.suffix}"
        dest = dst / rel.parent / new_name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)
        count += 1
        rec = {
            "ts": utc_now(),
            "action": "COPY_LOCKED",
            "src": str(rel),
            "dst": str(dest.relative_to(dst)),
        }
        print(f"{rec['ts']} [COPY_LOCKED] {rec['src']} -> {rec['dst']} ({count}/{total})")
        append_jsonl(jsonl_path, rec)
        if conn:
            conn.execute(
                "INSERT INTO simulation_events (ts, action, src, dst) VALUES (?, ?, ?, ?)",
                (rec["ts"], rec["action"], rec["src"], rec["dst"]),
            )
            conn.commit()

        if random_delay > 0:
            # add small random jitter up to the specified maximum delay
            import random, time
            time.sleep(random.random() * random_delay)

    note = dst / "README_RESTORE.txt"
    note.write_text(
        "=== SAFE SIMULATION ===\n"
        "Your originals are untouched. These files are COPIES with '.locked' appended.\n"
        "This is a benign simulation for educational purposes.\n",
        encoding="utf-8"
    )
    print("[simulate] created README_RESTORE.txt in destination.")
    if conn:
        conn.close()
    print("[simulate] done.")

# --------------------------- HONEYPOT ---------------------------

def honeypot_command(args: argparse.Namespace):
    host = args.host
    port = int(args.port)
    log_path = Path(args.log) if args.log else None
    sqlite_path = Path(args.sqlite) if args.sqlite else None

    conn = None
    if sqlite_path:
        conn = sqlite3.connect(sqlite_path)
        ensure_sqlite(conn)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(50)
        print(f"[honeypot] listening on {host}:{port}")
        while True:
            try:
                client, addr = s.accept()
            except KeyboardInterrupt:
                print("[honeypot] stopped.")
                break
            except Exception as e:
                print(f"[honeypot] accept error: {e}")
                continue
            with client:
                client.settimeout(3.0)
                peer = f"{addr[0]}:{addr[1]}"
                ts = utc_now()
                first_line = b""
                try:
                    client.sendall(b"220 Welcome (SAFE honeypot)\r\n")
                    data = client.recv(1024)
                    if data:
                        first_line = data.splitlines()[0][:200]
                    client.sendall(b"221 Bye\r\n")
                except Exception:
                    pass

                decoded = first_line.decode("latin1", "replace")
                line = f"{ts} {peer} first_line={decoded}"
                print(line)
                if log_path:
                    with log_path.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
                if conn:
                    conn.execute(
                        "INSERT INTO honeypot_events (ts, peer, first_line) VALUES (?, ?, ?)",
                        (ts, peer, decoded),
                    )
                    conn.commit()
    if conn:
        conn.close()

# --------------------------- Main ---------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Safe Security Lab Toolkit (all-in-one)")
    sub = p.add_subparsers(dest="cmd", required=True)

    # audit
    pa = sub.add_parser("audit", help="Monitor process creation/termination")
    pa.add_argument("--interval", type=float, default=2.0, help="Polling interval seconds (default: 2.0)")
    pa.add_argument("--jsonl", type=str, default=None, help="Path to JSONL log")
    pa.add_argument("--sqlite", type=str, default=None, help="Path to SQLite DB file")
    pa.set_defaults(func=audit_command)

    # simulate
    ps = sub.add_parser("simulate", help="Safe ransomware-like simulation (copies & renames)")
    ps.add_argument("--src", type=str, required=True, help="Source directory (read-only)")
    ps.add_argument("--dst", type=str, required=True, help="Destination directory for simulated output")
    ps.add_argument("--max-files", type=int, default=None, help="Max files to process (default: all)")
    ps.add_argument("--random-delay", type=float, default=0.15, help="Max random delay between copies in seconds (default: 0.15)")
    ps.add_argument("--jsonl", type=str, default=None, help="Path to JSONL log")
    ps.add_argument("--sqlite", type=str, default=None, help="Path to SQLite DB file")
    ps.set_defaults(func=simulate_command)

    # honeypot
    ph = sub.add_parser("honeypot", help="Simple TCP listener that logs inbound connections")
    ph.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind (default: 0.0.0.0)")
    ph.add_argument("--port", type=int, default=2222, help="Port to bind (default: 2222)")
    ph.add_argument("--log", type=str, default=None, help="Path to write plain-text log")
    ph.add_argument("--sqlite", type=str, default=None, help="Path to SQLite DB file")
    ph.set_defaults(func=honeypot_command)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
