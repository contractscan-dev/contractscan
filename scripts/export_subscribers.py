#!/usr/bin/env python3
"""Admin-only: export newsletter subscribers as CSV to stdout (or --out FILE, created 0600).
Run on the server as root:  /opt/contractscan/venv/bin/python /opt/contractscan/app/scripts/export_subscribers.py [--out subs.csv]"""
import argparse, csv, os, sqlite3, sys, datetime
ap = argparse.ArgumentParser(); ap.add_argument("--db", default=os.environ.get("CS_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "contractscan.db")))
ap.add_argument("--out"); ap.add_argument("--feedback", action="store_true", help="export feedback instead of subscribers")
a = ap.parse_args()
if hasattr(os, "geteuid") and os.geteuid() != 0 and not os.environ.get("CS_ALLOW_NONROOT_EXPORT"): sys.exit("Refusing: run as root (admin only).")
c = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
if a.feedback: hdr, rows = ["time_utc", "scan_id", "useful", "verdict", "comment"], [(datetime.datetime.utcfromtimestamp(t).isoformat(), s, u, v, cm) for t, s, u, cm, v in c.execute("select ts, scan_id, useful, comment, verdict from feedback order by ts")]
else: hdr, rows = ["email", "signup_utc", "source", "confirmed"], [(e, datetime.datetime.utcfromtimestamp(t).isoformat(), s, cf) for e, t, s, cf in c.execute("select email, ts, source, confirmed from subscribers order by ts")]
if a.out:
    fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); f = os.fdopen(fd, "w", newline="")
else: f = sys.stdout
w = csv.writer(f); w.writerow(hdr); w.writerows(rows)
if a.out: f.close(); print(f"wrote {len(rows)} rows to {a.out}", file=sys.stderr)
