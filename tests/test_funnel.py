"""Funnel analytics: events recorded end-to-end, nothing sensitive stored, never breaks the product."""
import os, sys, sqlite3
sys.path.insert(0, os.path.dirname(__file__))
from test_contractscan import env, H, PAYER, claim  # noqa: F401
import payments

def rows():
    with payments.db() as c: return c.execute("select event, surface, scan_id, verdict, detail from funnel").fetchall()

def test_funnel_scan_view_pay_paid(env):
    ch, c, _ = env
    r = c.post("/api/scan", json={"source": "contract SECRET_SOURCE_MARKER {}"}, headers={"x-cs-ui": "1"}).json()
    sid = r["scan_id"]
    assert c.post("/api/event", json={"event": "result_viewed", "scan_id": sid}).json()["ok"]
    assert c.post("/api/event", json={"event": "pay_clicked", "scan_id": sid, "detail": "wallet"}).json()["ok"]
    ch.add(H(77), PAYER, 3_000_000); claim(c, H(77)); claim(c, H(77))      # re-show must not double count
    ev = [x[0] for x in rows()]
    assert ev.count("scan_started") == 1 and ev.count("scan_completed") == 1 and ev.count("result_viewed") == 1
    assert ev.count("pay_clicked") == 1 and ev.count("paid") == 1
    assert ("scan_completed", "web", sid, "fix_first", "free") in rows()
    assert any(x[0] == "paid" and x[4] == "credits:1" for x in rows())

def test_funnel_stores_nothing_sensitive(env):
    ch, c, _ = env
    c.post("/api/scan", json={"source": "contract SECRET_SOURCE_MARKER {}"})
    ch.add(H(78), PAYER, 3_000_000); code = claim(c, H(78)).json()["code"]
    with payments.db() as db: dump = "\n".join(map(str, db.execute("select * from funnel").fetchall()))
    for s in ("SECRET_SOURCE_MARKER", "testclient", PAYER[2:], H(78)[2:], code): assert s.lower() not in dump.lower()

def test_event_endpoint_rejects_unknown_and_sanitizes(env):
    _, c, _ = env
    assert c.post("/api/event", json={"event": "paid"}).status_code == 400           # server-only event
    assert c.post("/api/event", json={"event": "scan_started"}).status_code == 400
    assert c.post("/api/event", json={"event": "pay_clicked", "scan_id": "<script>", "detail": "evil<x>"}).json()["ok"]
    assert rows()[-1] == ("pay_clicked", "web", None, None, None)

def test_failed_scan_logged_and_api_surface(env):
    _, c, _ = env
    c.post("/api/scan", json={"source": "BROKEN"})
    assert [x[:2] for x in rows()] == [("scan_started", "api"), ("scan_failed", "api")]

def test_funnel_never_breaks_scan(env, monkeypatch):
    _, c, _ = env
    monkeypatch.setattr(payments, "db", lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk full")))
    assert payments.log_event("scan_started") is False
