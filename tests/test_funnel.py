"""Funnel analytics: events recorded end-to-end, nothing sensitive stored, never breaks the product."""
import os, sys, sqlite3
sys.path.insert(0, os.path.dirname(__file__))
from test_contractscan import env, H, PAYER, claim  # noqa: F401
import payments
UA = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36"}
UI = {**UA, "x-cs-ui": "1"}

def rows():
    with payments.db() as c: return c.execute("select event, surface, scan_id, verdict, detail from funnel").fetchall()

def test_funnel_scan_view_pay_paid(env):
    ch, c, _ = env
    r = c.post("/api/scan", json={"source": "contract SECRET_SOURCE_MARKER {}"}, headers=UI).json()
    sid = r["scan_id"]
    assert c.post("/api/event", json={"event": "result_viewed", "scan_id": sid}, headers=UA).json()["logged"]
    assert c.post("/api/event", json={"event": "pay_clicked", "scan_id": sid, "detail": "wallet"}, headers=UA).json()["logged"]
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
    r = c.post("/api/event", json={"event": "pay_clicked", "scan_id": "<script>", "detail": "evil<x>"}, headers=UA).json()
    assert r["ok"] and not r["logged"] and not [x for x in rows() if x[0] == "pay_clicked"]

def test_failed_scan_logged_and_api_surface(env):
    _, c, _ = env
    c.post("/api/scan", json={"source": "BROKEN"})
    assert [x[:2] for x in rows()] == [("scan_started", "api"), ("scan_failed", "api")]

def test_funnel_never_breaks_scan(env, monkeypatch):
    _, c, _ = env
    monkeypatch.setattr(payments, "db", lambda: (_ for _ in ()).throw(sqlite3.OperationalError("disk full")))
    assert payments.log_event("scan_started") is False

def test_client_events_need_real_scan_same_client_once(env):
    _, c, _ = env
    sid = c.post("/api/scan", json={"source": "contract A {}"}, headers=UI).json()["scan_id"]
    ev = lambda h, e="pay_clicked", s=sid: c.post("/api/event", json={"event": e, "scan_id": s, "detail": "wallet"}, headers=h).json()
    assert not ev(UA, s="0123456789abcdef")["logged"]                     # never issued
    assert not ev({"user-agent": UA["user-agent"].replace("129", "130")})["logged"]   # different client
    assert ev(UA)["logged"] and not ev(UA)["logged"]                        # dedupe per scan_id
    assert ev(UA, "result_viewed")["logged"]
    with payments.db() as db: db.execute("update scan_client set ts=ts-?", (payments.CLIENT_EVENT_TTL + 5,))
    sid2 = c.post("/api/scan", json={"source": "contract B {}"}, headers=UI).json()["scan_id"]
    with payments.db() as db: db.execute("update scan_client set ts=ts-? where scan_id=?", (payments.CLIENT_EVENT_TTL + 5, sid2))
    assert not ev(UA, s=sid2)["logged"]                                     # stale
    with payments.db() as db: assert not db.execute("select * from scan_client where ch like '%127.0.0.1%' or ch like '%Mozilla%'").fetchall()

def test_bot_ua_ignored_and_rate_limit(env):
    _, c, _ = env
    sid = c.post("/api/scan", json={"source": "contract A {}"}, headers=UI).json()["scan_id"]
    for ua in ("", "curl/8.4", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Mozilla/5.0 HeadlessChrome/129.0 Safari/537.36"):
        assert not c.post("/api/event", json={"event": "pay_clicked", "scan_id": sid}, headers={"user-agent": ua}).json()["logged"]
    codes = [c.post("/api/event", json={"event": "pay_clicked", "scan_id": sid}, headers=UA).status_code for _ in range(30)]
    assert 429 in codes and codes.count(200) <= 20

def test_bot_migration_flags_not_deletes(tmp_path, monkeypatch):
    dbp = str(tmp_path / "old.db"); con = sqlite3.connect(dbp)
    con.executescript("create table funnel(ts int, day text, event text, surface text, scan_id text, verdict text, detail text);"
                      "create table scans(scan_id text primary key, ts int, verdict text, tier text);"
                      "insert into scans values('aaaaaaaaaaaaaaaa',1,'x','free');"
                      "insert into funnel values(1,'d','pay_clicked','web',null,null,'wallet');"
                      "insert into funnel values(1,'d','result_viewed','web','aaaaaaaaaaaaaaaa',null,null);"
                      "insert into funnel values(1,'d','scan_started','web','aaaaaaaaaaaaaaaa',null,null);"); con.commit(); con.close()
    monkeypatch.setattr(payments, "DB", dbp)
    with payments.db() as c: got = c.execute("select event, bot from funnel order by rowid").fetchall()
    assert got == [("pay_clicked", 1), ("result_viewed", 0), ("scan_started", 0)]
    assert {r["event"]: r["n"] for r in payments.funnel_summary(days=100000)}.get("pay_clicked") is None
