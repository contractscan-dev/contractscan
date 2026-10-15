"""Tests for SEO pages, llms.txt, newsletter, feedback, HEAD support and CSP."""
import json, re, os, sys, subprocess, pathlib
sys.path.insert(0, os.path.dirname(__file__))
from test_contractscan import env, ROOT  # noqa: F401  (fixture: temp DB + mocked RPC/scan)
import payments, pages

def test_pages_seo(env):
    _, c, _ = env
    for path in ["/", "/blog"]:
        r = c.get(path); t = r.text; assert r.status_code == 200
        assert t.count("<title>") == 1 and 'name="description"' in t and f'rel="canonical" href="{pages.BASE}{path}"' in t
        assert 'og:image" content="https://contract-scan.dev/static/og-image.png' in t and 'twitter:card' in t and "https://x.com/ContractScanDev" in t
        assert "<main>" in t and "not an audit" in t.lower() and 'action="/subscribe"' in t
    titles = {re.search(r"<title>(.*?)</title>", c.get(p).text).group(1) for p in ["/", "/blog"]}
    assert len(titles) == 2

def test_jsonld(env):
    _, c, _ = env; t = c.get("/").text
    lds = [json.loads(m) for m in re.findall(r'<script type="application/ld\+json">(.*?)</script>', t, re.S)]
    types = {x["@type"] for x in lds}; assert {"SoftwareApplication", "FAQPage"} <= types
    faq = next(x for x in lds if x["@type"] == "FAQPage"); assert len(faq["mainEntity"]) >= 5
    assert 'id="faq"' in t and "<details>" in t

def test_blog_published_post_and_404(env):
    _, c, _ = env
    assert "/blog/ai-written-solidity-24-contracts-scanned" in c.get("/blog").text
    r = c.get("/blog/ai-written-solidity-24-contracts-scanned")
    assert r.status_code == 200 and "By ContractScan Team" in r.text and 'rel="canonical" href="https://contract-scan.dev/blog/ai-written-solidity-24-contracts-scanned"' in r.text
    assert "github.com/contractscan-dev/ai-solidity-experiment-2026-10" in r.text
    assert "/blog/ai-written-solidity-24-contracts-scanned" in c.get("/sitemap.xml").text
    assert c.get("/blog/ai-solidity-common-vulnerabilities").status_code == 404   # drafts are not published
    assert c.get("/blog/../etc/passwd").status_code == 404

def test_blog_post_render(env, tmp_path, monkeypatch):
    _, c, _ = env
    d = tmp_path / "content" / "blog"; d.mkdir(parents=True)
    (d / "posts.json").write_text(json.dumps([{"slug": "hello-world", "title": "Hello <World>", "description": "Desc", "date": "2026-10-15"}]))
    (d / "hello-world.html").write_text("<p>Body text</p>")
    monkeypatch.setattr(pages, "HERE", str(tmp_path))
    t = c.get("/blog/hello-world").text
    assert "Hello &lt;World&gt;" in t and "<p>Body text</p>" in t and '"@type": "Article"' in t and "not an audit" in t
    assert "/blog/hello-world" in c.get("/sitemap.xml").text and "hello-world" in c.get("/blog").text

def test_sitemap_robots_llms_docs(env):
    _, c, _ = env
    sm = c.get("/sitemap.xml"); assert sm.headers["content-type"].startswith("application/xml") and "<loc>https://contract-scan.dev/</loc>" in sm.text
    rb = c.get("/robots.txt").text; assert "Sitemap: https://contract-scan.dev/sitemap.xml" in rb and "Disallow: /api/" in rb
    for p in ["/llms.txt", "/llms-full.txt", "/docs"]:
        r = c.get(p); assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    l = c.get("/llms.txt").text; assert l.startswith("# ContractScan") and "NOT an audit" in l and "scan_contract" in l and "POST /api/scan" in l
    assert "Known limitations" in c.get("/llms-full.txt").text and "POST /api/pay/claim" in c.get("/docs").text

def test_head_supported(env):
    _, c, _ = env
    for p in ["/", "/blog", "/docs", "/llms.txt", "/sitemap.xml", "/robots.txt", "/favicon.ico"]:
        assert c.head(p).status_code == 200, p

def test_csp_strict(env):
    _, c, _ = env; csp = c.get("/").headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp and "script-src 'self'" in csp
    t = c.get("/").text
    assert not re.search(r"<script(?![^>]*(src=|application/ld\+json))", t)   # no inline executable scripts
    assert not re.search(r"\sstyle=", t) and not re.search(r"\son[a-z]+=", t)  # no inline styles/handlers

def test_newsletter(env):
    _, c, _ = env
    r = c.post("/subscribe", data={"email": "Alice@Example.com", "source": "home"}); assert r.status_code == 200 and "on the list" in r.text
    c.post("/subscribe", data={"email": "alice@example.com", "source": "blog"})               # duplicate ignored
    assert c.post("/subscribe", data={"email": "not-an-email"}).status_code == 400
    assert c.post("/subscribe", data={"email": "bot@spam.com", "website": "http://spam"}).status_code == 200  # honeypot
    with payments.db() as d: rows = d.execute("select email, source, confirmed from subscribers").fetchall()
    assert rows == [("alice@example.com", "home", 0)]
    assert c.post("/subscribe", json={"email": "b@example.com"}).json()["ok"]

def test_newsletter_rate_limit(env):
    _, c, _ = env
    codes = [c.post("/subscribe", data={"email": f"u{i}@example.com"}).status_code for i in range(7)]
    assert codes[:5] == [200] * 5 and codes[5] == 429

def test_export_script(env, tmp_path):
    _, c, _ = env; c.post("/subscribe", data={"email": "x@example.com", "source": "home"})
    out = tmp_path / "s.csv"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/export_subscribers.py"), "--db", payments.DB, "--out", str(out)], capture_output=True, text=True, env={**os.environ, "CS_ALLOW_NONROOT_EXPORT": "1"})
    assert r.returncode == 0 and "x@example.com" in out.read_text() and oct(out.stat().st_mode)[-3:] == "600"
    r = subprocess.run([sys.executable, str(ROOT / "scripts/export_subscribers.py"), "--db", payments.DB], capture_output=True, text=True, env={k: v for k, v in os.environ.items() if k != "CS_ALLOW_NONROOT_EXPORT"})
    assert (os.geteuid() == 0) or r.returncode != 0

def test_feedback(env):
    _, c, _ = env
    sid = c.post("/api/scan", json={"source": "x"}).json()["scan_id"]
    assert c.post("/api/feedback", json={"scan_id": sid, "useful": False, "comment": "<script>x</script> missed a bug"}).json()["ok"]
    assert c.post("/api/feedback", json={"scan_id": "zz'; drop", "useful": True}).json()["ok"]
    assert c.post("/api/feedback", json={"useful": True, "comment": "a" * 1001}).status_code == 422
    with payments.db() as d: rows = d.execute("select scan_id, useful, comment, verdict from feedback order by ts").fetchall()
    assert rows[0] == (sid, 0, "<script>x</script> missed a bug", "fix_first") and rows[1][0] is None
    js = (ROOT / "static/app.js").read_text(); assert "/api/feedback" in js and "innerHTML" not in js
