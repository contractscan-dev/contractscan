"""Server-rendered marketing pages: home, blog, docs, llms.txt, sitemap, robots. No JS needed to read any page."""
import html, json, os, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("CS_BASE_URL", "https://contract-scan.dev").rstrip("/")
X_URL, X_HANDLE = "https://x.com/ContractScanDev", "@ContractScanDev"
GITHUB_URL = "https://github.com/contractscan-dev/contractscan"
DATA_URL = "https://github.com/contractscan-dev/ai-solidity-experiment-2026-10"
E = html.escape
DESC = "Paste AI-written Solidity and get a plain-language deploy verdict in seconds: Slither + Aderyn static analysis, rug-pull pattern checks, and AI explanations. Not an audit."

def posts():
    try: meta = json.load(open(os.path.join(HERE, "content/blog/posts.json")))
    except Exception: meta = []
    out = []
    for p in meta:
        f = os.path.join(HERE, "content/blog", os.path.basename(p["slug"]) + ".html")
        if os.path.exists(f): out.append({**p, "body": open(f, encoding="utf-8").read()})
    return sorted(out, key=lambda p: p["date"], reverse=True)

def newsletter_form(source):
    return f'''<section class="card" aria-labelledby="nl-{E(source)}"><h2 id="nl-{E(source)}">Get new articles and product updates</h2>
<form method="post" action="/subscribe"><label for="em-{E(source)}">Email</label> <input id="em-{E(source)}" type="email" name="email" required maxlength="254" autocomplete="email">
<input type="hidden" name="source" value="{E(source)}"><div class="hp" aria-hidden="true"><label>Website <input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>
<button type="submit">Subscribe</button></form>
<p class="mut"><small>Privacy: we store only your email, the signup time and the page you signed up from. No tracking, never sold or shared. Unsubscribe any time by emailing support@contract-scan.dev.</small></p></section>'''

def layout(title, desc, path, body, jsonld=None, og_type="website", extra_head=""):
    url = BASE + path
    ld = "".join(f'<script type="application/ld+json">{json.dumps(j, ensure_ascii=False).replace("</", "<\\/")}</script>' for j in (jsonld or []))
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{E(title)}</title><meta name="description" content="{E(desc)}"><link rel="canonical" href="{E(url)}">
<meta property="og:type" content="{og_type}"><meta property="og:site_name" content="ContractScan"><meta property="og:title" content="{E(title)}"><meta property="og:description" content="{E(desc)}"><meta property="og:url" content="{E(url)}">
<meta property="og:image" content="{BASE}/static/og-image.png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image"><meta name="twitter:site" content="{X_HANDLE}"><meta name="twitter:title" content="{E(title)}"><meta name="twitter:description" content="{E(desc)}"><meta name="twitter:image" content="{BASE}/static/og-image.png">
<link rel="icon" href="/favicon.ico" sizes="any"><link rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32.png"><link rel="apple-touch-icon" href="/static/apple-touch-icon.png">
<link rel="alternate" type="text/plain" title="llms.txt" href="/llms.txt"><link rel="stylesheet" href="/static/site.css">{extra_head}{ld}</head><body>
<header><a class="brand" href="/">Contract<span>Scan</span></a><nav aria-label="Main"><a href="/">Scan</a><a href="/blog">Blog</a><a href="/docs">API docs</a><a href="/#faq">FAQ</a></nav></header>
<main>{body}</main>
<footer><p>ContractScan is automated static analysis, <strong>not an audit</strong>. Results can miss bugs and contain false positives.</p>
<p><a href="{X_URL}" rel="me noopener">X {X_HANDLE}</a> · <a href="{GITHUB_URL}" rel="noopener">GitHub</a> · <a href="/blog">Blog</a> · <a href="/docs">API docs</a> · <a href="/llms.txt">llms.txt</a> · support@contract-scan.dev</p></footer></body></html>'''

FAQ = [
 ("Is ContractScan an audit?", "No. ContractScan runs automated static analysis (Slither and Aderyn) plus simple rug-pull pattern checks, and uses AI only to explain the findings in plain language. It can miss bugs and report false positives. For contracts that will hold real value, get a professional audit."),
 ("What does ContractScan check?", "Common Solidity vulnerabilities detected by Slither and Aderyn (for example reentrancy, unchecked calls, dangerous tx.origin use, missing access control) and rug-like patterns such as owner minting, blacklists, owner-changeable fees, pausing, trading switches, owner withdraw functions and upgradeability."),
 ("Is my contract code executed?", "No. Your code is only compiled and statically analysed in an isolated sandbox with no network access and strict time and memory limits. It is never deployed or executed."),
 ("Who decides the verdict, the AI or the tools?", "The verdict (Deployable / Fix first / Do not deploy) is computed from the static analysis findings. The AI writes explanations and optional patches but cannot change the verdict."),
 ("What are the limits?", "Single-file Solidity, up to 500 lines and 100 KB, no imports (flatten first), compiler versions 0.8.19 to 0.8.28. The free tier gives 3 scans per day with the verdict and top 3 findings."),
 ("How much does it cost and how do I pay?", "Free: 3 scans/day. Full report with all findings and an auto-fix patch: $3 USDC for 1 scan or $10 USDC for 5 scans, paid on Base. You send a normal USDC transfer, paste the transaction hash and receive a redeem code. We never ask you to sign messages or approve token spending."),
 ("Can AI agents use ContractScan?", "Yes. There is a JSON API (POST /api/scan) and a minimal MCP server exposing a scan_contract tool. See the API docs and llms.txt."),
 ("Do you store my code?", "Contract source is processed in a temporary directory that is deleted after the scan. We keep anonymous usage counters, payment records and optional feedback you choose to send."),
]

def home(min_conf=3):
    faq_html = "".join(f"<details><summary>{E(q)}</summary><p>{E(a)}</p></details>" for q, a in FAQ)
    body = f'''<button id="lt" class="toggle sec" type="button">中文</button>
<h1>Is your AI-written Solidity safe to deploy?</h1><div class="disc" id="disc">⚠️ Not an audit. Automated static analysis (Slither + Aderyn + heuristics) can miss bugs and give false positives.</div>
<p id="intro">Paste a single-file Solidity contract (≤500 lines). We compile and statically analyze it — it is never executed.</p>
<noscript><p class="err">The scanner needs JavaScript. You can also use the JSON API: see <a href="/docs">/docs</a>.</p></noscript>
<label for="src" class="hp">Solidity source</label><textarea id="src" placeholder="pragma solidity ^0.8.20; ..." maxlength="100000"></textarea><br><button id="go" type="button">Scan</button> <span id="st" role="status"></span>
<div id="out" aria-live="polite"></div><div id="fb" class="fb" hidden></div>
<section class="card" id="buy"><h2 id="buyT">Full report + auto-fix (pay with USDC on Base)</h2>
<p><label><input type="radio" name="pk" value="single" checked> <span id="b1">$3 USDC · 1 full scan</span></label> &nbsp; <label><input type="radio" name="pk" value="pack5"> <span id="b5">$10 USDC · 5 full scans</span></label></p>
<div class="box"><div id="payInfo"></div><button type="button" id="copyAddr" class="sec">Copy address</button></div>
<p><button type="button" id="wpay">Pay with browser wallet</button> <small id="manualT"></small></p>
<p><label for="txh" class="hp">Transaction hash</label><input id="txh" placeholder="0x… transaction hash" size="70" maxlength="80"> <button type="button" id="claimB" class="sec">Get my redeem code</button></p>
<div id="pst" role="status"></div>
<div id="codeBox" class="code" hidden><div id="codeWarn"></div><div id="codeVal"></div><button type="button" id="copyCode">Copy code</button></div>
<p><label for="codeIn" class="hp">Redeem code</label><input id="codeIn" placeholder="CS-XXXX-XXXX-XXXX-XXXX" size="30" maxlength="40"> <button type="button" id="useCode" class="sec">Use code</button> <span id="cr"></span> <button type="button" id="forget" class="sec" hidden>Forget code</button></p>
<small id="pay"></small><br><small id="sup"></small></section>
<section id="faq"><h2>FAQ</h2>{faq_html}</section>
{newsletter_form("home")}
<script src="/static/app.js" defer></script>'''
    ld = [{"@context": "https://schema.org", "@type": "SoftwareApplication", "name": "ContractScan", "url": BASE + "/", "applicationCategory": "DeveloperApplication",
           "operatingSystem": "Web", "description": DESC, "image": BASE + "/static/og-image.png",
           "offers": [{"@type": "Offer", "price": "0", "priceCurrency": "USD", "description": "Free: 3 scans/day, verdict + top 3 findings"},
                      {"@type": "Offer", "price": "3", "priceCurrency": "USD", "description": "1 full scan with all findings and auto-fix patch, paid in USDC on Base"},
                      {"@type": "Offer", "price": "10", "priceCurrency": "USD", "description": "5 full scans, paid in USDC on Base"}],
           "sameAs": [X_URL]},
          {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [{"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in FAQ]}]
    return layout("ContractScan — Is your AI-written Solidity safe to deploy?", DESC, "/", body, ld)

def blog_index():
    ps = posts()
    if ps: items = "".join(f'<li><a href="/blog/{E(p["slug"])}">{E(p["title"])}</a> <small><time datetime="{E(p["date"])}">{E(p["date"])}</time></small><br><span class="mut">{E(p["description"])}</span></li>' for p in ps)
    else: items = "<li class=\"mut\">Coming soon: practical, no-hype guides on Solidity security for people building with AI. Subscribe below to get the first one.</li>"
    body = f'<h1>ContractScan Blog</h1><p class="mut">Smart contract security for builders who ship with AI assistants.</p><ul>{items}</ul>{newsletter_form("blog")}'
    return layout("Blog — Solidity security for AI builders | ContractScan", "Practical guides on smart contract security for developers who build with AI coding assistants.", "/blog", body)

def blog_post(slug):
    p = next((x for x in posts() if x["slug"] == slug), None)
    if not p: return None
    cta = '<section class="card"><h2>Check your own contract</h2><p>Paste a single-file Solidity contract into <a href="/">ContractScan</a> for a free static-analysis check with plain-language explanations.</p><p class="mut"><small>ContractScan is automated static analysis, not an audit. For contracts holding real value, get a professional audit.</small></p></section>'
    body = f'<article><h1>{E(p["title"])}</h1><p class="mut">By {E(p.get("author", "ContractScan Team"))} · <time datetime="{E(p["date"])}">{E(p["date"])}</time></p>{p["body"]}{cta}</article>{newsletter_form("blog:" + slug)}'
    ld = [{"@context": "https://schema.org", "@type": "Article", "headline": p["title"], "description": p["description"], "datePublished": p["date"], "dateModified": p.get("updated", p["date"]),
           "image": BASE + "/static/og-image.png", "mainEntityOfPage": BASE + "/blog/" + slug, "author": {"@type": "Organization", "name": p.get("author", "ContractScan Team"), "url": BASE},
           "publisher": {"@type": "Organization", "name": "ContractScan", "logo": {"@type": "ImageObject", "url": BASE + "/static/apple-touch-icon.png"}}}]
    return layout(p["title"] + " | ContractScan", p["description"], "/blog/" + slug, body, ld, og_type="article")

def simple_page(title, msg, path="/subscribed"):
    return layout(title + " | ContractScan", title, path, f"<h1>{E(title)}</h1><p>{E(msg)}</p><p><a href=\"/\">Back to ContractScan</a></p>").replace('<link rel="canonical"', '<meta name="robots" content="noindex"><link rel="canonical"')

def sitemap():
    today = datetime.date.today().isoformat()
    urls = [("/", today), ("/blog", today), ("/docs", today)] + [("/blog/" + p["slug"], p.get("updated", p["date"])) for p in posts()]
    return '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + "".join(f"<url><loc>{BASE}{E(u)}</loc><lastmod>{d}</lastmod></url>" for u, d in urls) + "</urlset>\n"

def robots():
    return f"User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /subscribe\n\nSitemap: {BASE}/sitemap.xml\n"

DOCS = """ContractScan API documentation (plain text)
============================================
Base URL: {base}
ContractScan is automated static analysis (Slither + Aderyn + rug-pattern heuristics) with AI explanations. NOT AN AUDIT.

Limits
------
- Single-file Solidity, max 500 lines / 100 KB, no import statements (flatten first).
- Supported compilers: 0.8.19 - 0.8.28 (chosen from your pragma).
- Code is compiled and statically analysed in a network-less sandbox. It is never executed.
- Free tier: 3 scans per day per IP (verdict + top 3 findings, no patch).

POST /api/scan
--------------
Request:  Content-Type: application/json
          {{"source": "<solidity source>"}}
Optional header: X-CS-Code: CS-XXXX-XXXX-XXXX-XXXX   (redeem code -> full report + patch, uses 1 credit)
Response 200 (JSON), main fields:
  verdict          "deployable" | "fix_first" | "do_not_deploy"   (computed from tool findings, never by the AI)
  verdict_label    {{"en": "...", "zh": "..."}}
  counts           {{"high": n, "medium": n, "low": n, "info": n}}
  findings[]       tool, id, severity, title, detail, lines[], explain_en, explain_zh
  findings_hidden  number of findings not shown on the free tier
  summary          {{"en": "...", "zh": "..."}} AI summary (may be null)
  patch            patched source (full tier only, shown only if it passes a re-scan with no high/medium findings)
  disclaimer       {{"en": "...", "zh": "..."}}
  scan_id          id you can reference in feedback
Errors: 400 invalid input / compile error (not charged), 402 free limit reached (body contains payment info).

Example:
  curl -s -X POST {base}/api/scan -H 'content-type: application/json' \\
       -d '{{"source":"// SPDX-License-Identifier: MIT\\npragma solidity 0.8.24;\\ncontract A {{}}"}}'

Payments (USDC on Base, no signatures)
--------------------------------------
GET  /api/pricing                    -> prices, recipient address, USDC contract, network
1. Send a USDC transfer on Base (chain id 8453) to the recipient from /api/pricing. $3 = 1 full scan, $10 = 5.
   Amounts below $3 grant no credits (flagged for manual refund review).
2. POST /api/pay/claim {{"tx_hash": "0x..."}}  -> {{"code": "CS-....", "credits": n}}
   Needs 3 confirmations; "retryable": true errors mean try again shortly. The same tx returns the same code
   for 1 hour after the first claim; after that contact support.
3. POST /api/code {{"code": "CS-..."}}      -> remaining credits
x402 endpoints (POST /api/x402/scan $0.25, /api/x402/scan-full $1.50) are not enabled on mainnet yet.

Feedback
--------
POST /api/feedback {{"scan_id": "...", "useful": true|false, "comment": "optional, max 1000 chars"}}

MCP server (stdio)
------------------
Tool: scan_contract(source: string) -> JSON string with the same report as /api/scan (free tier, rate-limited per caller).
Run locally from the source distribution: python mcp_server.py

Source code (MIT): {gh}
Support: support@contract-scan.dev · X: {x}
"""

def docs(): return DOCS.format(base=BASE, x=X_URL, gh=GITHUB_URL)

def llms_txt():
    return f"""# ContractScan

> ContractScan ({BASE}) checks single-file Solidity smart contracts before deployment. It runs Slither and Aderyn static analysis plus rug-pull pattern heuristics, then explains findings in plain English and Chinese and gives a verdict: Deployable, Fix first, or Do not deploy. It is NOT an audit.

Key facts:
- Audience: developers and "vibe coders" who write Solidity with AI assistants, and coding agents that want a pre-deploy check.
- The verdict is computed from static-analysis findings; AI only writes explanations and optional patches.
- Code is compiled and analysed in a network-less sandbox and never executed.
- Limits: single file, <=500 lines, no imports, solc 0.8.19-0.8.28.
- Pricing: free 3 scans/day (verdict + top 3 findings); $3 USDC = 1 full scan with all findings and an auto-fix patch; $10 USDC = 5 full scans. Paid with a plain USDC transfer on Base; no wallet signatures.
- Interfaces: web UI, JSON API (POST /api/scan), MCP stdio server with tool `scan_contract`.

## Docs
- [API documentation (plain text)]({BASE}/docs): endpoints, request/response fields, payment flow
- [Full product description for LLMs]({BASE}/llms-full.txt)
- [FAQ]({BASE}/#faq)

## Optional
- [Blog]({BASE}/blog)
- [Source code (MIT)]({GITHUB_URL})
- [AI-written Solidity scan experiment data, 2026-10]({DATA_URL})
- [X / Twitter]({X_URL})
"""

def llms_full():
    faq = "\n".join(f"Q: {q}\nA: {a}\n" for q, a in FAQ)
    return llms_txt() + "\n\n## FAQ\n\n" + faq + "\n\n## API\n\n" + docs() + """
## Known limitations
- Static analysis only: no formal verification, fuzzing, economic or cross-contract analysis.
- Rug-pattern checks are regex heuristics; they produce false positives (e.g. legitimate pause functions) and can be evaded.
- Multi-file projects and imports are not supported yet.
- AI patches are rewrites; review them and re-test. A patch is only shown if a re-scan finds no high/medium issues.
"""
