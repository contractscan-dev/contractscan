import os, time, asyncio, logging, secrets, re, urllib.parse
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, PlainTextResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

def _load_cfg(p=os.path.join(os.path.dirname(__file__), "config.env")):
    if os.path.exists(p):
        for l in open(p):
            l = l.strip()
            if l and not l.startswith("#") and "=" in l:
                k, v = l.split("=", 1); os.environ.setdefault(k.strip(), v.strip())
_load_cfg()
from scanner import scan
import second_opinion
from explain import build_report
import payments
import pages
from payments import PayError

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("contractscan")
HERE = os.path.dirname(os.path.abspath(__file__))
app = FastAPI(title="ContractScan", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None)
FREE_PER_DAY = int(os.environ.get("CS_FREE_PER_DAY", "3"))
LIMIT_ON = not os.environ.get("CS_DISABLE_LIMIT")
_sem = asyncio.Semaphore(int(os.environ.get("CS_MAX_CONCURRENT_SCANS", "2")))
NET = payments.net()
PRICES = {"single": 3.0, "pack5": 10.0, "x402_quick": 0.25, "x402_full": 1.5}
FACILITATOR = os.environ.get("CS_X402_FACILITATOR", "https://x402.org/facilitator")
SUPPORT = payments.SUPPORT
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.update({"Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                         "Cross-Origin-Opener-Policy": "same-origin", "Cache-Control": resp.headers.get("Cache-Control", "no-store")})
    if request.url.path.startswith("/api/"): resp.headers["Cache-Control"] = "no-store"
    return resp
# No CORS middleware on purpose: browsers block cross-origin reads; agents use the API server-to-server.

# ---------------- x402 (SDK middleware on dedicated paid routes) ----------------
X402 = {"enabled": False, "network": NET["caip2"], "facilitator": FACILITATOR, "routes": {"POST /api/x402/scan": "$0.25", "POST /api/x402/scan-full": "$1.50"}}
def _setup_x402():
    if os.environ.get("CS_X402_ENABLED", "1") != "1": X402["reason"] = "disabled by config"; return
    if NET["chain_id"] == 8453 and "x402.org" in FACILITATOR:
        X402["reason"] = "TODO: Base mainnet needs a mainnet facilitator (e.g. Coinbase CDP, requires CDP API key). Set CS_X402_FACILITATOR (+auth) or use CS_PAY_NETWORK=base-sepolia."
        return
    from x402 import x402ResourceServer
    from x402.http import HTTPFacilitatorClient, FacilitatorConfig
    from x402.http.middleware.fastapi import payment_middleware
    from x402.mechanisms.evm.exact.register import register_exact_evm_server
    # TODO(mainnet): pass auth_provider for CDP facilitator (CDP_API_KEY_ID / CDP_API_KEY_SECRET).
    server = register_exact_evm_server(x402ResourceServer(HTTPFacilitatorClient(FacilitatorConfig(url=FACILITATOR))), NET["caip2"])
    acc = lambda price: {"scheme": "exact", "payTo": os.environ["CS_PAY_TO"], "price": price, "network": NET["caip2"]}
    routes = {"POST /api/x402/scan": {"accepts": acc("$0.25"), "description": "ContractScan quick check (not an audit)"},
              "POST /api/x402/scan-full": {"accepts": acc("$1.50"), "description": "ContractScan full report + auto-fix patch (not an audit)"}}
    mw = payment_middleware(routes, server)
    @app.middleware("http")
    async def x402_mw(request, call_next): return await mw(request, call_next)
    X402["enabled"] = True
try: _setup_x402()
except Exception as e: X402["reason"] = f"x402 init failed: {type(e).__name__}"; log.exception("x402 init")

PAYMENT = {"network": os.environ.get("CS_PAY_NETWORK", "base"), "chain_id": NET["chain_id"], "asset": "USDC", "usdc_contract": NET["usdc"],
           "pay_to": os.environ["CS_PAY_TO"], "explorer": NET["explorer"], "prices_usd": PRICES, "min_confirmations": payments.min_conf(),
           "support_email": SUPPORT, "x402": X402}

class ScanReq(BaseModel):
    source: str = Field(..., max_length=250_000)
class ClaimReq(BaseModel):
    tx_hash: str = Field(..., max_length=80)
class CodeReq(BaseModel):
    code: str = Field(..., max_length=40)

def _ip(request):
    # Trust X-Forwarded-For only from the local reverse proxy (Caddy overwrites it with the real client IP).
    if request.client and request.client.host in ("127.0.0.1", "::1") and request.headers.get("x-forwarded-for"):
        return request.headers["x-forwarded-for"].split(",")[-1].strip()[:64]
    return request.client.host if request.client else "unknown"
def _code(request):
    return request.headers.get("x-cs-code", "")[:40] or None
def _pay_err(e: PayError, status=400):
    return JSONResponse({"error": str(e), "code": e.code, "retryable": e.retryable, "support_email": SUPPORT}, status_code=503 if e.code == "rpc_unavailable" else status)

@app.exception_handler(PayError)
async def _pe(request, e): return _pay_err(e)

HTML_CACHE = {"Cache-Control": "public, max-age=300"}
@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
def index(): return HTMLResponse(pages.home(), headers=HTML_CACHE)
@app.api_route("/blog", methods=["GET", "HEAD"], response_class=HTMLResponse)
def blog(): return HTMLResponse(pages.blog_index(), headers=HTML_CACHE)
@app.api_route("/blog/{slug}", methods=["GET", "HEAD"], response_class=HTMLResponse)
def blog_post(slug: str):
    h = pages.blog_post(slug) if re.fullmatch(r"[a-z0-9-]{1,100}", slug) else None
    if not h: return HTMLResponse(pages.simple_page("Not found", "This article does not exist (yet).", "/blog"), status_code=404)
    return HTMLResponse(h, headers=HTML_CACHE)
@app.api_route("/docs", methods=["GET", "HEAD"])
def docs(): return PlainTextResponse(pages.docs(), headers=HTML_CACHE)
@app.api_route("/llms.txt", methods=["GET", "HEAD"])
def llms(): return PlainTextResponse(pages.llms_txt(), headers=HTML_CACHE)
@app.api_route("/llms-full.txt", methods=["GET", "HEAD"])
def llms_full(): return PlainTextResponse(pages.llms_full(), headers=HTML_CACHE)
@app.api_route("/sitemap.xml", methods=["GET", "HEAD"])
def sitemap(): return Response(pages.sitemap(), media_type="application/xml", headers=HTML_CACHE)
@app.api_route("/robots.txt", methods=["GET", "HEAD"])
def robots(): return PlainTextResponse(pages.robots(), headers=HTML_CACHE)
@app.api_route("/favicon.ico", methods=["GET", "HEAD"])
def favicon(): return FileResponse(os.path.join(HERE, "static/favicon.ico"), headers={"Cache-Control": "public, max-age=86400"})

EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
@app.post("/subscribe")
async def subscribe(request: Request):
    raw = (await request.body())[:4096]
    ctype = request.headers.get("content-type", "")
    if "json" in ctype:
        try: import json as _j; data = _j.loads(raw or b"{}")
        except Exception: data = {}
    else: data = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}
    wants_json = "json" in ctype or "json" in request.headers.get("accept", "")
    def done(ok, msg, status=200):
        if wants_json: return JSONResponse({"ok": ok, "message": msg}, status_code=status)
        return HTMLResponse(pages.simple_page("Thanks!" if ok else "Could not subscribe", msg), status_code=status)
    if data.get("website"): return done(True, "Thanks, you're on the list.")       # honeypot: pretend success
    if not payments._rate("sub:" + _ip(request), 5): return done(False, "Too many signups from your network; try later.", 429)
    email = str(data.get("email", "")).strip().lower()
    if len(email) > 254 or not EMAIL_RE.match(email): return done(False, "That doesn't look like a valid email address.", 400)
    src = re.sub(r"[^a-z0-9:_-]", "", str(data.get("source", "web")).lower())[:60] or "web"
    payments.add_subscriber(email, src)
    return done(True, "Thanks, you're on the list. We'll only email about new articles and product updates.")

class FeedbackReq(BaseModel):
    scan_id: str = Field("", max_length=32); useful: bool; comment: str = Field("", max_length=1000)
@app.post("/api/feedback")
def feedback(req: FeedbackReq, request: Request):
    if not payments._rate("fb:" + _ip(request), 30): return JSONResponse({"ok": False, "error": "rate limited"}, status_code=429)
    sid = req.scan_id if re.fullmatch(r"[0-9a-f]{0,32}", req.scan_id or "") else ""
    payments.add_feedback(sid, req.useful, req.comment.strip())
    return {"ok": True}

class EventReq(BaseModel):
    event: str = Field(..., max_length=20); scan_id: str = Field("", max_length=16); detail: str = Field("", max_length=20)
@app.post("/api/event")
def event(req: EventReq, request: Request):
    """Client funnel events (result_viewed, pay_clicked). No source, IP, wallet or tx data is stored."""
    if req.event not in payments.CLIENT_EVENTS: return JSONResponse({"ok": False, "error": "unknown event"}, status_code=400)
    if not payments._rate("ev:" + _ip(request), 20): return JSONResponse({"ok": False, "error": "rate limited"}, status_code=429)
    if is_bot_ua(request.headers.get("user-agent", "")): return {"ok": True, "logged": False}   # silently ignored
    why = payments.client_event_ok(req.event, req.scan_id, payments.client_hash(request.headers.get("user-agent", "")))
    if why: return {"ok": True, "logged": False}
    det = req.detail if req.detail in ("wallet", "manual", "claim", "copy_address") else None
    payments.log_event(req.event, "web", req.scan_id, detail=det)
    return {"ok": True, "logged": True}

BOT_UA = re.compile(r"bot|crawl|spider|slurp|headless|phantom|selenium|puppeteer|playwright|python|curl|wget|httpx|go-http|axios|node-fetch|okhttp|java/|libwww|scrapy|preview|monitor|uptime", re.I)
def is_bot_ua(ua): return not ua or len(ua) < 20 or bool(BOT_UA.search(ua))

app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
@app.get("/api/health")
def health(): return {"ok": True}
@app.get("/api/pricing")
def pricing(): return {"free_per_day_per_ip": FREE_PER_DAY, "payment": PAYMENT}

@app.post("/api/code")
def code_info(req: CodeReq, request: Request):
    try: c = payments.check_code(req.code, _ip(request))
    except PayError as e: return _pay_err(e)
    return {"code": c, "credits": payments.code_credits(c)}
@app.post("/api/pay/claim")
async def pay_claim(req: ClaimReq, request: Request):
    try:
        res = await asyncio.to_thread(payments.claim, req.tx_hash, _ip(request))
        if not res.get("already_claimed"): payments.log_event("paid", "web", detail=f"credits:{int(res.get('credits') or 0)}")
        return res
    except PayError as e: return _pay_err(e)
    except Exception: log.exception("claim"); return _pay_err(PayError(f"Unexpected error verifying payment; nothing was lost, retry later or email {SUPPORT}.", "internal", True), 500)

async def _ai(source, scan_id):
    """Advisory AI second opinion; runs concurrently with the scan and can never fail or change it."""
    try: return await asyncio.wait_for(asyncio.to_thread(second_opinion.second_opinion, source, scan_id), second_opinion.TIMEOUT * 2 + 30)
    except Exception: return second_opinion._skip("error")
async def _run(source, full, scan_id=None, ai=False):
    ai_task = asyncio.create_task(_ai(source, scan_id)) if ai else None
    try:
        async with _sem: raw = await asyncio.wait_for(asyncio.to_thread(scan, source), 300)
        rep = await asyncio.to_thread(build_report, raw, source, full)
    except BaseException:
        if ai_task: ai_task.cancel()
        raise
    if ai_task:
        op = await ai_task
        if raw.get("ok") and isinstance(rep, dict): rep["ai_second_opinion"] = op   # verdict is untouched: separate key
    return raw, rep

@app.post("/api/scan")
async def api_scan(req: ScanReq, request: Request):
    dev_full = os.environ.get("CS_DEV_FULL") == "1"; ip = _ip(request); free_left = None
    code = _code(request); wallet = None
    if code:
        try: code = payments.check_code(code, ip)
        except PayError as e: return _pay_err(e)
        wallet = payments.reserve(code)              # paid users: credit reserved first, bypass IP limit
    if not wallet and not dev_full and LIMIT_ON:
        free_left = payments.free_take(ip, FREE_PER_DAY)
        if free_left < 0:
            raise HTTPException(402, {"error": "free_limit_reached", "message": f"Free tier: {FREE_PER_DAY} scans/day per IP. Buy credits or use x402.", "payment": PAYMENT})
    scan_id = secrets.token_hex(8)
    if request.headers.get("x-cs-ui"): payments.bind_scan(scan_id, payments.client_hash(request.headers.get("user-agent", "")))
    payments.log_event("scan_started", "web" if request.headers.get("x-cs-ui") else "api", scan_id)
    try:
        raw, rep = await _run(req.source, full=bool(wallet) or dev_full, scan_id=scan_id, ai=True)
        ok = bool(raw.get("ok"))
    except ValueError as e:
        raw, rep, ok = None, None, False; err = str(e)
    except Exception:
        log.exception("scan"); raw, rep, ok = None, None, False; err = "internal error during scan"
    if not ok:  # failed scans never consume a credit or a free scan
        if wallet: payments.refund(wallet)
        elif free_left is not None: payments.free_give_back(ip)
        if rep is None:
            payments.log_event("scan_failed", "web" if request.headers.get("x-cs-ui") else "api", scan_id, detail="rejected")
            raise HTTPException(400, {"error": err, "charged": False})
        rep["charged"] = False
    else: rep["charged"] = "credit" if wallet else ("free" if free_left is not None else "none")
    if free_left is not None and ok: rep["free_remaining"] = free_left
    if code: rep["credits"] = payments.code_credits(code)
    rep["scan_id"] = scan_id
    surf = "web" if request.headers.get("x-cs-ui") else "api"
    if ok: payments.log_scan(rep["scan_id"], rep.get("verdict"), rep.get("tier")); payments.log_event("scan_completed", surf, scan_id, rep.get("verdict"), rep.get("tier"))
    else: payments.log_event("scan_failed", surf, scan_id, detail="compile_or_input")
    return rep

@app.post("/api/x402/scan")
async def x402_quick(req: ScanReq):
    if not X402["enabled"]: raise HTTPException(503, {"error": "x402 not enabled", "reason": X402.get("reason")})
    payments.log_event("scan_started", "x402")
    raw, rep = await _run(req.source, full=False)
    payments.log_event("scan_completed" if raw.get("ok") else "scan_failed", "x402", verdict=rep.get("verdict"), detail="quick")
    return {k: rep.get(k) for k in ("ok", "error", "disclaimer", "verdict", "verdict_label", "counts", "summary", "findings", "findings_hidden")} | {"tier": "x402_quick"}
@app.post("/api/x402/scan-full")
async def x402_full(req: ScanReq):
    if not X402["enabled"]: raise HTTPException(503, {"error": "x402 not enabled", "reason": X402.get("reason")})
    payments.log_event("scan_started", "x402")
    raw, rep = await _run(req.source, full=True); rep["tier"] = "x402_full"
    payments.log_event("scan_completed" if raw.get("ok") else "scan_failed", "x402", verdict=rep.get("verdict"), detail="full"); return rep
