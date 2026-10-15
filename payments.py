"""USDC-on-Base payments, NO signatures: user sends USDC to CS_PAY_TO, submits the tx hash, server verifies on-chain
and issues a random redeem code (CS-XXXX-XXXX-XXXX-XXXX) that holds the credits. No private keys; server only READS the chain."""
import os, re, sqlite3, secrets, time, threading, logging, json, httpx

NETWORKS = {  # USDC addresses verified from Circle docs (developers.circle.com/stablecoins/usdc-contract-addresses), 2026-10-15
    "base": {"chain_id": 8453, "caip2": "eip155:8453", "usdc": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "rpc": "https://mainnet.base.org", "explorer": "https://basescan.org"},
    "base-sepolia": {"chain_id": 84532, "caip2": "eip155:84532", "usdc": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "rpc": "https://sepolia.base.org", "explorer": "https://sepolia.basescan.org"},
}
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SINGLE, PACK5 = 3_000_000, 10_000_000  # micro-USDC: $3 = 1 credit, $10 = 5 credits
SUPPORT = os.environ.get("CS_SUPPORT_EMAIL", "support@contract-scan.dev")
DB = os.environ.get("CS_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "contractscan.db"))
TX_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ALPHA = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # 30 symbols, no 0/O/1/I/L/U ambiguity; 16 chars ~ 78.5 bits
CODE_RE = re.compile(r"^CS(-[%s]{4}){4}$" % ALPHA)
RESHOW_WINDOW = int(os.environ.get("CS_RESHOW_WINDOW_S", "3600"))  # re-show code by tx hash only within this window after first claim (default 1h)
LOOKUP_PER_HOUR = int(os.environ.get("CS_CLAIM_PER_HOUR", "20"))         # claim/lookup attempts per IP per hour
BADCODE_PER_HOUR = int(os.environ.get("CS_BADCODE_PER_HOUR", "20"))      # wrong redeem-code attempts per IP per hour
_lock = threading.RLock()
log = logging.getLogger("contractscan.payments")

class PayError(ValueError):
    """User-facing payment error. retryable=True means the client should retry the same claim later (nothing was lost)."""
    def __init__(self, msg, code, retryable=False): super().__init__(msg); self.code, self.retryable = code, retryable

def net(): n = NETWORKS[os.environ.get("CS_PAY_NETWORK", "base")]; return {**n, "rpc": os.environ.get("CS_RPC_URL", n["rpc"])}
def pay_to(): return os.environ["CS_PAY_TO"].lower()
def min_conf(): return int(os.environ.get("CS_MIN_CONFIRMATIONS", "3"))

import contextlib
_init_done = set()
@contextlib.contextmanager
def db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB, timeout=15, isolation_level=None); c.execute("pragma journal_mode=wal"); c.execute("pragma busy_timeout=15000")
    if DB not in _init_done:
        c.executescript("""
      create table if not exists codes(code text primary key, credits int not null default 0, created int);
      create table if not exists payments3(tx_hash text primary key, chain_id int, payer text, amount int, credits int, code text, first_claim int, review text);
      create table if not exists claims_log(ts int, tx_hash text, address text, outcome text, detail text);
      create table if not exists rate(k text, bucket text, n int, primary key(k, bucket));
      create table if not exists free_usage(ip text, day text, n int, primary key(ip, day));
      create table if not exists mcp_usage(caller text, day text, n int, primary key(caller, day));
      create table if not exists subscribers(email text primary key, ts int, source text, confirmed int not null default 0);
      create table if not exists scans(scan_id text primary key, ts int, verdict text, tier text);
      create table if not exists feedback(ts int, scan_id text, useful int, comment text, verdict text);
      create table if not exists funnel(ts int, day text, event text, surface text, scan_id text, verdict text, detail text);""")
        _init_done.add(DB)
    try: yield c
    finally: c.close()

def _win():
    h = RESHOW_WINDOW / 3600
    return f"{h:g} hour" + ("" if h == 1 else "s")

def _audit(tx, addr, outcome, detail=""):
    with db() as c: c.execute("insert into claims_log values(?,?,?,?,?)", (int(time.time()), tx, addr, outcome, str(detail)[:300]))
    log.info("claim tx=%s addr=%s outcome=%s %s", tx, addr, outcome, detail)

def _rate(key, limit, window=3600):
    """Fixed-window counter; returns True if allowed."""
    b = str(int(time.time()) // window)
    with _lock, db() as c:
        c.execute("insert into rate values(?,?,0) on conflict do nothing", (key, b))
        return c.execute("update rate set n=n+1 where k=? and bucket=? and n<?", (key, b, limit)).rowcount == 1

# ---------- redeem codes ----------
def norm_code(code):
    c = (code or "").strip().upper().replace(" ", "")
    if c and not c.startswith("CS-"): c = "CS-" + c
    return c if CODE_RE.match(c) else None
def _new_code(): return "CS-" + "-".join("".join(secrets.choice(ALPHA) for _ in range(4)) for _ in range(4))

def code_credits(code):
    code = norm_code(code)
    if not code: return None
    with db() as c: r = c.execute("select credits from codes where code=?", (code,)).fetchone()
    return r[0] if r else None

def check_code(code, ip):
    """Validate a user-supplied code with brute-force protection. Returns normalized code or raises PayError."""
    n = norm_code(code)
    if n and code_credits(n) is not None: return n
    if not _rate("badcode:" + ip, BADCODE_PER_HOUR): raise PayError("Too many invalid codes; try again later.", "rate_limited", True)
    raise PayError("Unknown redeem code.", "bad_code")

def reserve(code):
    """Atomically take 1 credit before a paid scan. Returns code or None."""
    code = norm_code(code)
    if not code: return None
    with _lock, db() as c:
        return code if c.execute("update codes set credits=credits-1 where code=? and credits>0", (code,)).rowcount == 1 else None
def refund(code):
    with _lock, db() as c: c.execute("update codes set credits=credits+1 where code=?", (code,))

def credits_for(amount):
    """$10 -> 5 credits (packs first), then $3 -> 1 credit each. Returns (credits, remainder_micro)."""
    cr = 5 * (amount // PACK5); rest = amount % PACK5
    cr += rest // SINGLE; rest %= SINGLE
    return cr, rest

# ---------- chain ----------
def _rpc(method, params):
    last = None
    for attempt in range(4):  # public RPC rate-limits (429) / flaky; back off. Production: dedicated CS_RPC_URL.
        try:
            r = httpx.post(net()["rpc"], json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
            if r.status_code == 429 or r.status_code >= 500: last = f"HTTP {r.status_code}"; time.sleep(1.5 * (attempt + 1)); continue
            r.raise_for_status(); j = r.json()
            if "error" in j: last = f"rpc error {j['error'].get('code')}"; time.sleep(1); continue
            return j["result"]
        except (httpx.HTTPError, ValueError) as e: last = type(e).__name__; time.sleep(1.5 * (attempt + 1))
    raise PayError(f"Blockchain RPC unavailable ({last}). Your payment is safe on-chain; retry the claim in a minute.", "rpc_unavailable", True)

def inspect_tx(tx_hash, recipient=None):
    """Return (payer, amount, confirmations) for USDC Transfer(s) to recipient in a successful tx."""
    n = net(); recipient = (recipient or pay_to()).lower()
    if _rpc("eth_chainId", []) != hex(n["chain_id"]): raise PayError("RPC chain mismatch (server misconfigured). Contact support.", "rpc_chain", True)
    rc = _rpc("eth_getTransactionReceipt", [tx_hash])
    if not rc: raise PayError("Transaction not found yet (pending or not broadcast). Retrying is safe.", "pending", True)
    if rc.get("status") != "0x1": raise PayError("Transaction failed on-chain; no USDC was transferred.", "tx_failed")
    conf = int(_rpc("eth_blockNumber", []), 16) - int(rc["blockNumber"], 16) + 1
    if conf < min_conf(): raise PayError(f"Waiting for confirmations ({max(conf,0)}/{min_conf()}). Retrying is safe.", "confirmations", True)
    total, payer = 0, None
    for lg in rc.get("logs", []):
        t = lg.get("topics", [])
        if lg.get("removed"): continue
        if lg["address"].lower() == n["usdc"].lower() and len(t) == 3 and t[0] == TRANSFER_TOPIC and ("0x" + t[2][-40:]).lower() == recipient:
            frm = ("0x" + t[1][-40:]).lower()
            if payer and frm != payer: continue  # only count transfers from one sender
            payer = frm; total += int(lg["data"], 16)
    if not total: raise PayError("No USDC transfer to the ContractScan wallet found in this transaction.", "no_transfer")
    return payer, total, conf

def claim(tx_hash, ip="unknown"):
    """Verify a USDC payment tx and return its redeem code. Same tx -> same code (re-shown only within RESHOW_WINDOW)."""
    if not (isinstance(tx_hash, str) and TX_RE.match(tx_hash.strip())): raise PayError("Bad transaction hash (0x + 64 hex chars).", "bad_tx")
    tx_hash = tx_hash.strip().lower()
    if not _rate("claim:" + ip, LOOKUP_PER_HOUR): raise PayError(f"Too many lookups from your network; try again within an hour or email {SUPPORT}.", "rate_limited", True)
    with db() as c: prev = c.execute("select code, credits, first_claim, amount, review from payments3 where tx_hash=?", (tx_hash,)).fetchone()
    if prev:
        code, cr, first, amount, review = prev
        if not code:
            _audit(tx_hash, None, "reshow_underpaid"); raise PayError(f"This payment ({amount/1e6} USDC) is below the $3 minimum and granted no credits. It is flagged for manual refund review; email {SUPPORT} with the tx hash.", "underpaid")
        if time.time() - first > RESHOW_WINDOW:
            _audit(tx_hash, None, "reshow_denied_expired"); raise PayError(f"This payment was already claimed more than {_win()} ago. For security the code can no longer be re-shown by tx hash; email {SUPPORT} with the tx hash and the sending wallet address.", "reshow_expired")
        _audit(tx_hash, None, "reshown")
        return {"code": code, "credited": cr, "already_claimed": True, "credits": code_credits(code), "amount_usdc": amount / 1e6}
    try: payer, amount, conf = inspect_tx(tx_hash)
    except PayError as e: _audit(tx_hash, None, "error:" + e.code, e); raise
    cr, rest = credits_for(amount)
    review = "refund_review_underpaid" if cr == 0 else ("remainder_review" if rest else None)
    code = _new_code() if cr else None
    with _lock, db() as c:
        c.execute("begin immediate")
        try:
            if c.execute("select 1 from payments3 where tx_hash=?", (tx_hash,)).fetchone(): c.execute("rollback"); return claim(tx_hash, ip)
            if code: c.execute("insert into codes values(?,?,?)", (code, cr, int(time.time())))
            c.execute("insert into payments3 values(?,?,?,?,?,?,?,?)", (tx_hash, net()["chain_id"], payer, amount, cr, code, int(time.time()), review))
            c.execute("commit")
        except Exception: c.execute("rollback"); raise
    _audit(tx_hash, payer, "credited" if cr else "underpaid", f"amount={amount} credits={cr} remainder={rest} review={review}")
    if not cr:
        raise PayError(f"Received {amount/1e6} USDC, below the $3 minimum: no credits granted. Flagged for manual refund review; email {SUPPORT} with the tx hash.", "underpaid")
    note = f"{rest/1e6} USDC above the pack price was logged for manual review (refund on request: {SUPPORT})." if rest else None
    return {"code": code, "credited": cr, "credits": cr, "amount_usdc": amount / 1e6, "note": note, "already_claimed": False}

# ---------- persistent rate limits ----------
def _day(): return time.strftime("%Y-%m-%d", time.gmtime())
def free_used(ip):
    with db() as c: r = c.execute("select n from free_usage where ip=? and day=?", (ip, _day())).fetchone()
    return r[0] if r else 0
def free_take(ip, per_day):
    """Atomically reserve one free scan; returns remaining or -1 if exhausted."""
    with _lock, db() as c:
        c.execute("insert into free_usage values(?,?,0) on conflict do nothing", (ip, _day()))
        if c.execute("update free_usage set n=n+1 where ip=? and day=? and n<?", (ip, _day(), per_day)).rowcount != 1: return -1
        return per_day - c.execute("select n from free_usage where ip=? and day=?", (ip, _day())).fetchone()[0]
def free_give_back(ip):
    with _lock, db() as c: c.execute("update free_usage set n=max(n-1,0) where ip=? and day=?", (ip, _day()))
def mcp_allow(caller, per_day):
    with _lock, db() as c:
        c.execute("insert into mcp_usage values(?,?,0) on conflict do nothing", (caller, _day()))
        if c.execute("update mcp_usage set n=n+1 where caller=? and day=? and n<?", (caller, _day(), per_day)).rowcount != 1: return False, 0
        return True, per_day - c.execute("select n from mcp_usage where caller=? and day=?", (caller, _day())).fetchone()[0]

# ---------- growth: newsletter + feedback ----------
def add_subscriber(email, source):
    """Store email (double opt-in deferred: confirmed=0). Duplicate signups are ignored."""
    with _lock, db() as c: c.execute("insert into subscribers(email,ts,source) values(?,?,?) on conflict(email) do nothing", (email, int(time.time()), source))
def log_scan(scan_id, verdict, tier):
    with db() as c: c.execute("insert or ignore into scans values(?,?,?,?)", (scan_id, int(time.time()), verdict, tier))
# ---------- funnel analytics (privacy-preserving) ----------
# Stores only: timestamp, UTC day, event name, surface (web|api|mcp|x402), random scan_id, verdict and a short
# allow-listed detail. Never stores contract source, IP addresses, wallet addresses, tx hashes, emails or redeem codes.
FUNNEL_EVENTS = {"scan_started", "scan_completed", "scan_failed", "result_viewed", "pay_clicked", "paid"}
CLIENT_EVENTS = {"result_viewed", "pay_clicked"}
def log_event(event, surface="web", scan_id=None, verdict=None, detail=None):
    if event not in FUNNEL_EVENTS: return False
    try:
        sid = scan_id if scan_id and re.fullmatch(r"[0-9a-f]{16}", scan_id) else None
        det = re.sub(r"[^a-z0-9_:.-]", "", str(detail).lower())[:40] if detail is not None else None
        with db() as c: c.execute("insert into funnel values(?,?,?,?,?,?,?)", (int(time.time()), _day(), event, str(surface)[:10], sid, (verdict or None) and str(verdict)[:20], det))
        return True
    except Exception: log.exception("funnel"); return False      # analytics must never break the product
def funnel_summary(days=30):
    since = int(time.time()) - days * 86400
    with db() as c: rows = c.execute("select event, surface, count(*) from funnel where ts>=? group by event, surface order by event", (since,)).fetchall()
    return [{"event": e, "surface": s, "n": n} for e, s, n in rows]

def add_feedback(scan_id, useful, comment):
    with db() as c:
        r = c.execute("select verdict from scans where scan_id=?", (scan_id,)).fetchone() if scan_id else None
        c.execute("insert into feedback values(?,?,?,?,?)", (int(time.time()), scan_id or None, 1 if useful else 0, comment[:1000], r[0] if r else None))
