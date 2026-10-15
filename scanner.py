"""ContractScan core: sandboxed compile + static analysis (Slither, Aderyn) + rug heuristics + verdict.
Never executes contract code. Each scan runs in a fresh temp dir inside bubblewrap (no network,
read-only root, private /tmp) with prlimit memory cap and a hard timeout."""
import json, os, re, shutil, subprocess, tempfile
from pathlib import Path

VENV = Path(os.environ.get("CS_VENV", "/workspace/csenv"))
SOLC_DIR = VENV / ".solc-select" / "artifacts"
SVM_DIR = Path.home() / ".local/share/svm"
ADERYN = shutil.which("aderyn") or str(Path.home() / ".local/bin/aderyn")
SLITHER = str(VENV / "bin/slither")
MAX_LINES, TIMEOUT = 500, 60
HAS_BWRAP = bool(shutil.which("bwrap"))

def _sandbox(cmd, workdir):
    lim = ["prlimit", "--as=4294967296", "--fsize=67108864", "--nofile=1024", "--cpu=90", "--"]
    if HAS_BWRAP:
        SVM_DIR.mkdir(parents=True, exist_ok=True)
        cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
               "--bind", workdir, workdir, "--ro-bind", str(SVM_DIR), str(SVM_DIR),
               "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--chdir", workdir] + lim + cmd
    else: cmd = lim + cmd
    return subprocess.run(["timeout", str(TIMEOUT)] + cmd, cwd=workdir, capture_output=True, text=True,
                          env={**os.environ, "VIRTUAL_ENV": str(VENV), "HOME": str(Path.home())})

def installed_solcs():
    return sorted([p.name.replace("solc-", "") for p in SOLC_DIR.glob("solc-*")], key=lambda v: tuple(map(int, v.split("."))))

def _v(x): return tuple(map(int, x.split(".")))
def _satisfies(v, spec):
    """Minimal semver check for solidity pragmas: ^a.b.c, >=, >, <=, <, =, exact; space-separated = AND; '||' = OR."""
    for alt in spec.split("||"):
        ok = True
        for part in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)", alt):
            op, b = part
            if op == "^": ok &= _v(v) >= _v(b) and _v(v)[:2] == _v(b)[:2] if _v(b)[0] == 0 else _v(v)[0] == _v(b)[0] and _v(v) >= _v(b)
            elif op == "~": ok &= _v(v)[:2] == _v(b)[:2] and _v(v) >= _v(b)
            elif op == ">=": ok &= _v(v) >= _v(b)
            elif op == ">": ok &= _v(v) > _v(b)
            elif op == "<=": ok &= _v(v) <= _v(b)
            elif op == "<": ok &= _v(v) < _v(b)
            else: ok &= _v(v) == _v(b)
        if ok and re.search(r"\d+\.\d+\.\d+", alt): return True
    return False

def pick_solc(src):
    """Only pre-installed (allow-listed) compilers are used; user pragmas never trigger downloads."""
    ms = re.findall(r"pragma\s+solidity\s+([^;]{1,60});", _strip_comments(src))
    if not ms: raise ValueError("No `pragma solidity` found")
    avail = installed_solcs()
    ok = [v for v in avail if all(_satisfies(v, m) for m in ms)]
    if not ok: raise ValueError(f"Unsupported compiler pragma `{ms[0].strip()[:40]}`. Supported solc versions: {', '.join(avail)}")
    return ok[-1]

def _prewarm_aderyn(ver):
    """Aderyn fetches solc via svm; warm the cache with a trivial stub (never user code) so the sandbox can stay offline."""
    if (SVM_DIR / ver).exists() or ver not in installed_solcs(): return
    d = tempfile.mkdtemp()
    Path(d, "W.sol").write_text(f"// SPDX-License-Identifier: MIT\npragma solidity {ver};\ncontract W{{}}\n")
    subprocess.run([ADERYN, d, "-o", f"{d}/o.json"], capture_output=True, timeout=120); shutil.rmtree(d, True)

SEV_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info", "Optimization": "info"}

def run_slither(d, ver):
    r = _sandbox([SLITHER, "C.sol", "--solc", str(SOLC_DIR / f"solc-{ver}" / f"solc-{ver}"), "--json", "s.json"], d)
    p = Path(d, "s.json")
    if not p.exists(): return [], f"slither failed: {(r.stderr or r.stdout)[-400:]}"
    j = json.loads(p.read_text())
    if not j.get("success"): return [], "compile error: " + str(j.get("error"))[-600:]
    out = []
    for x in j["results"].get("detectors", []):
        lines = sorted({l for e in x.get("elements", []) for l in e.get("source_mapping", {}).get("lines", [])})
        out.append({"tool": "slither", "id": x["check"], "severity": SEV_MAP.get(x["impact"], "info"),
                    "confidence": x.get("confidence"), "title": x["check"], "detail": x["description"].strip()[:800], "lines": lines[:10]})
    return out, None

# Aderyn detectors downgraded high -> low after our 2026-10 AI-Solidity experiment
# (experiments/ai-solidity-2026-10/review.csv: 24 DeepSeek-generated contracts, every finding manually triaged).
# Each produced ONLY false positives there (15/15 Aderyn highs were FPs). Findings stay visible as "low" so
# users can still review them, but they no longer drive the verdict.
ADERYN_DOWNGRADE = {
    # 7/7 FP: fired on ETH sent to msg.sender / owner / configured fee recipient, i.e. normal withdraw & fee flows.
    "eth-send-unchecked-address": "Recipient was msg.sender/owner/configured address in all 7 experiment hits (all false positives).",
    # 4/4 FP: fired on abi.encodePacked string concatenation (tokenURI, LP symbol) that is never hashed.
    "abi-encode-packed-hash-collision": "Fired on string concatenation that was never hashed in all 4 experiment hits (all false positives).",
    # 3/3 FP: constructor call, external *view* call, ETH sent after state updates. Slither's reentrancy-* detectors are
    # more precise and cover the real cases (Slither caught the one real AMM reentrancy; Aderyn missed it).
    "reentrancy-state-change": "All 3 experiment hits were false positives (constructor, view call, effects-before-interaction); Slither reentrancy detectors cover real cases.",
    # 1/1 FP: keccak256(..., block.timestamp, ...) used as a transaction id, not as randomness.
    "weak-randomness": "Only experiment hit hashed block.timestamp into an id, not randomness (false positive).",
}

def run_aderyn(d, ver):
    _prewarm_aderyn(ver)
    r = _sandbox([ADERYN, ".", "-o", "a.json"], d)
    p = Path(d, "a.json")
    if not p.exists(): return [], f"aderyn failed: {(r.stderr or r.stdout)[-400:]}"
    j = json.loads(p.read_text()); out = []
    for key, sev in (("high_issues", "high"), ("low_issues", "low")):
        for x in j.get(key, {}).get("issues", []):
            f = {"tool": "aderyn", "id": x["detector_name"], "severity": sev, "confidence": None, "title": x["title"],
                 "detail": x["description"][:800], "lines": [i["line_no"] for i in x.get("instances", [])][:10]}
            if sev == "high" and f["id"] in ADERYN_DOWNGRADE:
                f.update(severity="low", confidence="downgraded", downgraded_from="high", downgrade_reason=ADERYN_DOWNGRADE[f["id"]])
            out.append(f)
    return out, None

# ---- rug-pull heuristics (regex over comment-stripped source; intentionally simple) ----
# Fee-rate setters only. Excludes exemption/allowlist and recipient setters such as setExcludedFromTax,
# setTaxExempt, setFeeRecipient (false positive in the 2026-10 experiment: setExcludedFromTax matched).
FEE_SETTER = r"function\s+set(?!\w*(?:Exclu|Exempt|Whitelist|Allow|Recipient|Receiver|Wallet|Address|Collector|To\b))\w*(Fee|Tax)\w*\s*\("
RUG = [
  ("owner_mint", "high", r"function\s+mint\w*\s*\([^)]*\)[^{]*(onlyOwner|onlyRole|only\w+)", "Owner/privileged account can mint new tokens at will (supply inflation)."),
  ("blacklist", "high", r"(blacklist|blocklist|isBlocked|_isBot|bots\[|denylist|isBlacklisted)", "Contract keeps a blacklist; specific holders can be blocked from transferring/selling."),
  ("fee_change", "medium", FEE_SETTER, "Owner can change transfer fees/taxes, possibly up to 100% (honeypot risk)."),
  ("pausable", "medium", r"(function\s+pause\s*\(|whenNotPaused|_pause\s*\()", "Transfers can be paused by a privileged account."),
  ("trading_toggle", "high", r"(tradingEnabled|tradingOpen|enableTrading|canTrade|swapEnabled)\b", "Hidden trading switch: transfers can be restricted until/unless owner enables them."),
  ("max_tx_wallet", "low", r"(maxTx\w*|maxWallet\w*|_maxTxAmount)", "Max transaction/wallet limits that the owner may tighten to block sells."),
  ("owner_withdraw", "medium", r"function\s+(withdraw\w*|rescue\w*|emergency\w*|drain\w*|sweep\w*)\s*\([^)]*\)[^{]*only\w+", "Privileged withdraw/rescue function can move funds held by the contract."),
  ("upgradeable", "medium", r"(upgradeTo|_upgradeTo|UUPSUpgradeable|delegatecall)", "Contract logic can be replaced/delegated (owner can change behaviour after deploy)."),
  ("balance_override", "high", r"_balances\s*\[[^\]]+\]\s*=\s*[^;]*;[^}]*}\s*", None),
]
def _strip_comments(s): return re.sub(r"//[^\n]*|/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group()), s, flags=re.S)
def _functions(code):
    """Yield (name, header, body, start_offset) for each function, with brace matching."""
    for m in re.finditer(r"function\s+(\w+)\s*\(", code):
        i = code.find("{", m.end()); semi = code.find(";", m.end())
        if i < 0 or (0 <= semi < i): continue
        depth, j = 0, i
        while j < len(code):
            depth += (code[j] == "{") - (code[j] == "}")
            if depth == 0: break
            j += 1
        yield m.group(1), code[m.start():i], code[i:j + 1], m.start()

# Owner/admin-type roles only. Escrow roles (onlyArbiter/onlyClient) are part of the requested business logic.
PRIV = r"\b(onlyOwner|onlyAdmin|onlyRole\s*\(|onlyOperator|onlyGov\w*|onlyManager|onlyDev)\b"
# Contract takes user deposits (NFT mints / ERC20s do not match: their ETH is sale proceeds, not user funds held in custody).
USER_FUNDS = r"function\s+(deposit|stake|lock)\w*\s*\("
def owner_drain(code):
    """Centralization: privileged function can move funds the contract holds for users.
    Fires only when (a) the contract keeps user deposits/stakes, (b) a privileged function sends the WHOLE balance
    (address(this).balance / token.balanceOf(address(this))) or a caller-chosen amount to an arbitrary/owner address,
    (c) the amount is not bounded by user liabilities (e.g. balance - totalStaked) and (d) no timelock/delay is visible.
    2026-10 experiment: eth_vault_3 emergencyWithdraw() took every depositor's locked ETH (true positive)."""
    if not re.search(USER_FUNDS, code, re.I): return []
    hits = []
    for name, hdr, body, off in _functions(code):
        if not re.search(PRIV, hdr): continue
        sends = re.search(r"(\.call\s*\{\s*value|\.transfer\s*\(|\.send\s*\(|safeTransfer\s*\()", body)
        whole = re.search(r"(address\(this\)\.balance|balanceOf\s*\(\s*address\(this\)\s*\))", body)
        param_amt = re.search(r"uint\d*\s+(amount|_amount|amt|value|wad)\b", hdr)
        bounded = re.search(r"(-\s*\w*(total\w*(Staked|Deposit|Locked|Balance)\w*|reserve\w*|liabilit\w*)|excess|accrued\w*Fee|fees?Collected|protocolFee)", body, re.I) or \
                  re.search(r"require\s*\(\s*\w+\s*!=\s*address\s*\(\s*\w*(staking|deposit|reward|stake)\w*", body, re.I)  # protected-token recover
        timelocked = re.search(r"(timelock|delay|\beta\b|queued)", hdr + body, re.I) and "block.timestamp" in body
        if sends and (whole or param_amt) and not bounded and not timelocked:
            hits.append((name, code[:off].count("\n") + 1))
    return [{"tool": "heuristic", "id": "centralization:owner_can_take_user_funds", "severity": "high", "confidence": "heuristic",
             "title": "owner_can_take_user_funds",
             "detail": f"Privileged function `{n}` can send funds the contract holds for users (deposits/stakes) to the owner or an owner-chosen address, with no visible timelock. Users must fully trust the owner key.",
             "lines": [l]} for n, l in hits]

def fixed_apr_unfunded(code):
    """Solvency risk: fixed APR/APY rewards paid in the staked token, with no reward funding function and no reward
    reserve accounting. Rewards are then paid out of other users' principal (ponzi-like). Conservative: requires all
    signals. 2026-10 experiment: staking_1_chat (missed by Slither/Aderyn)."""
    if not re.search(r"\b(APR|APY|annual\w*|SECONDS_PER_YEAR|YEAR_IN_SECONDS|365\s+days)\b", code, re.I): return []
    if not re.search(r"function\s+(stake|deposit)\w*\s*\(", code, re.I): return []
    if re.search(r"\brewardToken\b|\brewardsToken\b", code): return []          # separate reward token -> different analysis
    if re.search(r"function\s+\w*(fund|notifyReward|addReward|topUp|depositReward|replenish)\w*\s*\(", code, re.I): return []
    if re.search(r"\b(rewardReserve|rewardPool|rewardsAvailable|availableRewards|rewardBalance|totalRewardsFunded)\b", code, re.I): return []
    m = re.search(r"\b(APR|APY|annual\w*|SECONDS_PER_YEAR|YEAR_IN_SECONDS)\b", code, re.I)
    return [{"tool": "heuristic", "id": "solvency:fixed_apr_unfunded", "severity": "medium", "confidence": "heuristic",
             "title": "fixed_apr_unfunded",
             "detail": "Fixed APR/APY rewards are paid in the staked token, but there is no reward-funding function or reward reserve. Unless someone keeps topping it up, rewards are paid from other stakers' deposits and the last users to withdraw may be unable to. Check where rewards come from.",
             "lines": [code[:m.start()].count("\n") + 1]}]

def rug_heuristics(src):
    code = _strip_comments(src); out = owner_drain(code) + fixed_apr_unfunded(code)
    for rid, sev, pat, msg in RUG:
        if msg is None: continue
        ms = list(re.finditer(pat, code, re.I))
        if ms:
            lines = sorted({code[:m.start()].count("\n") + 1 for m in ms})[:10]
            out.append({"tool": "heuristic", "id": "rug:" + rid, "severity": sev, "confidence": "heuristic", "title": rid, "detail": msg, "lines": lines})
    # owner-only function that writes arbitrary balances (hidden mint / balance wipe)
    for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)[^{]*only\w+[^{]*\{([^}]*)\}", code):
        if re.search(r"_balances\s*\[", m.group(2)) and not m.group(1).lower().startswith("mint"):
            out.append({"tool": "heuristic", "id": "rug:balance_override", "severity": "high", "confidence": "heuristic", "title": "balance_override",
                        "detail": f"Privileged function `{m.group(1)}` directly edits balances.", "lines": [code[:m.start()].count("\n") + 1]})
    return out

# Slither detectors precise enough to justify do_not_deploy on their own (non-Low confidence).
# In the 2026-10 experiment uncorroborated highs were mostly FPs (4/7 Slither, 15/15 Aderyn), so other highs need
# corroboration from a second tool or a heuristic on overlapping lines.
PRECISE_SLITHER = {"reentrancy-eth", "arbitrary-send-eth", "suicidal", "controlled-delegatecall"}
BLOCKING_HEURISTICS = {"centralization:owner_can_take_user_funds"}

def _overlap(a, b):
    la, lb = set(a.get("lines") or []), set(b.get("lines") or [])
    return bool(la & lb) or any(abs(x - y) <= 3 for x in la for y in lb)

def assess(findings):
    """Return (verdict, confidence, reasons)."""
    highs = [f for f in findings if f["severity"] == "high"]
    reasons = []
    for f in highs:
        if f["tool"] == "slither" and f["id"] in PRECISE_SLITHER and f.get("confidence") != "Low":
            reasons.append(f"precise detector slither:{f['id']}")
        elif f["tool"] == "heuristic" and f["id"] in BLOCKING_HEURISTICS:
            reasons.append(f"centralization: owner can take user funds ({f['id']})")
        elif any(g is not f and g["tool"] != f["tool"] and _overlap(f, g) and g["severity"] in ("high", "medium") for g in findings):
            reasons.append(f"corroborated {f['tool']}:{f['id']}")
    rug_hi = [f for f in highs if f["tool"] == "heuristic" and f["id"].startswith("rug:")]
    if len(rug_hi) >= 2: reasons.append("multiple rug-pattern heuristics")
    if reasons: return "do_not_deploy", "high", sorted(set(reasons))
    if highs: return "fix_first", "low", ["uncorroborated high finding(s): " + ", ".join(sorted({f"{f['tool']}:{f['id']}" for f in highs}))]
    if any(f["severity"] == "medium" for f in findings): return "fix_first", "medium", ["medium finding(s)"]
    return "deployable", "medium", ["no high/medium findings from static analysis (not an audit)"]

def verdict(findings): return assess(findings)[0]

def scan(source: str):
    if not isinstance(source, str) or not source.strip(): raise ValueError("Empty source")
    if len(source.encode()) > 100_000: raise ValueError("Source too large (max 100 KB)")
    if "\x00" in source: raise ValueError("Binary data not allowed")
    if source.count("\n") + 1 > MAX_LINES: raise ValueError(f"Max {MAX_LINES} lines")
    if re.search(r'^\s*import\s', _strip_comments(source), re.M): raise ValueError("Single-file only: imports are not supported in the MVP (inline/flatten them)")
    ver = pick_solc(source)
    d = tempfile.mkdtemp(prefix="cscan-")
    try:
        os.chmod(d, 0o700); Path(d, "C.sol").write_text(source)
        sl, e1 = run_slither(d, ver)
        if e1 and e1.startswith("compile error"): return {"ok": False, "error": e1, "solc": ver}
        ad, e2 = run_aderyn(d, ver)
    finally: shutil.rmtree(d, True)
    if e1 and e2: return {"ok": False, "error": "Analysis tools failed; no verdict. " + e1[:300], "solc": ver}
    findings = sl + ad + rug_heuristics(source)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["tool"]))
    v, conf, reasons = assess(findings)
    return {"ok": True, "solc": ver, "sandbox": "bwrap(no-net,ro-root)+prlimit+timeout" if HAS_BWRAP else "timeout+prlimit",
            "tool_errors": [e for e in (e1, e2) if e], "findings": findings,
            "verdict": ("fix_first" if (e1 or e2) and v == "deployable" else v),  # partial tool failure never yields green
            "verdict_confidence": conf, "verdict_reasons": reasons}
