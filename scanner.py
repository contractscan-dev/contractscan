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
MAX_LINES, MAX_BYTES, TIMEOUT = 2000, 250_000, 120   # per tool; app.py caps a whole scan at 300 s
MEM_LIMIT = int(os.environ.get("CS_SCAN_MEM_BYTES", str(1536 * 1024**2)))  # per tool process (address space); VPS has 4 GB and runs 2 scans at once
VENDOR = Path(__file__).resolve().parent / "vendor"
OZ = {"4": VENDOR / "oz-4.9.6", "5": VENDOR / "oz-5.7.0"}   # pinned, vendored; no network at scan time
HAS_BWRAP = bool(shutil.which("bwrap"))

def _sandbox(cmd, workdir):
    lim = ["prlimit", f"--as={MEM_LIMIT}", "--fsize=67108864", "--nofile=1024", f"--cpu={TIMEOUT + 30}", "--"]
    if HAS_BWRAP:
        SVM_DIR.mkdir(parents=True, exist_ok=True)
        cmd = ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
               "--bind", workdir, workdir, "--ro-bind", str(SVM_DIR), str(SVM_DIR),
               "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--chdir", workdir] + lim + cmd
    else: cmd = lim + cmd
    return subprocess.run(["timeout", str(TIMEOUT)] + cmd, cwd=workdir, capture_output=True, text=True,
                          env={**os.environ, "VIRTUAL_ENV": str(VENV), "HOME": str(Path.home())})

def installed_solcs(solc_dir=None):
    return sorted([p.name.replace("solc-", "") for p in (solc_dir or SOLC_DIR).glob("solc-*")], key=lambda v: tuple(map(int, v.split("."))))

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

def pick_solc(src, solc_dir=None):
    """Only pre-installed (allow-listed) compilers are used; user pragmas never trigger downloads."""
    ms = re.findall(r"pragma\s+solidity\s+([^;]{1,60});", _strip_comments(src))
    if not ms: raise ValueError("No `pragma solidity` found")
    avail = installed_solcs(solc_dir)
    ok = [v for v in avail if all(_satisfies(v, m) for m in ms)]
    if not ok: raise ValueError(f"Unsupported compiler pragma `{ms[0].strip()[:40]}`. Supported solc versions: {', '.join(avail)}")
    return ok[-1]

def _prewarm_aderyn(ver):
    """Aderyn fetches solc via svm; warm the cache with a trivial stub (never user code) so the sandbox can stay offline."""
    if (SVM_DIR / ver).exists() or os.environ.get("CS_ALLOW_PREWARM") != "1": return   # production: pre-installed by scripts/prewarm_compilers.py
    d = tempfile.mkdtemp()
    Path(d, "W.sol").write_text(f"// SPDX-License-Identifier: MIT\npragma solidity {ver};\ncontract W{{}}\n")
    subprocess.run([ADERYN, d, "-o", f"{d}/o.json"], capture_output=True, timeout=120); shutil.rmtree(d, True)

SEV_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info", "Optimization": "info"}

def _is_user_file(sm):
    fn = sm.get("filename_short") or sm.get("filename_relative") or ""
    if not fn: return True   # old solc (<0.4.12-ish) emits no filenames; only C.sol is compiled then
    return fn.split("/")[-1] == "C.sol" and "vendor/oz-" not in (sm.get("filename_absolute") or "")

def run_slither(d, ver, solc_dir=None, oz=None):
    cmd = [SLITHER, "C.sol", "--solc", str((solc_dir or SOLC_DIR) / f"solc-{ver}" / f"solc-{ver}"), "--json", "s.json"]
    if oz: cmd += ["--solc-remaps", f"@openzeppelin/contracts/={oz}/", "--solc-args", f"--allow-paths {VENDOR}"]
    r = _sandbox(cmd, d)
    p = Path(d, "s.json")
    if not p.exists(): return [], f"slither failed: {(r.stderr or r.stdout)[-400:]}"
    j = json.loads(p.read_text())
    if not j.get("success"): return [], "compile error: " + str(j.get("error"))[-600:]
    out = []
    for x in j["results"].get("detectors", []):
        els = [e for e in x.get("elements", []) if _is_user_file(e.get("source_mapping", {}))]
        if not els: continue                                   # finding is entirely inside vendored OpenZeppelin code
        lines = sorted({l for e in els for l in e.get("source_mapping", {}).get("lines", [])})
        desc = x["description"].strip()
        out.append({"tool": "slither", "id": x["check"], "severity": SEV_MAP.get(x["impact"], "info"),
                    "confidence": x.get("confidence"), "title": x["check"], "detail": desc[:800], "lines": lines[:10],
                    "why": f"Slither detector `{x['check']}` (impact {x['impact']}, confidence {x.get('confidence')}) matched: " + desc.split("\n")[0][:300]})
    return out, None

# Aderyn detectors downgraded high -> low after our 2026-10 AI-Solidity experiment
# (experiments/ai-solidity-2026-10/review.csv: 24 DeepSeek-generated contracts, every finding manually triaged).
# Each produced ONLY false positives there (15/15 Aderyn highs were FPs). Findings stay visible as "low" so
# users can still review them, but they no longer drive the verdict.
ETH_OUT = re.compile(r"(safeTransferETH\s*\(|sendValue\s*\(|\.call\s*\{\s*value|\.transfer\s*\(|\.send\s*\()")
LOCKS_ETHER_REASON = "the source has an ETH transfer path Aderyn does not trace (imported OpenZeppelin base or a library/assembly send)."
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

def run_aderyn(d, ver, oz=None):
    _prewarm_aderyn(ver)
    if oz:
        Path(d, "lib").mkdir(exist_ok=True); os.symlink(oz, Path(d, "lib", "oz"))
        Path(d, "remappings.txt").write_text("@openzeppelin/contracts/=lib/oz/\n")
    r = _sandbox([ADERYN, ".", "-o", "a.json"], d)
    p = Path(d, "a.json")
    if not p.exists(): return [], f"aderyn failed: {(r.stderr or r.stdout)[-400:]}"
    j = json.loads(p.read_text()); out = []
    for key, sev in (("high_issues", "high"), ("low_issues", "low")):
        for x in j.get(key, {}).get("issues", []):
            inst = [i for i in x.get("instances", []) if str(i.get("contract_path", "C.sol")).split("/")[-1] == "C.sol"]
            if not inst: continue
            f = {"tool": "aderyn", "id": x["detector_name"], "severity": sev, "confidence": None, "title": x["title"],
                 "detail": x["description"][:800], "lines": [i["line_no"] for i in inst][:10],
                 "why": f"Aderyn detector `{x['detector_name']}` ({x['title']}) matched {len(inst)} place(s)."}
            if sev == "high" and f["id"] == "contract-locks-ether" and (oz or ETH_OUT.search(_strip_comments(Path(d, "C.sol").read_text()))):
                # Aderyn only looks at this file: ETH can still leave through an inherited OZ base (VestingWallet, Escrow)
                # or a library/assembly send it does not recognise (solmate SafeTransferLib). 5/5 false positives on the known-safe set.
                f.update(severity="low", confidence="downgraded", downgraded_from="high", downgrade_reason=LOCKS_ETHER_REASON)
                f["why"] += " Downgraded to low: " + LOCKS_ETHER_REASON
            elif sev == "high" and f["id"] in ADERYN_DOWNGRADE:
                f.update(severity="low", confidence="downgraded", downgraded_from="high", downgrade_reason=ADERYN_DOWNGRADE[f["id"]])
                f["why"] += " Downgraded to low: " + ADERYN_DOWNGRADE[f["id"]]
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

# ---------------- token-logic heuristics (added 2026-10 after the DeFiHackLabs replay) ----------------
# Each rule targets a root cause seen in real exploits and is validated against those contracts
# (tests/fixtures/hacks). Rules are deliberately narrow: they only fire on the specific shape of the bug.
def _line(code, off): return code[:off].count("\n") + 1
def _snip(code, off, n=110): return re.sub(r"\s+", " ", code[off:off + 300]).strip()[:n]
def _F(rid, sev, title, detail, why, lines):
    return {"tool": "heuristic", "id": rid, "severity": sev, "confidence": "heuristic", "title": title, "detail": detail, "why": why, "lines": lines[:10]}

GUARD = re.compile(r"(\bonly\w+|\brequiresAuth\b|\bauth\b|\b_checkOwner\s*\(|\b_checkRole\s*\(|hasRole\s*\(|require\s*\(\s*(msg\.sender|_msgSender\(\))\s*==|require\s*\(\s*\w+\s*==\s*(msg\.sender|_msgSender\(\))"
                   r"|if\s*\(\s*(msg\.sender|_msgSender\(\))\s*!=|isOwner\s*\(|authorized\[|onlyMinter|minters?\[\s*(msg\.sender|_msgSender\(\)))")
SELF = r"(msg\.sender|_msgSender\(\)|address\(this\))"
NFT = re.compile(r"\b(ERC721|ERC1155|ownerOf\s*\(|tokenURI\s*\(|_safeMint\s*\()")

def self_transfer_inflation(code):
    """LABUBU (2024-12): _transfer caches BOTH balances in locals, then writes the recipient from its stale local,
    so transfer(self, x) credits x without the debit sticking."""
    out = []
    for name, hdr, body, off in _functions(code):
        if not re.search(r"transfer", name, re.I): continue
        locs = dict((m.group(2), m.group(1)) for m in re.finditer(r"uint\d*\s+(\w+)\s*=\s*_balances\s*\[\s*(\w+)\s*\]", body))
        if len(locs) < 2: continue
        params = re.findall(r"address\s+(\w+)", hdr)
        if len(params) < 2: continue
        snd, rcv = params[0], params[1]
        if snd in locs and rcv in locs:
            taint = {locs[rcv]}
            for _ in range(3):   # follow simple derivations: uint x = f(recipientBalance)
                for dm in re.finditer(r"uint\d*\s+(\w+)\s*=\s*([^;]*);", body):
                    if any(re.search(r"\b" + t + r"\b", dm.group(2)) for t in taint): taint.add(dm.group(1))
            m = re.search(r"_balances\s*\[\s*" + rcv + r"\s*\]\s*=\s*[^;]*\b(" + "|".join(taint) + r")\b", body)
            if m and not re.search(r"require\s*\(\s*" + snd + r"\s*!=\s*" + rcv, body):
                out.append(_F("token:self_transfer_inflation", "high", "self_transfer_inflation",
                    f"`{name}` reads the sender and recipient balances into local variables first and then writes the recipient balance from its stale copy. "
                    "If sender == recipient, the debit is overwritten and the balance grows (self-transfer inflation).",
                    f"`{locs[snd]} = _balances[{snd}]` and `{locs[rcv]} = _balances[{rcv}]` are both cached, then `_balances[{rcv}]` is assigned from `{locs[rcv]}`; no `{snd} != {rcv}` check.",
                    [_line(code, off + m.start())]))
    return out

def unguarded_mint_burn(code):
    """Uerii (2022-10): public mint() anyone can call. APEMAGA (2024-06): public family(account) burns any account's balance."""
    out = []; fns = list(_functions(code)); is_nft = bool(NFT.search(code))
    # internal helpers that decrease the balance of one of their address parameters
    burners = {}
    for name, hdr, body, off in fns:
        if re.search(r"transfer", name, re.I): continue   # transfer helpers move balance, they do not destroy it
        ps = re.findall(r"address\s+(?:payable\s+)?(\w+)", hdr)
        for i, p_ in enumerate(ps):
            if re.search(r"_balances\s*\[\s*" + p_ + r"\s*\]\s*(-=|=\s*[^;]*-)", body) or re.search(r"\b_burn\s*\(\s*" + p_ + r"\b", body):
                burners.setdefault(name, set()).add(i)
    for name, hdr, body, off in fns:
        if not re.search(r"\b(public|external)\b", hdr) or re.search(r"\b(view|pure)\b", hdr) or GUARD.search(hdr) or GUARD.search(body): continue
        if re.search(r"^(transfer|transferFrom|_\w+|burn|approve|permit|increaseAllowance|decreaseAllowance)$", name): continue
        allowance = re.search(r"(_spendAllowance|allowance|_allowances\s*\[)", body)
        # --- unguarded mint (fungible): free supply for anyone
        mm = re.search(r"\b_mint\s*\(|\b_?totalSupply\s*\+=", body)
        if mm and not is_nft and "payable" not in hdr and "msg.value" not in body and not re.search(r"(transferFrom|safeTransferFrom|\.deposit\s*\{)", body):
            out.append(_F("token:unguarded_mint", "high", "unguarded_mint",
                f"Anyone can call `{name}()` to create new tokens: it mints without any access control, payment or deposit.",
                f"`{name}` is {'public' if 'public' in hdr else 'external'}, has no owner/role check, and calls `{_snip(body, mm.start(), 40)}`.",
                [_line(code, off)]))
            continue
        if allowance or is_nft or re.search(r"transfer", name, re.I): continue
        # --- unguarded burn / balance decrease of an arbitrary account
        hit = None
        bm = re.search(r"\b_burn\s*\(\s*(?!" + SELF + r")(\w+)", body)
        if bm: hit = f"`_burn({bm.group(2)}, ...)`"
        for callee, idxs in burners.items():
            cm = re.search(r"(?:super\.)?\b" + callee + r"\s*\(([^;]*)\)\s*;", body)
            if cm and callee != name:
                args = [a.strip() for a in cm.group(1).split(",")]
                if any(i < len(args) and not re.fullmatch(SELF, args[i]) for i in idxs): hit = f"`{_snip(body, cm.start(), 60)}` (which lowers that account's balance)"
        dm = re.search(r"_balances\s*\[\s*(?!" + SELF + r")(\w+)\s*\]\s*-=", body)
        if dm: hit = f"`_balances[{dm.group(2)}] -= ...`"
        if hit:
            out.append(_F("token:unguarded_burn", "high", "unguarded_burn_of_any_account",
                f"Anyone can call `{name}()` to destroy tokens held by another address (for example the liquidity pool) without approval.",
                f"`{name}` has no access control or allowance check and calls {hit} on a caller-chosen address.", [_line(code, off)]))
    return out

PAIR = r"\w*(?:[pP]air|[pP]ool|lpAddress|LP)\w*"
def pair_balance_manipulation(code):
    """FireToken (2024-10): sell path subtracts from _balances[pair] then calls pair.sync().
    Uwerx (2023-08): transfer to the pool credits the full amount and then burns extra from the sender."""
    out = []
    for name, hdr, body, off in _functions(code):
        if name == "constructor" or "constructor" in hdr[:12]: continue
        m = re.search(r"_balances\s*\[\s*(" + PAIR + r")\s*\]\s*(=\s*_balances\s*\[\s*\1\s*\]\s*(\.sub\(|-)|-=)", body)
        if m and re.search(r"\.sync\s*\(", code):
            out.append(_F("token:pair_balance_rewrite", "high", "pair_balance_rewrite",
                f"`{name}` lowers the AMM pair's token balance directly and the contract calls `sync()`. Anyone who triggers this path can shrink the pool's reserves and buy the other side cheaply.",
                f"`{_snip(body, m.start(), 70)}` writes the pair balance outside a normal transfer, and `.sync()` is called in this contract.",
                [_line(code, off + m.start())]))
            continue
        if not re.search(r"transfer", name, re.I): continue
        full = re.search(r"_balances\s*\[\s*(\w+)\s*\]\s*\+=\s*(amount|value|_amount|_value|wad)\s*;", body)
        if not full: continue
        rest = body[full.end():]
        cond = re.search(r"if\s*\(([^)]*" + PAIR + r"[^)]*)\)", rest)
        bm = re.search(r"\b_burn\s*\(\s*(from|sender|_from)\b", rest)
        if cond and bm and cond.start() < bm.start():
            out.append(_F("token:pair_transfer_extra_burn", "high", "pair_transfer_extra_burn",
                f"`{name}` credits the full amount and then, on transfers involving the pool, burns additional tokens from the sender. If the sender is the pool (e.g. via `skim`), its balance drops below its reserves.",
                f"Full credit `{_snip(body, full.start(), 40)}` is followed by a pool-conditioned `{_snip(rest, bm.start(), 40)}`.",
                [_line(code, off + full.end() + bm.start())]))
    return out

def price_includes_payment(code):
    """AIZPT (2024-10): buy() prices tokens with address(this).balance, which already includes msg.value."""
    out = []
    for name, hdr, body, off in _functions(code):
        if "msg.value" not in body: continue
        for m in re.finditer(r"[^;]*address\s*\(\s*this\s*\)\.balance[^;]*;", body):
            st = m.group(0)
            if re.search(r"[*/]", st) and not re.search(r"balance\s*(-|\.sub\()\s*(msg\.value|\w*[vV]alue)", st):
                if re.search(r"(require|if)\s*\(", st): continue
                out.append(_F("token:price_includes_payment", "medium", "price_includes_payment",
                    f"`{name}` uses the contract's ETH balance in a price/amount calculation while handling a payment. During a payable call `address(this).balance` already includes `msg.value`, so the price is computed on an inflated reserve.",
                    f"`{_snip(st, st.find('address'), 80)}` in a function that reads `msg.value`, without subtracting `msg.value`.",
                    [_line(code, off + m.start() + len(m.group(0)) - len(m.group(0).lstrip()))]))
                break
    return out

def token_logic(code):
    return self_transfer_inflation(code) + unguarded_mint_burn(code) + pair_balance_manipulation(code) + price_includes_payment(code)

def rug_heuristics(src):
    code = _strip_comments(src); out = owner_drain(code) + fixed_apr_unfunded(code) + token_logic(code)
    for rid, sev, pat, msg in RUG:
        if msg is None: continue
        ms = list(re.finditer(pat, code, re.I))
        if ms:
            lines = sorted({code[:m.start()].count("\n") + 1 for m in ms})[:10]
            out.append({"tool": "heuristic", "id": "rug:" + rid, "severity": sev, "confidence": "heuristic", "title": rid, "detail": msg, "lines": lines,
                        "why": f"Pattern `{rid}` matched at line {lines[0]}: `{_snip(code, ms[0].start(), 90)}`"})
    # owner-only function that writes arbitrary balances (hidden mint / balance wipe)
    for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)[^{]*only\w+[^{]*\{([^}]*)\}", code):
        if re.search(r"_balances\s*\[", m.group(2)) and not m.group(1).lower().startswith("mint"):
            out.append({"tool": "heuristic", "id": "rug:balance_override", "severity": "high", "confidence": "heuristic", "title": "balance_override",
                        "detail": f"Privileged function `{m.group(1)}` directly edits balances.", "lines": [code[:m.start()].count("\n") + 1],
                        "why": f"Function `{m.group(1)}` has an only* modifier and writes `_balances[...]`."})
    for f in out: f.setdefault("why", f"Heuristic `{f['id']}` matched at line(s) {', '.join(map(str, f['lines'][:5]))}: {f['detail'][:200]}")
    return out

# Slither detectors precise enough to justify do_not_deploy on their own (non-Low confidence).
# In the 2026-10 experiment uncorroborated highs were mostly FPs (4/7 Slither, 15/15 Aderyn), so other highs need
# corroboration from a second tool or a heuristic on overlapping lines.
PRECISE_SLITHER = {"reentrancy-eth", "arbitrary-send-eth", "suicidal", "controlled-delegatecall"}
BLOCKING_HEURISTICS = {"centralization:owner_can_take_user_funds", "token:unguarded_mint", "token:unguarded_burn", "token:self_transfer_inflation"}

def _overlap(a, b):
    la, lb = set(a.get("lines") or []), set(b.get("lines") or [])
    return bool(la & lb) or any(abs(x - y) <= 3 for x in la for y in lb)

BLOCK_LABEL = {"centralization:owner_can_take_user_funds": "centralization: owner can take user funds (centralization:owner_can_take_user_funds)",
               "token:unguarded_mint": "anyone can mint tokens (token:unguarded_mint)",
               "token:unguarded_burn": "anyone can burn another account's tokens (token:unguarded_burn)",
               "token:self_transfer_inflation": "self-transfer inflates balance (token:self_transfer_inflation)"}
def assess(findings):
    """Return (verdict, confidence, reasons)."""
    highs = [f for f in findings if f["severity"] == "high"]
    reasons = []
    for f in highs:
        if f["tool"] == "slither" and f["id"] in PRECISE_SLITHER and f.get("confidence") != "Low":
            reasons.append(f"precise detector slither:{f['id']}")
        elif f["tool"] == "heuristic" and f["id"] in BLOCKING_HEURISTICS:
            reasons.append(BLOCK_LABEL.get(f["id"], f"blocking heuristic {f['id']}"))
        elif any(g is not f and g["tool"] != f["tool"] and _overlap(f, g) and g["severity"] in ("high", "medium") for g in findings):
            reasons.append(f"corroborated {f['tool']}:{f['id']}")
    rug_hi = [f for f in highs if f["tool"] == "heuristic" and f["id"].startswith("rug:")]
    if len(rug_hi) >= 2: reasons.append("multiple rug-pattern heuristics")
    if reasons: return "do_not_deploy", "high", sorted(set(reasons))
    if highs: return "fix_first", "low", ["uncorroborated high finding(s): " + ", ".join(sorted({f"{f['tool']}:{f['id']}" for f in highs}))]
    if any(f["severity"] == "medium" for f in findings): return "fix_first", "medium", ["medium finding(s)"]
    return "deployable", "medium", ["no high/medium findings from static analysis (not an audit)"]

def verdict(findings): return assess(findings)[0]

IMPORT_RE = re.compile(r'^\s*import\s+(?:[^;"\']*?\s+from\s+)?["\']([^"\']+)["\']\s*;', re.M)
IMPORT_ANY = re.compile(r'\bimport\s+(?:[^;"\']*?\s+from\s+)?["\']([^"\']*)["\']')
OZ_IMPORT = re.compile(r"^@openzeppelin/contracts(?:@(\d+)(?:\.[\w.-]*)?)?/")
def prepare_imports(source):
    """Only OpenZeppelin Contracts imports are allowed; they resolve to the pinned vendored copy (no network).
    Returns (source with `@openzeppelin/contracts@x.y/` rewritten in place, requested major or None, uses_oz)."""
    code = _strip_comments(source); majors = set(); uses = False
    # Check the comment-stripped code AND the raw text: the comment stripper is not string-aware, so
    # `import "https://..."` would otherwise lose its `//...` tail and slip past. Raw-text hits in real comments are
    # skipped only when `//` precedes `import` on the same line.
    raw = [m for m in IMPORT_ANY.finditer(source) if "//" not in source[source.rfind("\n", 0, m.start()) + 1:m.start()]]
    if len(IMPORT_ANY.findall(code)) and not raw: raise ValueError("Unparseable import statement")
    for m in list(IMPORT_RE.finditer(code)) + raw:
        path = m.group(1); o = OZ_IMPORT.match(path)
        if o and re.search(r"\.\.|//|\\", path[len(o.group(0)):]): o = None   # no traversal out of the vendored tree
        if not o: raise ValueError(f"Unsupported import `{path[:80]}`. Only @openzeppelin/contracts imports (v4.9 / v5) are supported; flatten other imports into one file.")
        uses = True
        if o.group(1): majors.add(o.group(1))
    if len(majors) > 1: raise ValueError("Mixed OpenZeppelin major versions in imports")
    major = majors.pop() if majors else None
    if major and major not in OZ: raise ValueError(f"OpenZeppelin v{major} is not supported (supported: 4.9, 5.x)")
    return re.sub(r"@openzeppelin/contracts@[\w.-]+/", "@openzeppelin/contracts/", source), major, uses

def scan(source: str, force_ver=None, solc_dir=None):
    """force_ver/solc_dir are for offline benchmarks only (old compilers); production always uses pick_solc."""
    if not isinstance(source, str) or not source.strip(): raise ValueError("Empty source")
    if len(source.encode()) > MAX_BYTES: raise ValueError(f"Source too large (max {MAX_BYTES // 1000} KB)")
    if "\x00" in source: raise ValueError("Binary data not allowed")
    if source.count("\n") + 1 > MAX_LINES: raise ValueError(f"Max {MAX_LINES} lines")
    source, major, uses_oz = prepare_imports(source)
    ver = force_ver or pick_solc(source, solc_dir)
    tries = [None]
    if uses_oz:
        paths = re.findall(r"@openzeppelin/contracts/([\w./-]+\.sol)", source)
        fits = [o for o in ("5", "4") if all((OZ[o] / p).is_file() for p in paths)]
        if major: tries = [major]
        elif not fits: raise ValueError("Imported OpenZeppelin file(s) not found in v4.9 or v5.x: " + ", ".join(p for p in paths if not any((OZ[o] / p).is_file() for o in OZ))[:200])
        else:
            pref = "5" if _v(ver) >= (0, 8, 20) else "4"
            tries = sorted(fits, key=lambda o: o != pref)
    for i, om in enumerate(tries):
        oz = str(OZ[om]) if om else None
        d = tempfile.mkdtemp(prefix="cscan-")
        try:
            os.chmod(d, 0o700); Path(d, "C.sol").write_text(source)
            sl, e1 = run_slither(d, ver, solc_dir, oz)
            if e1 and (e1.startswith("compile error") or "C.sol:" in e1 or "InvalidCompilation" in e1):
                if i + 1 < len(tries): continue
                return {"ok": False, "error": e1, "solc": ver}
            ad, e2 = run_aderyn(d, ver, oz)
        finally: shutil.rmtree(d, True)
        break
    if e1 and e2: return {"ok": False, "error": "Analysis tools failed; no verdict. " + e1[:300], "solc": ver}
    findings = sl + ad + rug_heuristics(source)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["tool"]))
    v, conf, reasons = assess(findings)
    return {"ok": True, "solc": ver, "openzeppelin": (OZ[om].name.replace("oz-", "") if om else None),
            "sandbox": "bwrap(no-net,ro-root)+prlimit+timeout" if HAS_BWRAP else "timeout+prlimit",
            "tool_errors": [e for e in (e1, e2) if e], "findings": findings,
            "verdict": ("fix_first" if (e1 or e2) and v == "deployable" else v),  # partial tool failure never yields green
            "verdict_confidence": conf, "verdict_reasons": reasons, "not_analyzed": NOT_ANALYZED}

NOT_ANALYZED = [
    "Business logic: whether the contract does what you intend (reward maths, fee flows, game rules) is not verified.",
    "Price / oracle manipulation and flash-loan attacks against AMM or token pricing.",
    "Cross-contract and external-protocol interactions (other contracts, proxies, unverified dependencies, deployment config).",
    "Economic and MEV risks (sandwiching, front-running, liquidity draining), and solvency over time.",
    "Off-chain risks: key management, admin operations, front-end and signing flows.",
]
