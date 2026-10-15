"""Minimal MCP stdio server exposing scan_contract, with a per-caller daily rate limit (sqlite, survives restarts)."""
import json, os
from mcp.server.fastmcp import FastMCP, Context
import app as _cfg  # loads config.env
from scanner import scan
from explain import build_report
import payments
mcp = FastMCP("contractscan")
PER_DAY = int(os.environ.get("CS_MCP_PER_DAY", "3"))

def _caller(ctx):
    # caller id = explicit CS_MCP_CALLER env (set per agent install) else MCP clientInfo name/version
    if os.environ.get("CS_MCP_CALLER"): return "env:" + os.environ["CS_MCP_CALLER"]
    try:
        ci = ctx.session.client_params.clientInfo; return f"client:{ci.name}/{ci.version}"
    except Exception: return "client:unknown"

@mcp.tool()
def scan_contract(source: str, ctx: Context) -> str:
    """Static-analyze a single-file Solidity contract (<=500 lines) with Slither+Aderyn+rug heuristics.
    Returns JSON with verdict (deployable|fix_first|do_not_deploy) and plain-language findings. NOT an audit. Free: limited calls/day."""
    caller = _caller(ctx)
    ok, left = payments.mcp_allow(caller, PER_DAY)
    if not ok: return json.dumps({"ok": False, "error": "rate_limited", "message": f"Free MCP limit {PER_DAY}/day for {caller}. Use x402 at POST /api/x402/scan."})
    try: r = build_report(scan(source), source); r["mcp_remaining_today"] = left; r["caller"] = caller; return json.dumps(r, ensure_ascii=False)
    except ValueError as e: return json.dumps({"ok": False, "error": str(e)})

if __name__ == "__main__": mcp.run()
