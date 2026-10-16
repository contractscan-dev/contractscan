"""AI second opinion: agreement filter, grounding (nonexistent/mismatched lines dropped), soft fail, verdict unchanged."""
import json, os, sys, pytest
sys.path.insert(0, os.path.dirname(__file__))
import second_opinion as SO, payments

SRC = "\n".join(["pragma solidity ^0.8.20;", "contract T {", "  mapping(address=>uint) public bal;",
                 "  function mint(uint a) external {", "    bal[msg.sender] += a;", "  }",
                 "  function pay() external {", "    payable(msg.sender).transfer(1);", "  }", "}"])
def I(line, code, fn, title, **k): return {"line": line, "code": code, "function": fn, "title": title, "severity": "high", "explain_en": title, "explain_zh": "z", **k}
MINT = I(4, "function mint(uint a) external {", "mint", "Unrestricted mint lets anyone credit balance")

class FakeHTTP:
    """Stands in for httpx: returns queued /chat/completions answers; balance from `bal`."""
    def __init__(self, answers, bal="29.5", fail=False): self.answers, self.bal, self.fail, self.calls = list(answers), bal, fail, 0
    def get(self, url, **k):
        class R: pass
        r = R(); r.json = lambda: {"is_available": True, "balance_infos": [{"currency": "CNY", "total_balance": self.bal}]}; return r
    def post(self, url, **k):
        self.calls += 1
        if self.fail: raise RuntimeError("boom")
        issues = self.answers.pop(0) if self.answers else []
        class R:
            def raise_for_status(s): pass
            def json(s): return {"choices": [{"message": {"content": json.dumps({"issues": issues})}}], "usage": {"prompt_tokens": 1000, "prompt_cache_hit_tokens": 0, "completion_tokens": 500}}
        return R()

@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(payments, "DB", str(tmp_path / "t.db")); monkeypatch.setattr(SO, "OPS_FLAGS", str(tmp_path / "ops.json"))
    SO._bal.update(t=0, v=None)

def test_agreement_filter_keeps_only_issues_in_both_runs():
    other = I(8, "payable(msg.sender).transfer(1);", "pay", "Reentrancy via transfer")
    out, st = SO.filter_issues([MINT, other], [dict(MINT, line=5, title="Anyone can mint unrestricted balance")], SRC)
    assert [i["line"] for i in out] == [4] and st["agreed"] == 1

def test_nonexistent_or_mismatched_lines_dropped():
    ghost = I(99, "function mint(uint a) external {", "mint", "x")                      # line does not exist
    wrong = I(8, "selfdestruct(owner);", "kill", "Unrestricted selfdestruct")         # line exists, code/function don't match
    out, st = SO.filter_issues([ghost, wrong], [ghost, wrong], SRC)
    assert out == [] and st["run1_grounded"] == 0
    assert SO.grounded(I(5, "bal[msg.sender] += a;", "", "t"), SRC.split("\n"))

def test_full_flow_ok_and_cost_logged():
    h = FakeHTTP([[MINT], [MINT]])
    r = SO.second_opinion(SRC, scan_id="abc", key="k", http=h)
    assert r["status"] == "ok" and r["issues"][0]["line"] == 4 and h.calls == 2 and r["label"]["zh"]
    assert payments.ai_spend_today() > 0

@pytest.mark.parametrize("kw,reason", [({"fail": True}, "error"), ({"bal": "1.0"}, "low_balance")])
def test_soft_fail(kw, reason):
    r = SO.second_opinion(SRC, scan_id="abc", key="k", http=FakeHTTP([], **kw))
    assert r["status"] == "omitted" and r["reason"] == reason and r["issues"] == [] and r["note"]["en"]
    if reason == "low_balance": assert json.load(open(SO.OPS_FLAGS))["deepseek_balance"]["state"] == "critical"

def test_no_key_and_budget_cap(monkeypatch):
    assert SO.second_opinion(SRC, key="")["reason"] == "not_configured"
    payments.log_ai_cost("x", "m", 0, 0, 0, SO.DAILY_USD + 1, "ok"); h = FakeHTTP([[MINT], [MINT]])
    assert SO.second_opinion(SRC, scan_id="y", key="k", http=h)["reason"] == "budget" and h.calls == 0

def test_verdict_unchanged_by_ai(monkeypatch):
    import app, asyncio
    fake = {"status": "ok", "issues": [I(4, "x", "mint", "AI says do not deploy", severity="high")], "label": SO.LABEL}
    monkeypatch.setattr(SO, "second_opinion", lambda src, sid=None: fake)
    src = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract A { function f() external pure returns (uint) { return 1; } }"
    raw, rep = asyncio.run(app._run(src, False, "0123456789abcdef", ai=True))
    raw2, rep2 = asyncio.run(app._run(src, False, None, ai=False))
    assert rep["verdict"] == rep2["verdict"] == raw["verdict"] and rep["ai_second_opinion"] is fake and "ai_second_opinion" not in rep2
