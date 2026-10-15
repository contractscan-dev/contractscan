"""Regression tests from the 2026-10 AI-Solidity experiment (experiments/ai-solidity-2026-10/review.csv).
Fixtures are DeepSeek-generated contracts, unmodified."""
import shutil, pytest
from pathlib import Path
import scanner as S

FX = Path(__file__).parent / "fixtures" / "ai2026_10"
def src(n): return (FX / f"{n}.sol").read_text()
def heur(n): return {f["id"] for f in S.rug_heuristics(src(n))}

# ---- (4) fee-change heuristic ----
def test_fee_change_not_fired_by_exclusion_setter():
    assert "rug:fee_change" not in heur("erc20_tax_1_chat")          # only has setExcludedFromTax
def test_fee_change_still_fires_on_real_setter():
    assert "rug:fee_change" in heur("erc20_tax_2_chat")              # setTaxes(buy, sell)
@pytest.mark.parametrize("name,hit", [("setTaxExempt", False), ("setFeeRecipient", False), ("setExcludedFromFees", False),
                                      ("setFees", True), ("setSellTax", True), ("setBuyFeeBps", True)])
def test_fee_setter_names(name, hit):
    code = f"contract C {{ function {name}(uint256 x) external onlyOwner {{ }} }}"
    assert ("rug:fee_change" in {f["id"] for f in S.rug_heuristics(code)}) == hit

# ---- (3) owner can take user funds ----
def test_emergency_withdraw_of_user_deposits_is_blocking():
    assert "centralization:owner_can_take_user_funds" in heur("eth_vault_3_chat")
def test_nft_proceeds_withdraw_not_user_funds():
    assert "centralization:owner_can_take_user_funds" not in heur("nft_allowlist_2_chat")
def test_escrow_arbiter_and_bounded_withdraws_not_flagged():
    for n in ("eth_vault_2_chat", "staking_1_reasoner", "staking_2_chat"):
        assert "centralization:owner_can_take_user_funds" not in heur(n), n
def test_timelocked_drain_not_flagged():
    code = """contract V { mapping(address=>uint) d; uint public eta; function deposit() external payable { d[msg.sender]+=msg.value; }
      function emergencyWithdraw() external onlyOwner { require(eta != 0 && block.timestamp >= eta, "timelock");
        payable(msg.sender).transfer(address(this).balance); } }"""
    assert not S.owner_drain(code)

# ---- (5) fixed APR, unfunded ----
def test_fixed_apr_unfunded_flagged_medium():
    f = [x for x in S.rug_heuristics(src("staking_1_chat")) if x["id"] == "solvency:fixed_apr_unfunded"]
    assert f and f[0]["severity"] == "medium"
def test_fixed_apr_with_funding_not_flagged():
    assert "solvency:fixed_apr_unfunded" not in heur("staking_1_reasoner")   # has fundRewards + rewardReserve

# ---- (1) verdict logic ----
def F(tool, id, sev="high", lines=(10,), conf="Medium"): return {"tool": tool, "id": id, "severity": sev, "confidence": conf, "lines": list(lines)}
def test_single_uncorroborated_high_is_fix_first_low():
    assert S.assess([F("slither", "encode-packed-collision")])[:2] == ("fix_first", "low")
    assert S.assess([F("slither", "reentrancy-balance")])[:2] == ("fix_first", "low")
def test_precise_detector_alone_blocks():
    for d in ("reentrancy-eth", "arbitrary-send-eth", "suicidal", "controlled-delegatecall"):
        assert S.assess([F("slither", d)])[0] == "do_not_deploy"
    assert S.assess([F("slither", "reentrancy-eth", conf="Low")])[0] == "fix_first"
def test_corroborated_high_blocks():
    assert S.assess([F("aderyn", "x", lines=[50]), F("slither", "y", sev="medium", lines=[51])])[0] == "do_not_deploy"
def test_downgraded_aderyn_does_not_corroborate():
    assert S.assess([F("slither", "encode-packed-collision", lines=[20]), F("aderyn", "abi-encode-packed-hash-collision", sev="low", lines=[20])])[0] == "fix_first"
def test_owner_drain_blocks():
    assert S.assess([F("heuristic", "centralization:owner_can_take_user_funds", conf="heuristic")])[0] == "do_not_deploy"

# ---- end-to-end (needs slither/aderyn/solc on the box) ----
TOOLS = shutil.which("aderyn") or Path.home().joinpath(".local/bin/aderyn").exists()
@pytest.mark.skipif(not TOOLS or not S.installed_solcs(), reason="analysis tools not installed")
@pytest.mark.parametrize("name,expected", [("dex_launcher_1_chat", "do_not_deploy"),   # real reentrancy-eth
                                           ("eth_vault_3_chat", "do_not_deploy"),      # owner takes deposits
                                           ("dex_launcher_1_reasoner", "do_not_deploy"),   # bundled token has an unguarded external mint() (token:unguarded_mint, true positive)
                                           ("nft_allowlist_1_chat", "fix_first"),      # FP encode-packed on tokenURI
                                           ("erc20_tax_1_chat", "deployable")])        # fee_change misfire fixed
def test_experiment_verdicts(name, expected):
    r = S.scan(src(name)); assert r["ok"] and r["verdict"] == expected, r.get("verdict_reasons")
