"""Coverage (imports, limits, compilers), token-logic heuristics, `why` on findings, not_analyzed list."""
import pathlib, pytest, scanner as S
FX = pathlib.Path(__file__).parent / "fixtures"
def H(name): return S.token_logic(S._strip_comments((FX / "hacks" / f"{name}.sol").read_text()))
def ids(fs): return {f["id"] for f in fs}

@pytest.mark.parametrize("name,rid,line", [
    ("LABUBUToken", "token:self_transfer_inflation", 131), ("APEMAGA", "token:unguarded_burn", 249),
    ("UeriiToken", "token:unguarded_mint", 489), ("FireToken", "token:pair_balance_rewrite", 269),
    ("Uwerx", "token:pair_transfer_extra_burn", 494), ("AIZPTToken", "token:price_includes_payment", 170)])
def test_hack_root_cause(name, rid, line):
    fs = [f for f in H(name) if f["id"] == rid]
    assert fs and line in fs[0]["lines"] and fs[0]["why"]

def test_blocking():
    for n, rid in (("UeriiToken", "token:unguarded_mint"), ("APEMAGA", "token:unguarded_burn"), ("LABUBUToken", "token:self_transfer_inflation")):
        assert S.assess([f for f in H(n) if f["id"] == rid])[0] == "do_not_deploy"

def test_safe_set_no_token_logic_hits():
    for p in sorted((FX / "safe").glob("*.sol")):
        assert not S.token_logic(S._strip_comments(p.read_text())), p.name

MINT = """pragma solidity ^0.8.20;
contract T { mapping(address=>uint) public balanceOf; uint public totalSupply; address owner = msg.sender;
 function _mint(address a, uint v) internal { totalSupply += v; balanceOf[a] += v; }
 function mint(address a, uint v) external %s { _mint(a, v); } }"""
def test_mint_guard_variants():
    assert "token:unguarded_mint" in ids(S.token_logic(MINT % ""))
    assert not S.token_logic((MINT % "").replace("{ _mint(a, v); }", "{ require(msg.sender == owner); _mint(a, v); }"))
    assert not S.token_logic(MINT % "payable")

def test_burn_self_ok():
    src = "pragma solidity ^0.8.20; contract T { mapping(address=>uint) _balances; function _burn(address a, uint v) internal { _balances[a] -= v; }\n function burn(uint v) external { _burn(msg.sender, v); }\n function burnOf(address a, uint v) external { _burn(a, v); } }"
    fs = S.token_logic(src); assert [f["lines"][0] for f in fs if f["id"] == "token:unguarded_burn"] == [3]

def test_prepare_imports():
    s, m, u = S.prepare_imports('import "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";\ncontract A {}')
    assert m == "4" and u and "@openzeppelin/contracts/token" in s
    with pytest.raises(ValueError): S.prepare_imports('import "./Other.sol";\ncontract A {}')
    with pytest.raises(ValueError): S.prepare_imports('import "https://x/y.sol";\ncontract A {}')

def test_limits():
    assert S.MAX_LINES == 2000
    with pytest.raises(ValueError): S.scan("pragma solidity ^0.8.20;\n" + "\n" * 2001 + "contract A {}")

def test_compilers_and_vendor():
    vs = S.installed_solcs()
    assert "0.8.0" in vs and "0.8.30" in vs
    assert (S.OZ["4"] / "token/ERC20/ERC20.sol").is_file() and (S.OZ["5"] / "token/ERC20/ERC20.sol").is_file()

@pytest.mark.parametrize("name,oz", [("oz5_erc20_full", "5.7.0"), ("oz4_erc721", "4.9.6")])
def test_oz_import_scan(name, oz):
    r = S.scan((FX / "safe" / f"{name}.sol").read_text())
    assert r["ok"] and r["openzeppelin"] == oz and not r["tool_errors"], r.get("error") or r.get("tool_errors")
    assert r["verdict"] != "do_not_deploy" and len(r["not_analyzed"]) >= 3
    assert all(f.get("why") for f in r["findings"])

def test_uerii_full_scan_blocks():
    r = S.scan((FX / "hacks" / "UeriiToken.sol").read_text())
    assert r["ok"] and r["verdict"] == "do_not_deploy" and any("unguarded_mint" in x for x in r["verdict_reasons"])
