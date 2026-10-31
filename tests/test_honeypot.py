#!/usr/bin/env python3
"""Offline regression tests for core.checks.honeypot (no network).

    ./venv/bin/python tests/test_honeypot.py

Uses hand-built contract profiles that mirror real SunPump/BEP-20 honeypot layouts.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.checks.honeypot import analyze_contract_risk  # noqa: E402

OWNER = "41" + "11" * 20
ZERO_ADDR = "41" + "00" * 20


def fn(name, selector, inputs=(), mut="nonpayable", outputs=()):
    ins = [{"name": f"a{i}", "type": t} for i, t in enumerate(inputs)]
    outs = [{"name": f"r{i}", "type": t} for i, t in enumerate(outputs)]
    sig = f"{name}({','.join(inputs)})"
    return {
        "name": name,
        "selector": selector,
        "state_mutability": mut,
        "constant": mut in ("view", "pure"),
        "payable": mut == "payable",
        "signature": sig,
        "inputs": ins,
        "outputs": outs,
    }


def profile(functions, bytecode="6080604052", name="Token"):
    abi = [{"type": "Function", "name": f["name"], "inputs": f["inputs"],
            "outputs": f["outputs"], "stateMutability": f["state_mutability"]} for f in functions]
    return {
        "address": "TEST",
        "name": name,
        "is_contract": True,
        "has_code": True,
        "bytecode": bytecode,
        "bytecode_bytes": len(bytecode) // 2,
        "abi": abi,
        "functions": functions,
        "events": [],
        "constructor": None,
        "resource": {},
        "warnings": [],
    }


BASE_TRC20 = [
    fn("transfer", "a9059cbb", ("address", "uint256"), outputs=("bool",)),
    fn("transferFrom", "23b872dd", ("address", "address", "uint256"), outputs=("bool",)),
    fn("approve", "095ea7b3", ("address", "uint256"), outputs=("bool",)),
    fn("balanceOf", "70a08231", ("address",), mut="view", outputs=("uint256",)),
    fn("totalSupply", "18160ddd", mut="view", outputs=("uint256",)),
    fn("owner", "8da5cb5b", mut="view", outputs=("address",)),
]


def test_clean_stable_token():
    r = analyze_contract_risk(profile(BASE_TRC20))
    assert r["level"] == "LOW", r
    assert r["score"] == 0 and not r["flags"], r


def test_sunpump_style_honeypot():
    """enableTrading switch + mint + blacklist + sell tax only owner can raise."""
    funcs = BASE_TRC20 + [
        fn("addToBlackList", "443dc312", ("address", "bool")),
        fn("mint", "a0712d68", ("uint256",)),
        fn("setSellTax", "6a1b0f6b", ("uint256",)),
        fn("setBuyTax", "1a5b9d89", ("uint256",)),
        fn("enableTrading", "9a3f2e01", ("bool",)),
        fn("setMarketingWallet", "b6c1a002", ("address",)),
        fn("sellTax", "c0ffee01", mut="view", outputs=("uint256",)),
        fn("buyTax", "c0ffee02", mut="view", outputs=("uint256",)),
    ]
    bc = "7f6d696e740000000000000000000000000000000000000000000000000000000000" + "e803"
    r = analyze_contract_risk(profile(funcs, bytecode=bc))
    ids = {f["id"] for f in r["flags"]}
    assert r["level"] == "HIGH", r
    assert {"HP-001", "HP-002", "HP-010", "HP-020"} <= ids, ids
    hp001 = next(f for f in r["flags"] if f["id"] == "HP-001")
    names = {x["name"] for x in hp001["evidence"]["switches"]} | {x["name"] for x in hp001["evidence"]["operators"]}
    assert "enableTrading" in names, names
    assert any(f["id"] == "HP-001" and f["severity"] == "critical" for f in r["flags"])
    assert r["is_honeypot_suspected"] is True


def test_pause_switch_is_hard_block():
    funcs = BASE_TRC20 + [fn("pause", "8456cb59"), fn("unpause", "3f4ba83a")]
    r = analyze_contract_risk(profile(funcs))
    assert r["level"] == "HIGH", r            # hard block even with a single flag
    assert r["flags"][0]["id"] == "HP-001"


def test_unverified_contract_without_abi():
    r = analyze_contract_risk(profile([], bytecode="6080604052" + "00" * 200))
    assert "HP-030" in {f["id"] for f in r["flags"]}, r
    assert r["level"] == "HIGH", r


def test_missing_transfer_surface():
    """Token-ish ABI (supply/balance) that ships buy/sell but no TRC-20 transfer."""
    funcs = [
        fn("totalSupply", "18160ddd", mut="view", outputs=("uint256",)),
        fn("balanceOf", "70a08231", ("address",), mut="view", outputs=("uint256",)),
        fn("buy", "d96a094a", ("uint256",)),
        fn("sell", "e4849b32", ("uint256",)),
    ]
    r = analyze_contract_risk(profile(funcs))
    assert "HP-040" in {f["id"] for f in r["flags"]}, r


def test_real_usdt_fixture_regression():
    """Tether profile: LOW-weight pause, but blacklist/destroy/mint keep it HIGH."""
    fx = ROOT / "tests" / "fixtures" / "usdt.json"
    if not fx.exists():
        print("  (skipped: no fixture)")
        return
    r = analyze_contract_risk(json.loads(fx.read_text()))
    assert r["level"] == "HIGH", r["level"]
    hp001 = next(f for f in r["flags"] if f["id"] == "HP-001")
    assert hp001["severity"] == "low", hp001


def test_payout_contract_pause():
    """Non-token contract that custodies value: owner pause on withdrawals is still HP-001."""
    funcs = [fn("deposit", "d0e30db0", mut="payable"), fn("withdrawAll", "c0ffee01"),
             fn("pause", "8456cb59")]
    r = analyze_contract_risk(profile(funcs, name="Payout"))
    assert r["level"] == "HIGH", r
    assert r["flags"][0]["id"] == "HP-001" and r["flags"][0]["severity"] == "critical"


def test_launchpad_template():
    funcs = BASE_TRC20 + [fn("swapAndLiquify", "c0ffee77", ("uint256",)),
                          fn("setTax", "c0ffee78", ("uint256",)),
                          fn("maxWallet", "c0ffee79", mut="view", outputs=("uint256",))]
    r = analyze_contract_risk(profile(funcs, name="MEME"))
    ids = {f["id"] for f in r["flags"]}
    assert "HP-034" in ids and "HP-012" in ids, ids
    assert r["level"] == "LOW", r   # nudges the analyst, does not accuse


def test_bad_input():
    try:
        analyze_contract_risk([])  # type: ignore[arg-type]
    except TypeError:
        return
    raise AssertionError("expected TypeError")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    failed = 0
    for t in TESTS:
        try:
            t()
            print(f"[ok]   {t.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"[FAIL] {t.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[ERR]  {t.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(TESTS) - failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
