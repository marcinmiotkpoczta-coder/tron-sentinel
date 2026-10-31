#!/usr/bin/env python3
"""TRON honeypot detector - MVP CLI.

    python main.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
    python main.py <address> --json
    python main.py --check-node
    python main.py <address> --no-risk          # skip the rule engine

Exit codes: 0 ok, 2 bad usage/address, 3 address is not a contract,
4 node unreachable/timeout, 5 node returned an error payload, 6 risk HIGH.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from tvm_analyzer import TVMBytecodeAnalyzer
from core.checks import analyze_contract_risk
from core.node_connector import (
    InvalidAddressError,
    NodeConnectorError,
    NodeResponseError,
    NodeTimeoutError,
    NodeUnavailableError,
    NotAContractError,
    check_node,
    get_contract_info,
)

USDT_TRC20 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
# Known TronScan-verified contracts for smoke tests.
CONTRACTS = {
    "USDT": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",   # TRC-20, no proxy
    "WTRX": "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",   # TRC-20 wrapper of TRX
}

EXIT_RISK_HIGH = 6

EXIT_CODES = {
    InvalidAddressError: 2,
    NotAContractError: 3,
    NodeTimeoutError: 4,
    NodeUnavailableError: 4,
    NodeResponseError: 5,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tron-honeypot-detector",
        description="Fetch raw TRON contract data (ABI, bytecode, functions).",
    )
    p.add_argument("address", nargs="?", help="TRON contract address (base58check, e.g. TR7N...)")
    p.add_argument("--json", action="store_true", help="dump full raw JSON (large: includes bytecode)")
    p.add_argument("--check-node", action="store_true", help="only ping the node and print latency/latest block")
    p.add_argument("--no-risk", action="store_true", help="skip the honeypot rule engine")
    p.add_argument("--demo", action="store_true",
                   help="run the rule engine on a synthetic SunPump-style honeypot (no network)")
    p.add_argument("--fail-on-high", action="store_true",
                   help="exit 6 when the risk level is HIGH (for CI / batch scanning)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging (HTTP details)")
    p.add_argument("--self-test", action="store_true",
                   help="run built-in checks: valid contract, EOA, malformed address, bad host")
    return p


def render_human(info: dict) -> str:
    lines = [
        f"address      : {info['address']}",
        f"hex          : {info['hex_address']}",
        f"endpoint     : {info['node']['endpoint']}  (api key: {'yes' if info['node']['api_key_used'] else 'no'})",
        f"is contract  : {info['is_contract']}  (code: {info['has_code']}, {info['bytecode_bytes']} bytes)",
        f"ABI entries  : {len(info['abi'])}",
        f"functions    : {len(info['functions'])}",
        "",
        "  constant  payable  selector    name",
        "  --------  -------  ----------  ----",
    ]
    for fn in info["functions"][:40]:
        lines.append(
            "  {:<8}  {:<7}  {:<10}  {}".format(
                "yes" if fn["constant"] else "no",
                "yes" if fn["payable"] else "no",
                str(fn["selector"] or "-"),
                fn["name"],
            )
        )
    if len(info["functions"]) > 40:
        lines.append(f"  ... {len(info['functions']) - 40} more")
    if info["events"]:
        lines.append("")
        lines.append("events       : " + ", ".join(e["name"] or "-" for e in info["events"]))
    res = info.get("resource") or {}
    if res:
        lines.append(
            "resource     : energy_limit={} energy_used={} net_limit={}".format(
                res.get("EnergyLimit", "?"), res.get("EnergyUsed", "?"), res.get("freeNetLimit", "?")
            )
        )
    if info["warnings"]:
        lines.append("")
        lines.append("warnings:")
        lines.extend(f"  - {w}" for w in info["warnings"])
    return "\n".join(lines)


def render_risk(risk: dict) -> str:
    """Human-readable risk block: verdict first, then evidence per flag."""
    level = risk["level"]
    lines = [
        "",
        "RISK REPORT",
        "-----------",
        f"verdict      : {level}  (score {risk['score']}/100, static confidence {risk['confidence']:.2f})",
        f"honeypot?    : {'SUSPECTED' if risk['is_honeypot_suspected'] else 'not indicated'}",
        f"scanned      : {', '.join(k for k, v in risk['checks'].items() if v == 'flagged') or 'nothing'}",
        "",
    ]
    if not risk["flags"]:
        lines.append("  no known honeypot pattern matched the ABI/bytecode profile")
    for i, flag in enumerate(risk["flags"], 1):
        lines.append(f"  {i}. [{flag['severity'].upper():8}] {flag['id']}  {flag['title']}")
        args = flag["evidence"]
        for key in ("switches", "tax_gates", "operators", "entries", "setters", "mint_functions",
                    "minter_gate", "accessors", "functions", "no_amount_parameter"):
            items = args.get(key) or []
            if not items:
                continue
            if isinstance(items[0], dict):
                shown = ", ".join(f"{x.get('name')}{x.get('signature', '')[len(x.get('name') or ''):]}"
                                  for x in items[:6])
            else:
                shown = ", ".join(str(x) for x in items[:6])
            more = f" (+{len(items) - 6} more)" if len(items) > 6 else ""
            lines.append(f"        {key}: {shown}{more}")
        for key in ("note", "downgraded_because", "check"):
            if args.get(key):
                lines.append(f"        {key}: {args[key]}")
    lines += ["", "not covered by static analysis:"]
    lines += [f"  - {c}" for c in risk["coverage"]["not_covered"]]
    return "\n".join(lines)


DEMO_HONEYPOT = """Demonstration profile: a SunPump-style token whose owner can freeze trading,
blacklist wallets, raise the sell tax to any value and mint new supply."""


def demo() -> dict:
    """Offline synthetic contract (no network) so the rule engine can be shown end-to-end."""

    def f(name, selector, inputs=(), mut="nonpayable", outputs=()):
        return {
            "name": name, "selector": selector, "state_mutability": mut,
            "constant": mut in ("view", "pure"), "payable": mut == "payable",
            "signature": f"{name}({','.join(inputs)})",
            "inputs": [{"name": f"a{i}", "type": t} for i, t in enumerate(inputs)],
            "outputs": [{"name": f"r{i}", "type": t} for i, t in enumerate(outputs)],
        }

    functions = [
        f("transfer", "a9059cbb", ("address", "uint256"), outputs=("bool",)),
        f("transferFrom", "23b872dd", ("address", "address", "uint256"), outputs=("bool",)),
        f("balanceOf", "70a08231", ("address",), mut="view", outputs=("uint256",)),
        f("totalSupply", "18160ddd", mut="view", outputs=("uint256",)),
        f("owner", "8da5cb5b", mut="view", outputs=("address",)),
        f("enableTrading", "9a3f2e01", ("bool",)),
        f("setPaused", "5c975abb", ("bool",)),
        f("addToBlackList", "443dc312", ("address", "bool")),
        f("mint", "a0712d68", ("address", "uint256")),
        f("addMinter", "983b2d56", ("address",)),
        f("setSellTax", "6a1b0f6b", ("uint256",)),
        f("setBuyTax", "1a5b9d89", ("uint256",)),
        f("setMarketingWallet", "b6c1a002", ("address",)),
        f("setLpWallet", "b6c1a003", ("address",)),
        f("swapAndLiquify", "c0ffee77", ("uint256",)),
        f("sellTax", "c0ffee01", mut="view", outputs=("uint256",)),
        f("maxTxAmount", "c0ffee02", mut="view", outputs=("uint256",)),
    ]
    return {
        "address": "TWGd9idELBV3is6rrtC5PQUhudiJYeCr7E",   # valid base58check, never deployed
        "hex_address": "41" + "de" * 20,
        "name": "DEMO",
        "is_contract": True, "has_code": True,
        "bytecode": "6080604052" + "e803" * 4, "bytecode_bytes": 514,
        "abi": [{"type": "Function", "name": x["name"], "inputs": x["inputs"],
                 "outputs": x["outputs"], "stateMutability": x["state_mutability"]} for x in functions],
        "functions": functions, "events": [], "constructor": None, "resource": {},
        "node": {"endpoint": "offline", "api_key_used": False, "timeout_s": 0},
        "warnings": [], "raw": {},
    }


def self_test() -> int:
    """Regression checks against the live network; exit 0 only if every case behaves."""
    cases: list[tuple[str, dict, bool]] = [
        ("USDT contract", {"address": CONTRACTS["USDT"]}, True),
        ("WTRX contract", {"address": CONTRACTS["WTRX"]}, True),
        ("malformed address", {"address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X"}, False),
        ("unreachable host", {"address": USDT_TRC20}, False),
    ]
    failures = 0
    for name, kwargs, should_pass in cases:
        try:
            if name == "unreachable host":
                from core.node_connector import NodeConfig
                kwargs["config"] = NodeConfig(endpoint="https://nonexistent.invalid", timeout=3.0)
            info = get_contract_info(**kwargs)
            ok = should_pass and info["is_contract"] and len(info["abi"]) > 0
            detail = f"{len(info['functions'])} functions, {info['bytecode_bytes']} bytes"
        except NodeConnectorError as exc:
            ok = not should_pass
            detail = f"{type(exc).__name__}: {exc}"
        print(f"[{'ok' if ok else 'FAIL'}] {name}: {detail}")
        failures += not ok
    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) failed'}")
    return 0 if not failures else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        if args.demo:
            info = demo()
            print(render_human(info))
            print(render_risk(analyze_contract_risk(info)))
            return 0
        if args.self_test:
            return self_test()
        if args.check_node:
            print(json.dumps(check_node(), indent=2))
            return 0
        if not args.address:
            build_parser().print_usage(sys.stderr)
            print(f"error: address required (try {USDT_TRC20})", file=sys.stderr)
            return 2
        info = get_contract_info(args.address)
    except NodeConnectorError as exc:
        code = next((c for t, c in EXIT_CODES.items() if isinstance(exc, t)), 1)
        print(f"error ({type(exc).__name__}): {exc}", file=sys.stderr)
        if args.verbose:
            raise
        return code

    risk = None
    if not args.no_risk:
        risk = analyze_contract_risk(info)

    if args.json:
        payload = dict(info)
        if risk is not None:
            payload["risk"] = risk
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(render_human(info))
        if risk is not None:
            print(render_risk(risk))

    if args.fail_on_high and risk and risk["level"] == "HIGH":
        return 6
    return 0


if __name__ == "__main__":
    sys.exit(main())
