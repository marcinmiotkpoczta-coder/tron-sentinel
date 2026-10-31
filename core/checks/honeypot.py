"""Rule engine for classic TRON / SunPump honeypot patterns.

Input: the dict returned by ``core.node_connector.get_contract_info`` (static data
only: ABI, bytecode, mutability, the getcontract payload). No transactions are
simulated here -- that is the dynamic layer, out of scope for this module.

Design:
  * every rule is a pure function ``rule(ctx) -> list[Flag]`` operating on one context;
  * a flag carries an id, severity, weight, evidence and the ABI function it came from;
  * the score is the capped sum of weights; the level is derived from the score;
  * a finding is always explainable: an analyst can re-check ``evidence`` against the ABI.

Severity weights (score points): critical 40 | high 25 | medium 12 | low 5
Level: HIGH = any ``hard_block`` flag or score >= 70; MEDIUM = score >= 20; else LOW.
``hard_block`` marks the patterns that alone can make a token unsellable: an owner switch
over trading on a value-custody contract, or a contract with no readable interface at all.
Rule ids: HP-001/2/3 owner controls, HP-010/11/12 fee-on-transfer, HP-020 mint,
HP-030..034 bytecode/template facts, HP-040/41 broken TRC-20 surface.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- knowledge
# Canonical selectors (keccak4). Renaming a function does not hide it: we match by
# selector first, name second.
KNOWN_SELECTORS: Dict[str, str] = {
    "8456cb59": "pause",            # pause()
    "3f4ba83a": "unpause",          # unpause()
    "5c975abb": "paused",           # paused()
    "8da5cb5b": "owner",            # owner()
    "f2fde38b": "transferOwnership",
    "a9059cbb": "transfer",
    "23b872dd": "transferFrom",
    "095ea7b3": "approve",
    "40c10f19": "mint",
    "a0712d68": "mint",
    "983b2d56": "addMinter",
    "aa271e1a": "isMinter",
    "98650275": "renounceMinter",
    "0ecb93c0": "addBlackList",
    "e4997dc5": "removeBlackList",
    "59bf1abe": "getBlackListStatus",
    "e47d6060": "isBlackListed",
    "f3bdc228": "destroyBlackFunds",
    "42966c68": "burn",
    "79cc6790": "burnFrom",
    "cea9d26f": "rescueERC20",      # rescueERC20 / withdrawToken family
    "f0ec2e2c": "setTrading",       # generic switch
    "b03f4528": "setLimits",
    "cc872b66": "issue",            # TRC-10 issuance / TRC-20 "issue"
    "9d29ba2e": "blacklist",
    "115f7a57": "setBlacklist",
    "443dc312": "setFee",
    "6a1b0f6b": "setTaxFee",
    "1a5b9d89": "enableTrading",
    "8f32d59b": "transferable",     # tradable()
}

PATTERNS: Dict[str, re.Pattern] = {
    # trading switch: something an owner can flip to stop sells
    "pause": re.compile(r"(^|_)(pause|paused|unpause|halt|frozen|freeze|frezee|sale?s?stop)($|_)", re.I),
    "trading": re.compile(
        r"(^|_)(trad(e|ing)|sale)(_|$)|swaps?(enabled|start)|start(ing)?_?sale|presal|cooldown|maxwallet|maxtx|"
        r"sell(ing)?_?(enabled|limit|block)|buy(ing)?_?(enabled|limit|block)|open(ing)?_?trade|"
        r"enable|disable", re.I),
    "blacklist": re.compile(r"(black|white)list|(black|white)_?list|banned|_ban\b|block(ed)?_?address", re.I),
    "owner": re.compile(
        r"owner|admin|operator|manager|controller|moderator|master|dev|creator|"
        r"setperm|transfer_?admin|setrole|roles?", re.I),
    "mint": re.compile(r"(^|_)mint|_mint|mintable|issu(e|ance)|reb(as|a)se|add_?supply|print", re.I),
    # fee *parameters* only: "rate"/"limit" alone match unrelated setters (setParams, setLimits)
    "fee": re.compile(r"fee|tax|toll|commission|bps|deduct|(^|_)(rate)(_|$)", re.I),
    "transfer": re.compile(r"^(_?transfer|_?transferfrom|_?safetransfer)", re.I),
    "hidden_vault": re.compile(
        r"marketing|team|lp|pair|pool|router|fund|wallet|treasury|collector|receiver|to_?address|vault|"
        r"dev_?addr|treasury", re.I),
    "liquidity": re.compile(r"(add|remove)_?liquidity|liq_?(wallet|pool|address)|_?uniswap|pancake|sun_?swap|swap(_|$)", re.I),
    # a launchpad/meme token: DEX plumbing in the ABI
    "launchpad": re.compile(
        r"swap|router|pair|liquidity|marketing|tax|max_?wallet|cooldown|snipers?", re.I),
    "selfdestruct": re.compile(r"selfdestruct|kill|destruct", re.I),
}

# Owner-only setters whose subject is trade control -> the switch is *operable*.
OWNER_MUTATORS = re.compile(
    r"^(set|update|change|enable|disable|toggle|open|close|start|stop|activate|deactivate|"
    r"pause|unpause|freeze|unfreeze|resume|lock|unlock)", re.I)


_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5}
_LOW_CAP = 10  # low-severity observations together never exceed 2x a single low flag


def _severity_weight(sev: str) -> int:
    return _WEIGHTS.get(sev, 5)


@dataclass
class Flag:
    id: str
    title: str
    severity: str
    rule: str
    evidence: Dict[str, Any]
    hard_block: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "weight": _severity_weight(self.severity),
            "rule": self.rule,
            "evidence": self.evidence,
        }


# --------------------------------------------------------------------------- context
@dataclass
class ContractContext:
    info: Dict[str, Any]
    functions: List[Dict[str, Any]]
    by_selector: Dict[str, Dict[str, Any]]
    bytecode: str
    abi: List[Dict[str, Any]]
    name: str = ""

    @classmethod
    def build(cls, info: Dict[str, Any]) -> "ContractContext":
        funcs = list(info.get("functions") or [])
        by_selector = {}
        for fn in funcs:
            sel = (fn.get("selector") or "").lower()
            if sel:
                by_selector.setdefault(sel, fn)
        return cls(
            info=info,
            functions=funcs,
            by_selector=by_selector,
            bytecode=(info.get("bytecode") or "").lower(),
            abi=list(info.get("abi") or []),
            name=str(info.get("name") or ""),
        )

    # -- helpers -----------------------------------------------------------
    def canonical(self, fn: Dict[str, Any]) -> str:
        sel = (fn.get("selector") or "").lower()
        return KNOWN_SELECTORS.get(sel, fn.get("name") or "")

    def find(self, names: Iterable[str], *, mutating_only: bool = True) -> List[Dict[str, Any]]:
        wanted = {n.lower() for n in names}
        out = []
        for fn in self.functions:
            if mutating_only and fn.get("constant"):
                continue
            if (fn.get("name") or "").lower() in wanted or self.canonical(fn).lower() in wanted:
                out.append(fn)
        return out

    def matching(self, pattern: str, *, mutating_only: bool = True) -> List[Dict[str, Any]]:
        rx = PATTERNS[pattern]
        return [
            fn for fn in self.functions
            if (not mutating_only or not fn.get("constant"))
            and rx.search(fn.get("name") or "")
        ]

    def has_string(self, needle: str) -> bool:
        """True if the literal is embeddable in PUSH32 literals of the code."""
        if len(needle) > 32:
            needle = needle[:32]
        return needle.encode().hex() in self.bytecode

    def code_sha256(self) -> str:
        return hashlib.sha256(self.bytecode.encode()).hexdigest() if self.bytecode else ""


def _fn_brief(fn: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": fn.get("name"),
        "selector": fn.get("selector"),
        "state_mutability": fn.get("state_mutability"),
        "signature": fn.get("signature"),
        "inputs": [f"{i.get('type')} {i.get('name')}" for i in (fn.get("inputs") or [])],
    }


# --------------------------------------------------------------------------- rules
def rule_owner_control_surface(ctx: ContractContext) -> List[Flag]:
    """R1 - owner-controlled switches that can stop transfers (guardian, pause, blacklist)."""
    flags: List[Flag] = []

    # value-custody context first: it decides whether a fee setter can count as a switch
    launchpad_plumbing = [fn for fn in ctx.matching("launchpad") if not PATTERNS["fee"].search(fn.get("name") or "")]
    custodies_value = any(fn.get("payable") for fn in ctx.functions) or bool(launchpad_plumbing)
    has_token_transfer = bool(
        ctx.find(["transfer", "transferfrom"], mutating_only=True)
    ) or bool(ctx.by_selector.get("a9059cbb"))

    # "enable*Trading" is matched by pattern: the exact-name list would have to grow with
    # every template variant (enableTrade, setTradingEnabled, openTrading...).
    explicit_pauses = ctx.find(["pause", "unpause", "setpaused"])
    explicit_pauses += [fn for fn in ctx.functions
                        if not fn.get("constant")
                        and re.search(r"(en|dis)able_?(trad|sell|swap)|^open_?trad|settrad|launch(en)?",
                                      fn.get("name") or "", re.I)]
    pauses = list(explicit_pauses)
    tax_gates: List[Dict[str, Any]] = []
    if has_token_transfer and not custodies_value:
        # a plain TRC-20: a 0..10000 tax setter is itself a trading gate (bind to 10000%).
        # (Excluded when real DEX plumbing exists -- then it is a normal tax, see custodies_value)
        tax_gates = [fn for fn in ctx.functions
                     if not fn.get("constant") and not PATTERNS["liquidity"].search(fn.get("name") or "")
                     and PATTERNS["fee"].search(fn.get("name") or "")
                     and any(str(i.get("type", "")) in ("uint256", "uint8") for i in (fn.get("inputs") or []))]
        pauses += tax_gates
    pauses = _dedupe(pauses)
    explicit_pauses = [fn for fn in pauses if fn in explicit_pauses]
    tax_gates = [fn for fn in pauses if fn in tax_gates]

    # token context: a token transfer entry point (most honeypots) OR a contract that
    # custodies value (payable entry points / DEX/launchpad plumbing) -- SunPump caps,
    # lockers and staking wrappers can pause withdrawals without exposing transfer().

    def _relevant(fns: List[Dict[str, Any]]) -> bool:
        return bool(fns) and (has_token_transfer or custodies_value)

    # Tether-style issuers expose the same levers (pause/unpause, blacklist) but also ship a
    # fee oracle + blacklist query API; only issuers of real assets do that. Their switch is
    # kept on the report as a low-severity observation instead of a hard block.
    fee_oracle = [fn for fn in ctx.functions if fn.get("constant")
                  and re.search(r"(fee|tax)", fn.get("name") or "", re.I)]
    blacklist_query = bool(ctx.find(["isblacklisted", "getblackliststatus"], mutating_only=False))
    operational_issuer = bool(fee_oracle) and blacklist_query

    if _relevant(pauses) and any(f in explicit_pauses for f in pauses) or (
            _relevant(tax_gates) and not custodies_value):

        setters = [fn for fn in pauses if OWNER_MUTATORS.search(fn.get("name") or "")
                   or fn.get("name", "").lower() in ("pause", "unpause")]
        flags.append(Flag(
            id="HP-001",
            title="Owner can toggle trading (pause / enableTrading switch on transfers)",
            severity="low" if operational_issuer else "critical",
            rule="owner_control_surface",
            hard_block=not operational_issuer,
            evidence={
                # switches = explicit pause/trading gates; tax-only gates are added for plain
                # TRC-20s and must be labelled as such (they are also HP-010 evidence)
                "switches": [_fn_brief(f) for f in pauses if f in explicit_pauses],
                "tax_gates": [_fn_brief(f) for f in pauses if f in tax_gates],
                "operators": [_fn_brief(f) for f in setters],
                "note": "a paused/enabled switch reachable only by the owner is the #1 honeypot lever on TRON",
                "downgraded_because": "known operational-issuer profile (fee oracle + blacklist query)"
                if operational_issuer else None,
            },
        ))

    blacklist = ctx.find(["addblacklist", "blacklist", "setblacklist", "banaddress",
                          "blockaddress", "addtoblacklist"])
    blacklist = _dedupe(blacklist)
    if _relevant(blacklist):
        flags.append(Flag(
            id="HP-002",
            title="Blacklist / address ban can freeze a holder's balance",
            severity="high",
            rule="owner_control_surface",
            evidence={"entries": [_fn_brief(f) for f in blacklist]},
        ))

    # burnFrom only fires when the owner holds an allowance -> informational, not flagged here
    destroy = ctx.find(["destroyblackfunds", "destroy", "seize"])

    if _relevant(destroy):
        flags.append(Flag(
            id="HP-003",
            title="Owner can destroy/burn funds held by third parties",
            severity="high",
            rule="owner_control_surface",
            evidence={"entries": [_fn_brief(f) for f in destroy]},
        ))
    return flags


def rule_fee_on_transfer(ctx: ContractContext) -> List[Flag]:
    """R2 - hidden transfer fee whose parameters only the deployer can change."""
    flags: List[Flag] = []
    fee_setters = [
        fn for fn in ctx.functions
        if not fn.get("constant") and PATTERNS["fee"].search(fn.get("name") or "")
        and not PATTERNS["mint"].search(fn.get("name") or "")
    ]
    fee_accessors = [
        fn for fn in ctx.functions
        if fn.get("constant") and PATTERNS["fee"].search(fn.get("name") or "")
    ]
    if not fee_setters:
        return flags

    # owner/permission gate: some mutating function matching owner/admin AND a fee setter
    owner_gate = [
        fn for fn in ctx.functions
        if not fn.get("constant") and PATTERNS["owner"].search(fn.get("name") or "")
    ]
    numeric_inputs = [
        fn for fn in fee_setters
        if any(str(i.get("type", "")).startswith(("uint", "int")) for i in (fn.get("inputs") or []))
    ]

    # fee logic actually present in the code: a fee accessor read inside transfer paths
    has_fee_state = bool(fee_accessors) or any(
        ctx.has_string(name) for name in ("fee", "tax", "marketing", "buyFee", "sellFee")
    )

    if numeric_inputs and has_fee_state:
        flags.append(Flag(
            id="HP-010",
            title="Fee/tax setter with owner-controlled numeric parameter (fee-on-transfer risk)",
            severity="high" if owner_gate else "medium",
            rule="fee_on_transfer",
            evidence={
                "setters": [_fn_brief(f) for f in numeric_inputs],
                "accessors": [_fn_brief(f) for f in fee_accessors],
                "owner_gate_candidates": [_fn_brief(f) for f in owner_gate[:8]],
                "check": "ACCEPT-SELL simulation is required to see the actual tax and whether sells revert",
            },
        ))

    # optional *1000 / *10000 scaling hints: fee in basis points is fine, x/1000 in a
    # transfer path is a classic 99.9% drain. Static heuristic only.
    if "e803" in ctx.bytecode or "1027" in ctx.bytecode:
        if numeric_inputs:
            flags.append(Flag(
                id="HP-011",
                title="Basis-point style scaling present (fee can reach 100% by design)",
                severity="low",
                rule="fee_on_transfer",
                evidence={"note": "bytecode contains 1000/10000 constants near fee logic; verify bounds on setters"},
            ))
    return flags


def rule_mint(ctx: ContractContext) -> List[Flag]:
    """R3 - owner/minter can inflate supply after launch."""
    flags: List[Flag] = []
    mint = ctx.find(["mint", "issuetoken", "issue", "increaseSupply"])
    mint += ctx.matching("mint")
    mint += ctx.find(["issuetoken"], mutating_only=True)
    mint = _dedupe(mint)
    if not mint:
        return flags

    minter_gate = ctx.find(["addminter", "setminter", "isminter", "addissuer", "setissuer"])
    public_mint = [fn for fn in mint if not (fn.get("inputs"))]
    ungated = [fn for fn in mint if not any("amount" in (i.get("name") or "").lower()
                                            or str(i.get("type", "")).startswith(("uint", "int"))
                                            for i in (fn.get("inputs") or []))]
    # An "issue"/"mint" module with no amount parameter and no minter role is the
    # TRC-10 issue(uint256) / one-shot pattern: lower weight than a real mint(amount).
    takes_amount = any(
        any(str(i.get("type", "")).startswith(("uint", "int")) for i in (fn.get("inputs") or []))
        for fn in mint
    )
    severity = "high" if (minter_gate or takes_amount) else "medium"
    flags.append(Flag(
        id="HP-020",
        title="Supply is mintable after deployment (owner/minter can dilute holders)",
        severity=severity,
        rule="mint",
        evidence={
            "mint_functions": [_fn_brief(f) for f in mint],
            "minter_gate": [_fn_brief(f) for f in minter_gate],
            "public_mint_no_args": [_fn_brief(f) for f in public_mint],
            "no_amount_parameter": [_fn_brief(f) for f in ungated],
            "note": "killed supply only if a public burn/renounceMinter exists AND no privileged mint remains",
        },
    ))
    return flags


def rule_bytecode(ctx: ContractContext) -> List[Flag]:
    """R4/R5 - static facts: verified source, proxies, hidden stake wallets, selfdestruct."""
    flags: List[Flag] = []
    if ctx.abi and ctx.matching("launchpad", mutating_only=False) and not ctx.find(
            ["pause", "setpaused", "blacklist", "addblacklist"]):
        flags.append(Flag(
            id="HP-034",
            title="Launchpad-style token with no pause/blacklist surface (typical of automated rug scripts)",
            severity="low",
            rule="bytecode",
            evidence={"matches": [_fn_brief(f) for f in ctx.matching("launchpad", mutating_only=False)[:8]],
                      "note": "informational: meme-token template detected, LP can still be pulled"},
        ))

    if not ctx.abi:
        flags.append(Flag(
            id="HP-030",
            title="No ABI published (source unverified, behaviour opaque)",
            severity="high",
            rule="bytecode",
            evidence={"bytecode_bytes": len(ctx.bytecode) // 2, "code_sha256": ctx.code_sha256()},
            # nothing readable at all: can't be cleared statically -> treated as HIGH
            hard_block=not ctx.functions,
        ))

    # EIP-1967 / selector-style proxy: the code is a forwarder
    proxy_markers = ("363d3d373d3d3d363d73", "5c60da1b", "a3f0ad74", "f4f4a3")
    if any(m in ctx.bytecode for m in proxy_markers) or ctx.find(["implementation", "upgradeto"]):
        flags.append(Flag(
            id="HP-031",
            title="Upgradeable/proxy contract (logic can be replaced behind the same address)",
            severity="medium",
            rule="bytecode",
            evidence={"upgrade_calls": [_fn_brief(f) for f in ctx.find(["upgradeto", "setimplementation"])]},
        ))

    hidden = [fn for fn in ctx.functions
              if not fn.get("constant") and PATTERNS["hidden_vault"].search(fn.get("name") or "")
              and any(str(i.get("type", "")).startswith(("address", "uint")) for i in (fn.get("inputs") or []))]
    if hidden:
        flags.append(Flag(
            id="HP-032",
            title="Setters for payout addresses (marketing/team/LP) - funds can be redirected",
            severity="medium",
            rule="bytecode",
            evidence={"setters": [_fn_brief(f) for f in hidden[:10]]},
        ))

    if "ff" in ctx.bytecode and any(ctx.has_string(s) for s in ("selfdestruct", "suicide")) \
            or ctx.find(["destruct", "selfdestruct", "kill"]):
        flags.append(Flag(
            id="HP-033",
            title="Self-destruct / kill path present",
            severity="high",
            rule="bytecode",
            evidence={},
        ))
    return flags


def rule_launchpad_template(ctx: ContractContext) -> List[Flag]:
    """R8 - meme/launchpad template fingerprint: DEX plumbing but no admin kill switch."""
    if not ctx.abi:
        return []
    template = ctx.matching("launchpad", mutating_only=False)
    if not template:
        return []
    if ctx.find(["pause", "setpaused", "opentrading", "settradingenabled"]):
        return []
    return [Flag(
        id="HP-034",
        title="Launchpad-style token (DEX swap/tax plumbing) with no pause switch",
        severity="low",
        rule="launchpad_template",
        evidence={"matches": [_fn_brief(f) for f in template[:8]],
                  "note": "template fingerprint, not a verdict: LP can still be pulled"},
    )]


def rule_tax_bounds_missing(ctx: ContractContext) -> List[Flag]:
    """R6 - fee setters without any visible max/limit guard in the ABI."""
    flags: List[Flag] = []
    setters = [fn for fn in ctx.functions
               if not fn.get("constant") and PATTERNS["fee"].search(fn.get("name") or "")
               and any(str(i.get("type", "")).startswith(("uint", "int")) for i in (fn.get("inputs") or []))]
    if not setters:
        return flags
    guards = [fn for fn in ctx.functions if PATTERNS["fee"].search(fn.get("name") or "")
              and re.search(r"max|limit|cap|bound", fn.get("name") or "", re.I)]
    if not guards:
        flags.append(Flag(
            id="HP-012",
            title="Fee setters expose no max/limit accessor (unbounded tax possible)",
            severity="medium",
            rule="fee_on_transfer",
            evidence={"setters": [_fn_brief(f) for f in setters],
                      "note": "no MaxFee/MaxTax getter found; bounds may still be hardcoded in bytecode"},
        ))
    return flags


def rule_transfer_hooks(ctx: ContractContext) -> List[Flag]:
    """R7 - TRC-20 surface itself deviates from the standard (missing/renamed transfer)."""
    flags: List[Flag] = []
    names = {(fn.get("name") or "").lower() for fn in ctx.functions}
    # only trust this when the ABI is otherwise a real token (has balances/supply)
    looks_like_token = bool({"balanceof", "totalsupply"} & names) or bool(
        ctx.by_selector.get("70a08231") or ctx.by_selector.get("18160ddd"))
    if ctx.abi and looks_like_token and "transfer" not in names and "a9059cbb" not in ctx.by_selector:
        flags.append(Flag(
            id="HP-040",
            title="No standard transfer(address,uint256) in ABI - not a plain TRC-20",
            severity="high",
            rule="transfer_surface",
            evidence={"functions": sorted(names)[:20]},
        ))
    elif ctx.abi and looks_like_token and "transferfrom" not in names and "23b872dd" not in ctx.by_selector:
        flags.append(Flag(
            id="HP-041",
            title="transferFrom missing - DEX sells may not be possible",
            severity="medium",
            rule="transfer_surface",
            evidence={},
        ))
    return flags


RULES: List[Callable[[ContractContext], List[Flag]]] = [
    rule_owner_control_surface,
    rule_fee_on_transfer,
    rule_tax_bounds_missing,
    rule_mint,
    rule_bytecode,
    rule_launchpad_template,
    rule_transfer_hooks,
]


# --------------------------------------------------------------------------- engine
def _dedupe(fns: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for fn in fns:
        key = (fn.get("selector"), fn.get("name"))
        if key in seen:
            continue
        seen.add(key)
        out.append(fn)
    return out


def _level(score: int, flags: List[Flag]) -> str:  # noqa: D401
    """HIGH only on a hard block or score >=70; a pile of soft flags stays MEDIUM.

    4 independent 25-point privileges (Tether-style profile) score 100 but are not a
    honeypot: they must not reach HIGH unless a hard block (pause on transfers) fired.
    """
    if any(f.hard_block for f in flags) or score >= 70:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def analyze_contract_risk(contract_info: dict) -> dict:
    """Score a contract from its static ABI/bytecode profile.

    Returns:
      {
        "level": "LOW"|"MEDIUM"|"HIGH",
        "score": int,                 # 0..100, capped sum of flag weights
        "is_honeypot_suspected": bool,
        "flags": [ {id,title,severity,weight,rule,evidence}, ... ],
        "checks": {rule: "clean"|"flagged"},
        "summary": [str, ...],        # human-readable one-liners
        "coverage": {...}             # what static analysis cannot see
      }
    """
    if not isinstance(contract_info, dict):
        raise TypeError("analyze_contract_risk expects the dict from get_contract_info()")
    ctx = ContractContext.build(contract_info)

    flags: List[Flag] = []
    checks: Dict[str, str] = {}
    for rule in RULES:
        produced = rule(ctx)
        checks[rule.__name__.replace("rule_", "")] = "flagged" if produced else "clean"
        flags.extend(produced)

    # de-duplicate by id, keep the highest weight
    unique: Dict[str, Flag] = {}
    for f in flags:
        if f.id not in unique or _severity_weight(f.severity) > _severity_weight(unique[f.id].severity):  # noqa: E501
            unique[f.id] = f
    flags = [unique[k] for k in sorted(unique, key=lambda k: -_severity_weight(unique[k].severity))]

    def _weight(flag: Flag) -> int:
        # a critical flag that was downgraded for an issuer profile adds little weight
        return 40 if (flag.severity == "critical" and flag.hard_block) else _WEIGHTS.get(flag.severity, 5)  # noqa: E501

    raw_score = sum(_weight(f) for f in flags)
    score = min(100, raw_score)
    level = _level(score, flags)
    confidence = 0.0
    if flags:
        strongest = _severity_weight(flags[0].severity)
        confidence = round(min(0.95, 0.45 + 0.05 * score / 10 + 0.2 * (strongest / 40)), 2)
    logger.debug("risk: level=%s score=%d/%d flags=%s", level, score, raw_score,
                 [(f.id, f.severity, f.hard_block) for f in flags])


    summary = [f"[{f.severity.upper()}] {f.id} {f.title}" for f in flags] or ["no known honeypot pattern matched"]

    return {
        "level": level,
        "score": score,
        "score_raw": raw_score,   # before the 100 cap: shows how far over the ceiling a contract is
        "is_honeypot_suspected": level == "HIGH",
        "confidence": confidence,   # static-only confidence in the level, 0..1
        "flags": [f.as_dict() for f in flags],
        "checks": checks,
        "summary": summary,
        "coverage": {
            "static": ["ABI names/selectors", "state mutability", "bytecode literals", "function surface"],
            "not_covered": [
                "actual fee charged on a real buy (needs simulate/accept-sell)",
                "sell-side revert due to liquidity/loop logic",
                "hidden state already armed by the deployer (paused=true at deploy)",
                "per-holder limits enforced inside _transfer body",
            ],
        },
    }


if __name__ == "__main__":  # python -m core.checks.honeypot <address>
    import json
    import sys

    from core.node_connector import NodeConfig, get_contract_info

    target = sys.argv[1] if len(sys.argv) > 1 else "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    cfg = NodeConfig(endpoint="https://tron-rpc.publicnode.com")
    print(json.dumps(analyze_contract_risk(get_contract_info(target, cfg)), indent=2))
