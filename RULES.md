# Static honeypot rules - what each flag means and how it scores

`core/checks/honeypot.py` -> `analyze_contract_risk(info)` consumes the dict from
`core.node_connector.get_contract_info()` and is purely static (ABI + bytecode literals).
It never sends a transaction: no buy/sell simulation, no `triggerconstantcontract` probing.

## Scoring

| severity | points | meaning |
|---|---|---|
| critical | 40 | owner holds a lever that can make the token unsellable (hard block) |
| high | 25 | one privilege that a rug needs (mint, blacklist, destroy, no ABI) |
| medium | 12 | supporting condition (fee setter, payout redirect, proxy) |
| low | 5 | fingerprint / hint, never decisive |

`score = min(100, sum(points))`; `score_raw` keeps the uncapped sum.
Level: `HIGH` = any `hard_block` flag or `score >= 70`; `MEDIUM` = `score >= 20`; else `LOW`.
`confidence` is a static-only indicator (0..1) of how sure the level is, not a probability.

## Flag catalogue

| id | rule | default severity | trigger |
|---|---|---|---|
| HP-001 | owner_control_surface | critical (hard block) | a token/value-custody contract exposes `pause/setPaused/enableTrading/...` **or** (plain TRC-20 without DEX plumbing) any numeric tax setter that can bind to 100% |
| HP-002 | owner_control_surface | high | `addBlackList/setBlacklist/...` on a token |
| HP-003 | owner_control_surface | high | `destroyBlackFunds/destroy/seize` |
| HP-010 | fee_on_transfer | high | fee/tax setter with a numeric input AND a fee getter (fee exists) |
| HP-011 | fee_on_transfer | low | basis-point constants present in bytecode |
| HP-012 | fee_on_transfer | medium | fee setters with no `max/limit/cap` accessor in the ABI |
| HP-020 | mint | high | mint/issue taking an amount, or a minter role |
| HP-030 | bytecode | high (hard block when ABI empty) | no ABI |
| HP-031 | proxy / upgradeable | medium | proxy markers or `upgradeTo` |
| HP-032 | payout redirect | medium | setters for marketing/team/LP wallets |
| HP-033 | self-destruct path | high | | HP-034 | launchpad_template | low | meme-token plumbing (swap/tax/maxWallet) without a pause switch |
| HP-040/041 | transfer_surface | high/medium | token ABI without `transfer` / `transferFrom` |

## Prior-knowledge downgrades

`operational_issuer`: if the ABI has a **fee getter** (e.g. `maximumFee`, `calcFee`) *and* a
**blacklist query** (`isBlackListed`), HP-001 drops from critical to low and stops being a
hard block. This is the Tether-style profile: levers exist, admin is a regulated issuer.
USDT on TRON therefore lands on HIGH through HP-002/003/020 (92 points), not through the pause.

## Known limits (state them in any report)

- No fee simulation: a `0%` tax in the ABI may still be set to 100% after launch.
- Hidden `_transfer` logic (allowlist/denylist, loop to force energy exhaustion, gas traps)
  is not decompiled; bytecode checks are literal-string based only.
- State is not read: a contract deployed already `paused`/`blacklisted` looks identical.
- A clean LOW means "no known pattern", not "safe": LP can still be pulled (HP-034 is only a hint).

## Adding a flag

1. Write `rule_<topic>(ctx) -> list[Flag]`; never raise -- read through `ctx.find/matching`.
2. Use the canonical selector (`KNOWN_SELECTORS`) when the function is standard; match names only
   for template-specific extras.
3. Set `hard_block=True` only if the flag alone can block sells.
4. Add a case to `tests/test_honeypot.py` (synthetic profile) and keep real fixtures in `tests/fixtures/`.
