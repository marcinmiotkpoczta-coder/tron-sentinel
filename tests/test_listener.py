#!/usr/bin/env python3
"""Tests for listener.py (no Telegram login, no network).

    ./venv/bin/python tests/test_listener.py
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import listener  # noqa: E402
from listener import ListenerConfig, RiskPipeline, extract_tron_addresses, format_alert  # noqa: E402

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
WTRX = "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR"


def test_regex_finds_address():
    text = f"LFG new pump {USDT} buy now"
    assert extract_tron_addresses(text) == [USDT], extract_tron_addresses(text)


def test_regex_dedupes_preserving_order():
    text = f"{WTRX} and again {WTRX} plus {USDT}"
    assert extract_tron_addresses(text) == [WTRX, USDT]


def test_checksum_typo_rejected():
    bad = USDT[:-1] + "X"   # 34 chars, T-prefixed, bad base58check checksum
    assert len(bad) == 34 and bad.startswith("T")
    assert extract_tron_addresses(f"address {bad} ??") == []


def test_non_tron_and_short_strings_ignored():
    text = "0x41a614f803b6fd780986a42c78ec9c7f77e6ded13c TShort TESTSYM123"
    assert extract_tron_addresses(text) == []


def test_address_inside_longer_token_not_matched():
    assert extract_tron_addresses("x" + USDT) == []
    assert extract_tron_addresses(USDT + "9") == []


def test_hex_address_in_message_is_ignored():
    """Only 'T...' base58 addresses are in scope for the listener regex."""
    assert extract_tron_addresses("0x" + USDT) == []


class FakePipeline(RiskPipeline):
    def analyze(self, address):
        return {"address": address, "name": "X", "functions": [],
                "bytecode_bytes": 10}, {
            "level": "HIGH", "score": 75, "confidence": 0.9,
            "flags": [{"id": "HP-001", "title": "t", "severity": "critical",
                       "evidence": {"switches": [{"name": "pause"}]}}],
        }


def _cfg(**kw):
    base = dict(api_id=None, api_hash=None, session=":memory:", channels=[],
                alert_chat=None, alert_mode="reply", alert_levels=("HIGH",),
                cooldown_s=3600, max_addrs=5)
    base.update(kw)
    return ListenerConfig(**base)


def test_threshold_and_cooldown():
    p = FakePipeline(_cfg())
    assert p.needs_alert("HIGH") and not p.needs_alert("MEDIUM")
    addr = USDT
    assert not p.throttled(addr)
    p.mark(addr)
    assert p.throttled(addr)
    q = FakePipeline(_cfg(cooldown_s=0))
    q.mark(addr)
    assert not q.throttled(addr)


def test_dedupe_lru_is_capped():
    p = FakePipeline(_cfg())
    for i in range(5100):
        p.flag("chat", f"addr{i}")
    assert len(p._already_flagged) == p._seen_cap
    assert p.already_flagged("chat", "addr5099")


def test_alert_text_contains_levers():
    info = {"address": USDT, "name": "TetherToken", "functions": [{}], "bytecode_bytes": 15575}
    risk = {"level": "HIGH", "score": 92, "confidence": 0.95,
            "flags": [{"id": "HP-020", "title": "mint", "severity": "high",
                       "evidence": {"mint_functions": [{"name": "issue"}]}}]}
    text = format_alert(info, risk, "@chan", "https://t.me/c/1/2")
    assert "HONEYPOT RISK: HIGH" in text and USDT in text
    assert "HP-020" in text and "issue" in text
    assert "@chan" in text and "t.me/c/1/2" in text


def test_alert_levels_configurable():
    p = FakePipeline(_cfg(alert_levels=("HIGH", "MEDIUM")))
    assert p.needs_alert("MEDIUM")


def test_cli_handle_offline_path():
    """main() with --dry-run must exit 0 without Telegram credentials."""
    assert listener.main(["--dry-run", "--channels", "@test"]) == 0


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]

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
