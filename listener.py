#!/usr/bin/env python3
"""Telegram listener: watch crypto channels, detect TRON contracts, score them, alert.

    python listener.py --channels @sunpumpnews @somealpha --dry-run     # no Telegram login
    python listener.py --channels @sunpumpnews                          # live (first run asks for the SMS code)
    python listener.py --list-dialogs                                   # find channel usernames
    python listener.py --handle "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"    # score one message offline
    python listener.py --demo-listen --channels demo \
        --demo-texts "final call {usdt}|second {demo}"                  # simulate incoming messages

Pipeline per incoming message:
    update -> extract TRON addresses (regex + base58check validation)
           -> get_contract_info() -> analyze_contract_risk()
           -> level HIGH ? reply/forward alert (with cooldown + per-address dedupe)

Credentials come from .env: TG_API_ID, TG_API_HASH (required), TG_SESSION, TG_ALERT_CHAT,
TG_ALERT_MODE, TG_CHANNELS, TRON_HTTP_ENDPOINT, TRONGRID_API_KEY.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from core.checks import analyze_contract_risk
from core.node_connector import (
    NodeConfig,
    NodeConnectorError,
    get_contract_info,
    normalize_address,
)

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

log = logging.getLogger("listener")

# --------------------------------------------------------------------------- config
# Base58 (Bitcoin/TRON alphabet, no 0/O/I/l) address beginning with T, 34 chars total.
# The regex is a *candidate* filter: odd lengths/typos in chat text are rejected by
# normalize_address() before any network call.
TRON_ADDR_RE = re.compile(r"(?<![A-Za-z0-9])T[1-9A-HJ-NP-Za-km-z]{33}(?![A-Za-z0-9])")

DEMO_HONEYPOT = "TWGd9idELBV3is6rrtC5PQUhudiJYeCr7E"   # synthetic, matches main.demo()

DEFAULT_MAX_ADDRS_PER_MSG = 5
DEFAULT_COOLDOWN_S = 3600
ALERT_LEVELS = ("HIGH",)


@dataclass
class ListenerConfig:
    api_id: Optional[int]
    api_hash: Optional[str]
    session: str
    channels: List[str]
    alert_chat: Optional[str]
    alert_mode: str            # reply | forward | self | none
    alert_levels: Tuple[str, ...]
    cooldown_s: int
    max_addrs: int
    node: NodeConfig = field(default_factory=NodeConfig.from_env)

    @classmethod
    def from_env(cls, argv_channels: Optional[List[str]] = None) -> "ListenerConfig":
        raw_id = (os.getenv("TG_API_ID") or "").strip()
        try:
            api_id = int(raw_id) if raw_id else None
        except ValueError:
            api_id = None
        channels = argv_channels or [
            c.strip() for c in (os.getenv("TG_CHANNELS") or "").split(",") if c.strip()
        ]
        levels = tuple(
            l.strip().upper() for l in (os.getenv("TG_ALERT_LEVELS") or "HIGH").split(",") if l.strip()
        )
        return cls(
            api_id=api_id,
            api_hash=(os.getenv("TG_API_HASH") or "").strip() or None,
            session=os.getenv("TG_SESSION") or str(ROOT / "listener.session"),
            channels=channels,
            alert_chat=(os.getenv("TG_ALERT_CHAT") or "").strip() or None,
            alert_mode=(os.getenv("TG_ALERT_MODE") or "reply").strip().lower(),
            alert_levels=levels,
            cooldown_s=int(os.getenv("TG_ALERT_COOLDOWN") or DEFAULT_COOLDOWN_S),
            max_addrs=int(os.getenv("TG_MAX_ADDRS") or DEFAULT_MAX_ADDRS_PER_MSG),
            node=NodeConfig.from_env(),
        )


# --------------------------------------------------------------------------- extraction
def extract_tron_addresses(text: str) -> List[str]:
    """All valid, de-duplicated TRON addresses in a message, in order of appearance."""
    out: List[str] = []
    seen = set()
    for match in TRON_ADDR_RE.findall(text or ""):
        try:
            addr = normalize_address(match)   # base58check: kills typos/checksum errors
        except Exception:                     # noqa: BLE001 - a bad candidate is not an error
            log.debug("rejected candidate %s", match)
            continue
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


# --------------------------------------------------------------------------- alerts
def format_alert(info: Dict[str, Any], risk: Dict[str, Any], source: str,
                 link: Optional[str]) -> str:
    """Plain-text alert (Telegram HTML: only <b>/<code>/<a> are safe)."""
    # a flag dict carries {id,title,severity,...}; evidence holds the ABI functions
    levers = [f"{f['id']}: " + ", ".join(
        sorted({e.get("name") or "" for key in ("switches", "operators", "entries", "setters",
                                                "mint_functions")
                for e in (f["evidence"].get(key) or []) if e.get("name")}))
        for f in risk["flags"] if f["severity"] in ("critical", "high")]
    levers = [l for l in levers if not l.endswith(": ")] or ["-"]
    lines = [
        f"<b>⚠ HONEYPOT RISK: {risk['level']}</b> ({risk['score']}/100, conf {risk['confidence']:.2f})",
        f"Contract: <code>{info['address']}</code>",
        f"Name: {info.get('name') or '-'} | ABI fns: {len(info['functions'])} | code: {info['bytecode_bytes']} B",
        f"Source: {source}",
        "",
    ]
    for flag in risk["flags"]:
        lines.append(f"• [{flag['severity'].upper()}] {flag['id']} {flag['title']}")
    lines += ["", "High-risk levers:"] + [f"  {l}" for l in levers[:5]]
    if link:
        lines.append(f'<a href="{link}">open original message</a>')
    return "\n".join(lines)


# --------------------------------------------------------------------------- engine core
class RiskPipeline:
    """Network -> rules -> alert, independent of Telethon (testable with --handle)."""

    def __init__(self, cfg: ListenerConfig):
        self.cfg = cfg
        self._last_alert: Dict[str, float] = {}
        # capped LRU: (chat_id, address) already alerted, survives long channel lifetimes
        self._already_flagged: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        self._seen_cap = 5000

    def needs_alert(self, level: str) -> bool:
        return level in self.cfg.alert_levels

    def throttled(self, key: str) -> bool:
        last = self._last_alert.get(key)
        return last is not None and (time.time() - last) < self.cfg.cooldown_s

    def mark(self, key: str) -> None:
        self._last_alert[key] = time.time()

    def already_flagged(self, chat_id: str, address: str) -> bool:
        return (chat_id, address) in self._already_flagged

    def flag(self, chat_id: str, address: str) -> None:
        key = (chat_id, address)
        self._already_flagged[key] = None
        self._already_flagged.move_to_end(key)
        while len(self._already_flagged) > self._seen_cap:
            self._already_flagged.popitem(last=False)

    WHITELIST = {
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",  # USDT
        "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8",  # USDC
        "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"   # USDD
    }

    def analyze(self, address: str):
        if address in self.WHITELIST:
            return None
        try:
            info = get_contract_info(address, self.cfg.node)
        except NodeConnectorError as exc:
            log.warning("skip %s: %s", address, exc)
            return None
        return info, analyze_contract_risk(info)


# --------------------------------------------------------------------------- Telegram
def _build_client(cfg: ListenerConfig):
    from telethon import TelegramClient  # imported lazily: --handle works without Telegram

    if not cfg.api_id or not cfg.api_hash:
        raise SystemExit(
            "TG_API_ID / TG_API_HASH missing in .env — copy them from https://my.telegram.org/apps "
            "(API development tools). The project will not start without them."
        )
    Path(cfg.session).parent.mkdir(parents=True, exist_ok=True)
    return TelegramClient(cfg.session, cfg.api_id, cfg.api_hash)


async def _resolve_target(client, ref: str):
    """Accept @username, numeric id, t.me link or a dialog title."""
    ref = ref.strip()
    if ref.startswith("https://t.me/"):
        ref = ref.replace("https://t.me/", "").lstrip("+").strip("/")
        if not ref.startswith("@"):
            ref = "@" + ref
    try:
        if ref.lstrip("-").isdigit():
            return await client.get_entity(int(ref))
        return await client.get_entity(ref if ref.startswith("@") else ref)
    except Exception:  # noqa: BLE001 - fall back to title search
        async for dialog in client.iter_dialogs():
            if dialog.name and dialog.name.lower() == ref.lower():
                return dialog.entity
    raise SystemExit(f"cannot resolve channel {ref!r} (joined? spelled right?) — try --list-dialogs")


async def _notify(client, cfg: ListenerConfig, event, text: str) -> None:
    mode = cfg.alert_mode
    if mode == "none":
        log.info("alert suppressed (TG_ALERT_MODE=none)")
        return
    if mode == "reply":
        await event.reply(text, link_preview=False)
        return
    if mode == "forward":
        await client.forward_messages(cfg.alert_chat or "me", event.message)
    target = cfg.alert_chat or "me"
    await client.send_message(target, text, link_preview=False)


def _message_link(event) -> Optional[str]:
    try:
        return f"https://t.me/c/{event.chat_id}/{event.message.id}"
    except Exception:  # noqa: BLE001
        return None


async def run_listener(cfg: ListenerConfig) -> None:
    from telethon import events

    client = _build_client(cfg)
    pipeline = RiskPipeline(cfg)
    targets = []

    @client.on(events.NewMessage())
    async def on_message(event):  # noqa: ANN001
        target_ids = {t.id for t in targets}
        if target_ids and event.chat_id not in target_ids:
            return
        text = event.raw_text or ""
        addresses = extract_tron_addresses(text)[: cfg.max_addrs]
        if not addresses:
            return
        sender = None
        try:
            sender = await event.get_chat()
        except Exception:  # noqa: BLE001
            pass
        source = getattr(sender, "title", None) or str(event.chat_id)
        for addr in addresses:
            if pipeline.already_flagged(str(event.chat_id), addr):
                continue
            result = await asyncio.to_thread(pipeline.analyze, addr)
            if not result:
                continue
            info, risk = result
            log.info("%s %s -> %s (%d)", source, addr, risk["level"], risk["score"])
            if not pipeline.needs_alert(risk["level"]):
                continue
            if pipeline.throttled(addr):
                log.info("alert for %s suppressed (cooldown %ss)", addr, cfg.cooldown_s)
                continue
            pipeline.mark(addr)
            pipeline.flag(str(event.chat_id), addr)
            try:
                await _notify(client, cfg, event,
                              format_alert(info, risk, source, _message_link(event)))
            except Exception as exc:  # noqa: BLE001
                log.error("alert delivery failed for %s: %s", addr, exc)

    await client.start()  # first run: prompts for the SMS/login code on stdin
    me = await client.get_me()
    log.info("signed in as %s (id %s)", me.username or me.first_name, me.id)

    if cfg.channels:
        for ref in cfg.channels:
            entity = await _resolve_target(client, ref)
            targets.append(entity)
            log.info("watching %s (id %s)", getattr(entity, "title", ref), entity.id)
    else:
        log.warning("no channels configured (TG_CHANNELS / --channels): following ALL dialogs")
    log.info("listening ... ctrl+c to stop")
    await client.run_until_disconnected()


async def list_dialogs(cfg: ListenerConfig) -> None:
    client = _build_client(cfg)
    await client.start()
    async for dialog in client.iter_dialogs():
        if getattr(dialog, "is_channel", False) or getattr(dialog, "is_group", False):
            username = getattr(dialog.entity, "username", None)
            print(f"{dialog.id:<16} {'@' + username if username else '-':<28} {dialog.name}")
    await client.disconnect()


# --------------------------------------------------------------------------- demo (offline)
class DemoMessage:
    """Minimal stand-in for Telethon's message/event, enough for the listener handler."""

    def __init__(self, chat_id: int, mid: int, text: str):
        self.chat_id = chat_id
        self.message = self
        self.id = mid
        self.raw_text = text
        self.replied: list[str] = []

    async def reply(self, text: str, link_preview: bool = False):  # noqa: ANN001
        self.replied.append(text)

    async def get_chat(self):
        return type("Chat", (), {"title": "demo-channel", "id": self.chat_id})()


class DemoClient:
    def __init__(self):
        self.sent: list[tuple[object, str]] = []   # send_message / forward targets
        self.replied: list[str] = []               # event.reply() bodies

    def on(self, _event):
        def deco(fn):
            self.handler = fn
            return fn
        return deco

    async def send_message(self, target, text, link_preview=False):  # noqa: ANN001
        self.sent.append((target, text))

    async def forward_messages(self, target, message):  # noqa: ANN001
        self.sent.append((target, "<forward>"))


DEMO_ADDRS = {
    "{usdt}": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",   # real mainnet token -> HIGH
    "{wtrx}": "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",   # real mainnet token -> LOW
    "{demo}": DEMO_HONEYPOT,                           # synthetic honeypot from main.demo()
}


def demo_analyze(self, address):  # noqa: ANN001 - monkeypatched on RiskPipeline
    if address == DEMO_HONEYPOT:
        import main as cli
        info = cli.demo()
        return info, analyze_contract_risk(info)
    return _real_analyze(self, address)


_real_analyze = RiskPipeline.analyze


class _DisconnectNow(Exception):
    pass


async def run_demo(cfg: ListenerConfig, texts: list[str]) -> None:
    """Drive the real on_message handler with fake events: no Telegram login, no sends."""
    client = DemoClient()
    log.info("DEMO MODE: simulated events, nothing is sent to Telegram")
    demo_chat = type("Chat", (), {"id": -1001, "title": "demo-channel"})()

    async def fake_targets() -> list:
        return [demo_chat]

    real_build, real_resolve, real_analyze = _build_client, _resolve_target, RiskPipeline.analyze

    async def fake_resolve(_client, _ref):
        return (await fake_targets())[0]

    async def fake_disconnect():
        raise _DisconnectNow

    globals()["_build_client"] = lambda _cfg: client
    globals()["_resolve_target"] = fake_resolve
    RiskPipeline.analyze = demo_analyze          # type: ignore[method-assign]

    async def fake_me():
        return type("Me", (), {"username": "demo", "first_name": "demo", "id": 0})()

    # reuse the production wiring (handler registration, channel filter, alert path);
    # run_until_disconnected stops the client right after login so the texts can be replayed
    client.start = fake_me
    client.get_me = fake_me
    client.run_until_disconnected = fake_disconnect
    try:
        try:
            await run_listener(cfg)                 # registers client.handler, resolves "demo"
        except _DisconnectNow:
            pass
        for i, raw in enumerate(texts, 1):
            text = raw
            for token, addr in DEMO_ADDRS.items():
                if token in text:
                    text = text.replace(token, addr)
            event = DemoMessage(-1001, i, text)
            await client.handler(event)            # production on_message
            client.replied.extend(event.replied)
    finally:
        globals()["_build_client"] = real_build
        globals()["_resolve_target"] = real_resolve
        RiskPipeline.analyze = real_analyze      # type: ignore[method-assign]

    print(f"demo: {len(texts)} message(s) in, {len(client.sent) + len(client.replied)} alert(s) out")
    for text in client.replied:
        print("-" * 60)
        print(text)


# --------------------------------------------------------------------------- main
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TRON honeypot watcher for Telegram channels")
    parser.add_argument("--channels", nargs="*", help="channel refs (@name, id, t.me link); overrides TG_CHANNELS")
    parser.add_argument("--alert-to", help="chat id / @username for alerts (overrides TG_ALERT_CHAT)")
    parser.add_argument("--alert-mode", choices=("reply", "forward", "self", "none"),
                        help="reply in the channel, forward+summary to --alert-to, DM only, or nothing")
    parser.add_argument("--list-dialogs", action="store_true", help="print dialogs and exit")
    parser.add_argument("--handle", help="score one raw message text offline (no Telegram login)")
    parser.add_argument("--demo-listen", action="store_true",
                        help="offline: feed fake messages through the real handler (no login, no sends)")
    parser.add_argument("--demo-texts", default="", help="'msg1|msg2' with {usdt}, {wtrx}, {demo} placeholders")
    parser.add_argument("--dry-run", action="store_true",
                        help="no Telegram login and no sends: print what would be alerted")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    cfg = ListenerConfig.from_env(args.channels)
    if args.alert_to:
        cfg.alert_chat = args.alert_to
    if args.alert_mode:
        cfg.alert_mode = args.alert_mode

    if args.demo_listen:
        cfg.alert_mode = "reply"
        asyncio.run(run_demo(cfg, [t for t in args.demo_texts.split("|") if t]))
        return 0

    if args.handle is not None:
        addresses = extract_tron_addresses(args.handle)
        print(f"addresses: {addresses or 'none'}")
        pipeline = RiskPipeline(cfg)
        for addr in addresses[: cfg.max_addrs]:
            result = pipeline.analyze(addr)
            if not result:
                continue
            info, risk = result
            print(format_alert(info, risk, "cli", None))
            print("would_alert:", pipeline.needs_alert(risk["level"]))
        return 0

    if args.dry_run or not (cfg.api_id and cfg.api_hash):
        if not (cfg.api_id and cfg.api_hash):
            log.warning("TG_API_ID/TG_API_HASH not set -> dry-run mode (no Telegram connection)")
        log.info("config: channels=%s alert_mode=%s alert_chat=%s levels=%s cooldown=%ss endpoint=%s",
                 cfg.channels or "ALL", cfg.alert_mode, cfg.alert_chat or "me",
                 ",".join(cfg.alert_levels), cfg.cooldown_s, cfg.node.endpoint)
        if args.handle is None:
            print(json.dumps({"ready": False, "reason": "no credentials" if not (cfg.api_id and cfg.api_hash)
                              else "dry-run"}, indent=2))
        return 0

    try:
        if args.list_dialogs:
            asyncio.run(list_dialogs(cfg))
        else:
            asyncio.run(run_listener(cfg))
    except KeyboardInterrupt:
        log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
