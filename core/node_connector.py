"""TRON node connection layer.

Single responsibility: hold one TronPy client and turn *raw* node responses into
plain Python data. No honeypot heuristics live here -- detectors consume this output.

Public API
----------
get_contract_info(address) -> dict   raw data for one contract
check_node()               -> dict   health probe / latency
get_client()                          cached, process-wide client

Every network failure is re-raised as a subclass of ``NodeConnectorError`` with a
human-readable message; callers never have to know TronPy's exception zoo.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar

import requests
from dotenv import load_dotenv
from tronpy import Tron
from tronpy.exceptions import (
    AddressNotFound,
    BadAddress,
    NotFound,
    TvmError,
    ValidationError,
)
from tronpy.keys import is_base58check_address
from tronpy.providers.http import HTTPProvider

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logger = logging.getLogger(__name__)

DEFAULT_ENDPOINT = "https://api.trongrid.io"
DEFAULT_TIMEOUT = 15.0


# --------------------------------------------------------------------------- errors
class NodeConnectorError(Exception):
    """Base class for every failure this module surfaces."""


class InvalidAddressError(NodeConnectorError):
    """The string is not a base58check TRON address."""


class NotAContractError(NodeConnectorError):
    """Address exists (or not) but holds no deployed contract."""


class NodeTimeoutError(NodeConnectorError):
    """Node did not answer within the configured timeout."""


class NodeUnavailableError(NodeConnectorError):
    """Transport-level failure: DNS, TLS, connection reset, HTTP 5xx."""


class NodeResponseError(NodeConnectorError):
    """Node answered but with an error payload (bad params, rate limit, TVM error)."""


# --------------------------------------------------------------------------- config
@dataclass(frozen=True)
class NodeConfig:
    endpoint: str = DEFAULT_ENDPOINT
    api_key: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "NodeConfig":
        env = os.environ if env is None else env
        raw_timeout = env.get("TRON_REQUEST_TIMEOUT", "")
        try:
            timeout = float(raw_timeout) if raw_timeout else DEFAULT_TIMEOUT
        except ValueError:
            logger.warning("TRON_REQUEST_TIMEOUT=%r is not a number, using %.0fs",
                           raw_timeout, DEFAULT_TIMEOUT)
            timeout = DEFAULT_TIMEOUT
        return cls(
            endpoint=env.get("TRON_HTTP_ENDPOINT") or DEFAULT_ENDPOINT,
            api_key=(env.get("TRONGRID_API_KEY") or "").strip() or None,
            timeout=timeout,
        )

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)


# --------------------------------------------------------------------------- address
def normalize_address(address: str) -> str:
    """Validate and canonicalise a TRON address.

    Accepts base58check ("TR7N..."), 0x-prefixed and bare 21-byte hex.
    Raises InvalidAddressError for anything else -- before any network call.
    """
    if not isinstance(address, str):
        raise InvalidAddressError(f"address must be str, got {type(address).__name__}")
    candidate = address.strip()
    if not candidate:
        raise InvalidAddressError("address is empty")

    try:
        if is_base58check_address(candidate):
            return candidate
    except ValueError:
        # base58.b58decode_check raises ValueError on a bad checksum
        pass

    if candidate.lower().startswith("0x") or len(candidate) == 42:
        hex_body = candidate[2:] if candidate.lower().startswith("0x") else candidate
        if len(hex_body) == 42 and hex_body.lower().startswith("41"):
            try:
                return Tron.to_base58check_address(bytes.fromhex(hex_body))
            except (ValueError, TypeError):
                pass

    raise InvalidAddressError(
        f"{address!r} is not a valid TRON base58check address "
        "(expected 34 chars starting with 'T') nor a 41-prefixed hex address"
    )


# --------------------------------------------------------------------------- client
_client: Optional[Tron] = None
_client_config: Optional[NodeConfig] = None


def build_client(config: Optional[NodeConfig] = None) -> Tron:
    """Construct a fresh TronPy client (no caching) -- useful for tests."""
    config = config or NodeConfig.from_env()
    provider = HTTPProvider(
        endpoint_uri=config.endpoint,
        timeout=config.timeout,
        api_key=config.api_key,
    )
    # tronpy 0.6.x rejects a `timeout` key in conf; the provider owns it.
    client = Tron(provider=provider)
    logger.debug("TronPy client ready: endpoint=%s api_key=%s timeout=%.1fs",
                 config.endpoint, "set" if config.has_api_key else "none", config.timeout)
    return client


def get_client(config: Optional[NodeConfig] = None) -> Tron:
    """Process-wide cached client, rebuilt when the effective config changes."""
    global _client, _client_config
    effective = config or NodeConfig.from_env()
    if _client is None or _client_config != effective:
        _client = build_client(effective)
        _client_config = effective
    return _client


# --------------------------------------------------------------------------- errors->types
def _translate(exc: Exception, address: str) -> NodeConnectorError:
    """Map TronPy/requests/network errors onto this module's exception hierarchy."""
    if isinstance(exc, NodeConnectorError):
        return exc
    if isinstance(exc, (requests.exceptions.Timeout, TimeoutError)):
        return NodeTimeoutError(f"node timed out while serving {address}")
    if isinstance(exc, requests.exceptions.HTTPError):
        code = exc.response.status_code
        if code == 429:
            return NodeResponseError(
                f"rate limited (HTTP 429) for {address} -- set TRONGRID_API_KEY or retry later"
            )
        if code >= 500:
            return NodeUnavailableError(f"node returned HTTP {code} for {address}")
        return NodeResponseError(f"node returned HTTP {code} for {address}: {exc}")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return NodeUnavailableError(f"cannot reach node: {exc}")
    if isinstance(exc, requests.exceptions.RequestException):
        return NodeUnavailableError(f"transport failure talking to node: {exc}")
    if isinstance(exc, (AddressNotFound, NotFound)):
        return NotAContractError(f"nothing found at {address} (account/contract does not exist)")
    if isinstance(exc, (BadAddress, ValidationError)):
        return InvalidAddressError(f"node rejected {address}: {exc}")
    if isinstance(exc, TvmError):
        return NodeResponseError(f"TVM error for {address}: {exc}")
    if isinstance(exc, ValueError):
        return NodeResponseError(f"malformed/absent contract data for {address}: {exc}")
    if isinstance(exc, (KeyError, TypeError)):
        return NodeResponseError(f"unexpected node payload for {address}: {exc!r}")
    return NodeResponseError(f"unexpected failure for {address}: {type(exc).__name__}: {exc}")


T = TypeVar("T")


def _guarded(address_label: str) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Convert any exception into a NodeConnectorError carrying context."""

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            try:
                return fn(*args, **kwargs)
            except NodeConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001 - deliberate normalisation
                raise _translate(exc, address_label) from exc

        return wrapper

    return decorator


# --------------------------------------------------------------------------- raw pulls
def _pick_contract_node(tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Locate the SmartContract node inside a getcontract transaction."""
    if not isinstance(tx, dict):
        return None
    if tx.get("contract_type") == "CreateSmartContract":
        return None  # deploy transaction, not a call target
    for entry in tx.get("raw_data", {}).get("contract", []) or []:
        param = entry.get("parameter") or {}
        if param.get("type_url", "").endswith("SmartContract"):
            value = param.get("value") or {}
            return value
    return None


def _raw_tx(client: Tron, address: str) -> Optional[Dict[str, Any]]:
    try:
        return client.get_contract(address)
    except (AddressNotFound, NotFound):
        return None


def _is_contract(has_code: bool, abi: List[Dict[str, Any]], raw: Optional[Dict[str, Any]]) -> bool:
    """A deployed contract has TVM code; getcontract exists even for plain accounts."""
    if has_code:
        return True
    origin = (raw or {}).get("origin_address")
    return bool(origin) and not abi


def get_account_resource(client: Tron, address: str) -> Optional[Dict[str, Any]]:
    """Energy/bandwidth limits of the contract account (affects honeypot cost traps)."""
    try:
        return client.get_account_resource(address)
    except (AddressNotFound, NotFound):
        return None


@_guarded("getnowblock")
def check_node(config: Optional[NodeConfig] = None) -> Dict[str, Any]:
    """Latency + reachability probe against the configured node."""
    config = config or NodeConfig.from_env()
    client = get_client(config)
    started = time.perf_counter()
    # wallet/getnowblock, not getnodeinfo: some providers omit the "block" string.
    head = int(client.get_block()["block_header"]["raw_data"]["number"])
    return {
        "endpoint": config.endpoint,
        "api_key_used": config.has_api_key,
        "latest_block": head,
        "latency_ms": round((time.perf_counter() - started) * 1000.0, 1),
    }


@_guarded("get_contract_info")
def get_contract_info(address: str, config: Optional[NodeConfig] = None) -> Dict[str, Any]:
    """Fetch raw contract data for ``address``.

    Returns a dict with:
      address, hex_address, node, has_code, bytecode, abi, functions, events,
      constructor, resource, warnings -- all values straight from the node,
      no scoring/interpretation.
    """
    normalized = normalize_address(address)
    config = config or NodeConfig.from_env()
    client = get_client(config)
    warnings: List[str] = []

    tx = _raw_tx(client, normalized)
    if tx is None:
        raise NotAContractError(
            f"{normalized} is not a deployed contract (no account/contract on record)"
        )

    node = _pick_contract_node(tx) or {}
    contract_address = node.get("contract_address") or normalized

    try:
        bytecode = client.get_contract(contract_address).bytecode or ""
    except (AttributeError, KeyError, ValueError):
        # account has a contract but no TVM code -> plain account / TRC-10 style entry
        bytecode = ""
    except Exception as exc:  # noqa: BLE001 - network errors must not be swallowed
        raise _translate(exc, normalized) from exc

    has_code = bool(bytecode.strip())
    is_contract = has_code or bool(_pick_contract_node(tx))

    abi: List[Dict[str, Any]] = []
    functions: List[Dict[str, Any]] = []
    events: List[Dict[str, Any]] = []
    constructor: Optional[Dict[str, Any]] = None

    try:
        contract = client.get_contract(contract_address)
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc, normalized) from exc
    raw_abi = contract.abi or []
    if isinstance(raw_abi, dict):
        raw_abi = raw_abi.get("entrys") or raw_abi.get("entries") or []
    abi = list(raw_abi)

    if abi:
        try:
            for fn in contract.functions:
                mutability = (fn._abi.get("stateMutability") or "").lower()
                functions.append(
                    {
                        "name": fn.name,
                        "state_mutability": mutability or "nonpayable",
                        "constant": mutability in ("view", "pure"),  # read-only from outside
                        "payable": mutability == "payable",
                        "signature": fn.function_signature,
                        "selector": fn.function_signature_hash,
                        "inputs": fn.inputs,
                        "outputs": fn.outputs,
                    }
                )
        except ValueError as exc:
            warnings.append(f"ABI present but functions could not be wrapped: {exc}")
        try:
            for ev in contract.events:
                events.append({"name": ev._event_name, "inputs": ev._abi.get("inputs", [])})
        except Exception as exc:  # noqa: BLE001 - events are optional metadata
            warnings.append(f"events not available: {exc}")
        constructor = next(
            (e for e in abi if e.get("type") in ("Constructor", "constructor")), None
        )
    else:
        warnings.append("contract has no ABI -> source not verified, only bytecode is known")

    try:
        resource = get_account_resource(client, normalized)
    except Exception as exc:  # noqa: BLE001 - optional extra, never fatal
        resource = None
        warnings.append(f"account resource unavailable: {_translate(exc, normalized)}")

    if not config.has_api_key:
        warnings.append("TRONGRID_API_KEY not set -> anonymous rate limits apply")

    info = {
        "address": normalized,
        "name": getattr(contract, "name", "") or "",   # on-chain contract name (may be empty)
        "is_contract": is_contract,
        "hex_address": client.to_hex_address(normalized),
        "node": {
            "endpoint": config.endpoint,
            "api_key_used": config.has_api_key,
            "timeout_s": config.timeout,
        },
        "has_code": has_code,
        "bytecode_bytes": len(bytecode) // 2,
        "bytecode": bytecode,
        "abi": abi,
        "functions": functions,
        "events": events,
        "constructor": constructor,
        "resource": resource,
        "raw": tx,          # untouched getcontract payload
        "warnings": warnings,
    }
    if not is_contract:
        warnings.append("no TVM code at this address -> plain account, not a contract")
    logger.info("fetched %s: %d ABI entries, %d bytes of code",
                normalized, len(abi), info["bytecode_bytes"])
    return info


if __name__ == "__main__":  # tiny smoke test: python -m core.node_connector
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    print(check_node())
