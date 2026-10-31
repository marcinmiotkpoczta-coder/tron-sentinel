"""Static analysis rules for TRON contracts."""

from .honeypot import analyze_contract_risk  # noqa: F401

__all__ = ["analyze_contract_risk"]
