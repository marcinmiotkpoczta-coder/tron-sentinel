import binascii
from tronpy import Tron

class TVMBytecodeAnalyzer:
    # Znane sygnatury funkcji (4-byte selectors) często powiązane z pułapkami i modyfikacją podatków/prawnień
    SUSPICIOUS_SELECTORS = {
        "05835c6a": "setTaxFee(uint256)",
        "13284f1a": "blacklist(address,bool)",
        "7065cbdf": "setSellFee(uint256)",
        "31233075": "setMaxTxPercent(uint256)",
        "8f283970": "changeOwner(address)",
        "4c83251b": "excludeFromFee(address,bool)",
    }

    def __init__(self, tron_client: Tron):
        self.client = tron_client

    def fetch_bytecode(self, contract_address: str) -> str:
        try:
            hex_addr = self.client.to_hex_address(contract_address)
            res = self.client.provider.make_request("wallet/getcontractinfo", {"value": hex_addr})
            return res.get("runtimecode", "") or ""
        except Exception:
            return ""

    WHITELIST = {
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",  # USDT
        "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8",  # USDC
        "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"   # USDD
    }

    def scan_contract(self, contract_address: str) -> dict:
        if contract_address in self.WHITELIST:
            return {"contract": contract_address, "risk_level": "SAFE", "risk_score": 0, "detected_selectors": [], "transfer_blocker_detected": False, "message": "Whitelista"}
        """Przeprowadza heurystyczną analizę statyczną bajtkodu TVM."""
        bytecode = self.fetch_bytecode(contract_address)
        if not bytecode:
            return {"status": "error", "message": "Brak bajtkodu lub kontrakt nie istnieje"}

        detected_risks = []
        
        # Skanowanie pod kątem podejrzanych selektorów funkcji
        for selector, description in self.SUSPICIOUS_SELECTORS.items():
            if selector in bytecode:
                detected_risks.append({
                    "selector": selector,
                    "risk": description
                })

        # Heuryzma: Sprawdzenie instrukcji zapobiegania sprzedaży (np. nadmierne użycie warunków revert w logice transferu)
        # TVM opiera się na kodzie maszynowym EVM, szukamy instrukcji warunkowych blokujących transfery
        has_transfer_blocker = "600080fd" in bytecode  # Częsty wzorzec bytecode dla dynamicznego revert()

        risk_score = len(detected_risks) * 25 + (50 if has_transfer_blocker else 0)
        risk_level = "CRITICAL" if risk_score >= 50 else ("WARNING" if risk_score > 0 else "SAFE")

        return {
            "contract": contract_address,
            "risk_level": risk_level,
            "risk_score": min(risk_score, 100),
            "detected_selectors": detected_risks,
            "transfer_blocker_detected": has_transfer_blocker
        }
