SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

CLASSIFICATION_RULES = {
    "credit_card": {"severity": "critical", "category": "financial", "risk": "credit card number"},
    "cpf": {"severity": "high", "category": "pii", "risk": "Brazilian CPF"},
    "cnpj": {"severity": "high", "category": "pii", "risk": "Brazilian CNPJ"},
    "rg": {"severity": "medium", "category": "pii", "risk": "Brazilian RG"},
    "email": {"severity": "medium", "category": "pii", "risk": "email address"},
    "phone": {"severity": "low", "category": "pii", "risk": "phone number"},
    "cep": {"severity": "low", "category": "pii", "risk": "Brazilian CEP"},
    "aws_key": {"severity": "critical", "category": "credential", "risk": "AWS Access Key"},
    "aws_secret": {"severity": "critical", "category": "credential", "risk": "AWS Secret Key"},
    "api_key": {"severity": "high", "category": "credential", "risk": "API key"},
    "password": {"severity": "critical", "category": "credential", "risk": "password"},
    "private_key": {"severity": "critical", "category": "credential", "risk": "private key"},
    "jwt_token": {"severity": "high", "category": "credential", "risk": "JWT token"},
    "generic_secret": {"severity": "high", "category": "credential", "risk": "generic secret"},
    "custom": {"severity": "medium", "category": "custom", "risk": "custom rule match"},
}


def classify_finding(detector_type: str, subtype: str = "") -> dict:
    key = subtype.lower() if subtype else detector_type.lower()
    rule = CLASSIFICATION_RULES.get(key)
    if rule:
        return dict(rule)
    if detector_type == "pii":
        return {"severity": "medium", "category": "pii", "risk": f"PII: {subtype}"}
    if detector_type == "credential":
        return {"severity": "high", "category": "credential", "risk": f"credential: {subtype}"}
    return {"severity": "medium", "category": "unknown", "risk": "unknown finding"}
