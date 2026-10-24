import sys
import pytest
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from detectors.pii_detector import PIIDetector
from detectors.credit_card import CreditCardDetector
from detectors.credentials import CredentialDetector
from detectors.custom_rules import CustomRulesDetector
from rules.classification_rules import classify_finding


class TestPIIDetector:
    def setup_method(self):
        self.detector = PIIDetector()

    def test_detect_cpf(self):
        findings = self.detector.scan("Meu CPF é 529.982.247-25")
        cpf_findings = [f for f in findings if f.subtype == "cpf"]
        assert len(cpf_findings) > 0
        assert "529.982.247-25" in cpf_findings[0].value

    def test_detect_invalid_cpf(self):
        findings = self.detector.scan("CPF inválido: 111.111.111-11")
        cpf_findings = [f for f in findings if f.subtype == "cpf"]
        assert len(cpf_findings) == 0

    def test_detect_cnpj(self):
        findings = self.detector.scan("CNPJ: 11.444.777/0001-61")
        cnpj_findings = [f for f in findings if f.subtype == "cnpj"]
        assert len(cnpj_findings) > 0

    def test_detect_email(self):
        findings = self.detector.scan("Email: user@example.com")
        email_findings = [f for f in findings if f.subtype == "email"]
        assert len(email_findings) > 0
        assert "user@example.com" in email_findings[0].value

    def test_detect_phone(self):
        findings = self.detector.scan("Telefone: (11) 91234-5678")
        phone_findings = [f for f in findings if f.subtype == "phone"]
        assert len(phone_findings) > 0

    def test_detect_cep(self):
        findings = self.detector.scan("CEP: 01310-000")
        cep_findings = [f for f in findings if f.subtype == "cep"]
        assert len(cep_findings) > 0

    def test_no_false_positive(self):
        findings = self.detector.scan("Just a normal text without any PII here 12345")
        assert len(findings) == 0

    def test_rg_detection(self):
        findings = self.detector.scan("RG: 12.345.678-X")
        rg_findings = [f for f in findings if f.subtype == "rg"]
        assert len(rg_findings) > 0

    def test_multiple_pii(self):
        text = """
        CPF: 529.982.247-25
        Email: john@test.com
        Phone: (21) 98765-4321
        """
        findings = self.detector.scan(text)
        assert len(findings) >= 2


class TestCreditCardDetector:
    def setup_method(self):
        self.detector = CreditCardDetector()

    def test_valid_visa(self):
        findings = self.detector.scan("Visa: 4111 1111 1111 1111")
        assert len(findings) > 0

    def test_valid_mastercard(self):
        findings = self.detector.scan("Mastercard: 5500 0000 0000 0004")
        assert len(findings) > 0

    def test_valid_amex(self):
        findings = self.detector.scan("Amex: 3782 822463 10005")
        assert len(findings) > 0

    def test_invalid_credit_card(self):
        findings = self.detector.scan("Invalid: 1234 5678 9012 3456")
        assert len(findings) == 0

    def test_short_number(self):
        findings = self.detector.scan("Short: 1234 5678 9012")
        assert len(findings) == 0

    def test_dashed_format(self):
        findings = self.detector.scan("Card: 4111-1111-1111-1111")
        assert len(findings) > 0


class TestCredentialDetector:
    def setup_method(self):
        self.detector = CredentialDetector()

    def test_aws_key(self):
        findings = self.detector.scan("AWS_KEY=AKIAIOSFODNN7EXAMPLE")
        aws_findings = [f for f in findings if f.subtype == "aws_key"]
        assert len(aws_findings) > 0

    def test_api_key(self):
        findings = self.detector.scan('api_key = "sk-abc123def456ghi789jkl"')
        key_findings = [f for f in findings if f.subtype == "api_key"]
        assert len(key_findings) > 0

    def test_password(self):
        findings = self.detector.scan('password = "supersecret123!"')
        pass_findings = [f for f in findings if f.subtype == "password"]
        assert len(pass_findings) > 0

    def test_private_key(self):
        findings = self.detector.scan("-----BEGIN RSA PRIVATE KEY-----")
        pk_findings = [f for f in findings if f.subtype == "private_key"]
        assert len(pk_findings) > 0

    def test_jwt_token(self):
        findings = self.detector.scan("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
        jwt_findings = [f for f in findings if f.subtype == "jwt_token"]
        assert len(jwt_findings) > 0

    def test_generic_secret(self):
        findings = self.detector.scan("Bearer sk-abcdefghijklmnopqrstuvwxyz123456")
        secret_findings = [f for f in findings if f.subtype == "generic_secret"]
        assert len(secret_findings) > 0


    def test_private_key_formats(self):
        for header in (
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
        ):
            findings = self.detector.scan(header)
            assert [f for f in findings if f.subtype == "private_key"], header

    def test_aws_secret_requires_context(self):
        git_hash = "commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        assert not [f for f in self.detector.scan(git_hash) if f.subtype == "aws_secret"]
        line = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert [f for f in self.detector.scan(line) if f.subtype == "aws_secret"]



def _reference_cpf(rng):
    """Independent implementation of the CPF check-digit algorithm."""
    digits = [rng.randint(0, 9) for _ in range(9)]
    if len(set(digits)) == 1:
        digits[0] = (digits[0] + 1) % 10
    for size in (9, 10):
        total = sum(d * (size + 1 - i) for i, d in enumerate(digits))
        rest = (total * 10) % 11
        digits.append(0 if rest == 10 else rest)
    return "".join(map(str, digits))


def test_cpf_validator_against_reference_implementation():
    import random

    detector = PIIDetector()
    rng = random.Random(42)
    for _ in range(500):
        cpf = _reference_cpf(rng)
        assert detector._validate_cpf(cpf), cpf
        wrong = cpf[:-1] + str((int(cpf[-1]) + 1) % 10)
        assert not detector._validate_cpf(wrong), wrong


@pytest.mark.parametrize(
    "text",
    [
        "Diners 3056 930902 5904",
        "Elo 6362970000457013",
        "Hipercard 6062825624254001",
        "MC 2-series 2223003122003222",
        "Discover 6011-1111-1111-1117",
    ],
)
def test_credit_card_brands_detected(text):
    assert CreditCardDetector().scan(text)


@pytest.mark.parametrize(
    "text",
    [
        "Luhn-valid but no brand 1000000000000008",
        "mixed separators 4111-1111 1111 1111",
        "phone 11 98765-4321",
    ],
)
def test_credit_card_false_positives_rejected(text):
    assert not CreditCardDetector().scan(text)


class TestCustomRulesDetector:
    def test_add_rule_dynamically(self):
        detector = CustomRulesDetector()
        detector.add_rule("test_pattern", r"SECRET-\d{4}")
        findings = detector.scan("My secret is SECRET-1234")
        assert len(findings) > 0
        assert findings[0].subtype == "test_pattern"

    def test_no_match(self):
        detector = CustomRulesDetector()
        detector.add_rule("test", r"\bFOO-\d{3}\b")
        findings = detector.scan("Nothing matches here")
        assert len(findings) == 0


class TestClassificationRules:
    def test_credit_card_classification(self):
        cls = classify_finding("credit_card", "credit_card")
        assert cls["severity"] == "critical"
        assert cls["category"] == "financial"

    def test_cpf_classification(self):
        cls = classify_finding("pii", "cpf")
        assert cls["severity"] == "high"

    def test_unknown_classification(self):
        cls = classify_finding("unknown", "something")
        assert cls["severity"] == "medium"
