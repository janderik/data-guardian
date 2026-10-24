import re
from typing import List, Dict
from .base import BaseDetector, Finding


class PIIDetector(BaseDetector):
    PATTERNS: Dict[str, str] = {
        "cpf": r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b",
        "cnpj": r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b",
        "rg": r"\b\d{1,2}\.\d{3}\.\d{3}[-]?[\dXx]\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "phone": r"(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)?\d{4,5}-?\d{4}\b",
        "cep": r"\b\d{5}-?\d{3}\b",
    }

    CPF_WEIGHTS = [10, 9, 8, 7, 6, 5, 4, 3, 2]
    CNPJ_WEIGHTS_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    CNPJ_WEIGHTS_2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]

    def __init__(self, sensitivity: str = "medium"):
        super().__init__(sensitivity)
        self._compile_patterns(self.PATTERNS)
        self._cpf_pattern = re.compile(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}")
        self._cnpj_pattern = re.compile(r"\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}")

    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        findings: List[Finding] = []
        for pattern_name in self._compiled_patterns:
            results = self._match_pattern(pattern_name, content, file_path)
            for f in results:
                if pattern_name == "cpf" and not self._validate_cpf(f.value):
                    continue
                if pattern_name == "cnpj" and not self._validate_cnpj(f.value):
                    continue
                findings.append(f)
        return findings

    def _validate_cpf(self, cpf: str) -> bool:
        digits = re.sub(r"\D", "", cpf)
        if len(digits) != 11 or all(d == digits[0] for d in digits):
            return False
        total = sum(int(digits[i]) * self.CPF_WEIGHTS[i] for i in range(9))
        d1 = (total * 10) % 11
        if d1 == 10:
            d1 = 0
        if d1 != int(digits[9]):
            return False
        # Second check digit: weights 11..2 over the first 10 digits.
        total = sum(int(digits[i]) * (11 - i) for i in range(10))
        d2 = (total * 10) % 11
        if d2 == 10:
            d2 = 0
        return d2 == int(digits[10])

    def _validate_cnpj(self, cnpj: str) -> bool:
        digits = re.sub(r"\D", "", cnpj)
        if len(digits) != 14 or all(d == digits[0] for d in digits):
            return False
        total = sum(int(digits[i]) * self.CNPJ_WEIGHTS_1[i] for i in range(12))
        d1 = total % 11
        if d1 < 2:
            d1 = 0
        else:
            d1 = 11 - d1
        if d1 != int(digits[12]):
            return False
        total = sum(int(digits[i]) * self.CNPJ_WEIGHTS_2[i] for i in range(13))
        d2 = total % 11
        if d2 < 2:
            d2 = 0
        else:
            d2 = 11 - d2
        return d2 == int(digits[13])
