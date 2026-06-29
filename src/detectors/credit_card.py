import re
from typing import List, Dict
from .base import BaseDetector, Finding


class CreditCardDetector(BaseDetector):
    PATTERNS: Dict[str, str] = {
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    }

    def __init__(self, sensitivity: str = "medium"):
        super().__init__(sensitivity)
        self._compile_patterns(self.PATTERNS)

    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        findings: List[Finding] = []
        for pattern_name in self._compiled_patterns:
            results = self._match_pattern(pattern_name, content, file_path)
            for f in results:
                if self._luhn_check(f.value):
                    findings.append(f)
        return findings

    @staticmethod
    def _luhn_check(number: str) -> bool:
        digits = re.sub(r"\D", "", number)
        if len(digits) < 13 or len(digits) > 19:
            return False
        if not digits.isdigit():
            return False

        total = 0
        reverse_digits = digits[::-1]
        for i, d in enumerate(reverse_digits):
            n = int(d)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
