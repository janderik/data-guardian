import re
from typing import Dict, List, Optional
from .base import BaseDetector, Finding


class CreditCardDetector(BaseDetector):
    # Candidates in real card layouts, one consistent separator per number.
    # Brand and Luhn checks follow.
    PATTERNS: Dict[str, str] = {
        "credit_card": (
            r"(?<![\d-])(?:"
            r"\d{13,19}"  # no separators
            r"|\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?"  # 4-4-4-4(-1..3)
            r"|\d{4}([ -])\d{6}\2\d{4,5}"  # Amex 4-6-5, Diners 4-6-4
            r")(?![\d-])"
        ),
    }

    # Elo BIN ranges (first 6 digits), inclusive.
    ELO_BIN_RANGES = [
        (401178, 401179), (431274, 431274), (438935, 438935), (451416, 451416),
        (457393, 457393), (457631, 457632), (504175, 504175), (506699, 506778),
        (509000, 509999), (627780, 627780), (636297, 636297), (636368, 636368),
        (650031, 650033), (650035, 650051), (650405, 650439), (650485, 650538),
        (650541, 650598), (650700, 650718), (650720, 650727), (650901, 650978),
        (651652, 651679), (655000, 655019), (655021, 655058),
    ]

    # (brand, prefix regex, allowed lengths). Checked in order: the specific
    # Brazilian ranges (Elo, Hipercard) come before the broader ones.
    BRANDS = [
        ("elo", None, {16}),  # matched by ELO_BIN_RANGES below
        ("hipercard", re.compile(r"^(?:606282|3841(?:[046]0))"), {13, 16, 19}),
        ("amex", re.compile(r"^3[47]"), {15}),
        ("diners", re.compile(r"^(?:30[0-5]|309|36|3[89])"), {14, 16, 17, 18, 19}),
        ("jcb", re.compile(r"^35(?:2[89]|[3-8]\d)"), {16, 17, 18, 19}),
        ("discover", re.compile(r"^(?:6011|64[4-9]|65)"), {16, 17, 18, 19}),
        ("mastercard", re.compile(r"^(?:5[1-5]|2(?:2[2-9]|[3-6]\d|7[01])|2720)"), {16}),
        ("visa", re.compile(r"^4"), {13, 16, 19}),
    ]

    def __init__(self, sensitivity: str = "medium"):
        super().__init__(sensitivity)
        self._compile_patterns(self.PATTERNS)

    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        findings: List[Finding] = []
        for pattern_name in self._compiled_patterns:
            results = self._match_pattern(pattern_name, content, file_path)
            for f in results:
                if self._luhn_check(f.value) and self.card_brand(f.value):
                    findings.append(f)
        return findings

    @classmethod
    def card_brand(cls, number: str) -> Optional[str]:
        """Brand whose prefix and length match ``number``, or None."""
        digits = re.sub(r"\D", "", number)
        for brand, prefix, lengths in cls.BRANDS:
            if len(digits) not in lengths:
                continue
            if brand == "elo":
                bin6 = int(digits[:6])
                if any(lo <= bin6 <= hi for lo, hi in cls.ELO_BIN_RANGES):
                    return brand
            elif prefix.match(digits):
                return brand
        return None

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
