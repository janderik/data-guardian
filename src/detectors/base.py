import re
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


_TOKEN = re.compile(r"\S+")


def mask_text(value: str) -> str:
    """Keep the first and last two characters, hide the rest."""
    if len(value) <= 6:
        return value[:1] + "*" * (len(value) - 1)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _mask_if_sensitive(match: "re.Match[str]") -> str:
    word = match.group(0)
    if any(ch.isdigit() for ch in word) or "@" in word or len(word) >= 12:
        return mask_text(word)
    return word


def safe_context(content: str, start: int, end: int, max_chars: int = 40) -> str:
    """Label text before a match plus the masked match.

    Reports must not become a new copy of the sensitive data they point to,
    so only the text *before* the match on the same line is kept (usually a
    label such as "CPF:" or "password ="). Any word in it that could itself be
    sensitive (has a digit or "@", or is 12+ characters long) is masked, and
    so is the match. Text after the match is dropped because it often holds
    the next sensitive value.
    """
    line_start = content.rfind("\n", 0, start) + 1
    before = content[max(line_start, start - max_chars) : start]
    before = _TOKEN.sub(_mask_if_sensitive, before)
    return (before + mask_text(content[start:end].strip())).strip()


class Finding:
    def __init__(
        self,
        detector_type: str,
        subtype: str,
        value: str,
        line: int = 0,
        column: int = 0,
        file_path: str = "",
        context: str = "",
        severity: str = "medium",
        category: str = "unknown",
        risk: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.detector_type = detector_type
        self.subtype = subtype
        self.value = value
        self.line = line
        self.column = column
        self.file_path = file_path
        self.context = context
        self.severity = severity
        self.category = category
        self.risk = risk or subtype
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_type": self.detector_type,
            "subtype": self.subtype,
            "value": self.mask_value(),
            "line": self.line,
            "column": self.column,
            "file_path": self.file_path,
            "context": self.context,
            "severity": self.severity,
            "category": self.category,
            "risk": self.risk,
        }

    def mask_value(self) -> str:
        return mask_text(self.value)

    def __repr__(self) -> str:
        return f"Finding(type={self.detector_type}, subtype={self.subtype}, severity={self.severity})"


class BaseDetector(ABC):
    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity
        self.findings: List[Finding] = []
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    @abstractmethod
    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        ...

    def _compile_patterns(self, patterns: Dict[str, str]) -> None:
        for name, pattern in patterns.items():
            try:
                self._compiled_patterns[name] = re.compile(pattern, re.MULTILINE)
            except re.error as e:
                logger.error(f"Failed to compile pattern '{name}': {e}")

    def _match_pattern(
        self,
        pattern_name: str,
        content: str,
        file_path: str = "",
        context_chars: int = 40,
    ) -> List[Finding]:
        findings: List[Finding] = []
        pattern = self._compiled_patterns.get(pattern_name)
        if not pattern:
            return findings

        for match in pattern.finditer(content):
            value = match.group(0).strip()
            if not value:
                continue

            context = safe_context(content, match.start(), match.end(), context_chars)

            line_num = content[: match.start()].count("\n") + 1

            finding = self._make_finding(
                subtype=pattern_name,
                value=value,
                line=line_num,
                column=match.start() - content.rfind("\n", 0, match.start()) - 1,
                file_path=file_path,
                context=context,
            )
            findings.append(finding)

        return findings

    def _make_finding(
        self,
        subtype: str,
        value: str,
        line: int = 0,
        column: int = 0,
        file_path: str = "",
        context: str = "",
    ) -> Finding:
        from rules.classification_rules import classify_finding
        cls = classify_finding(self.__class__.__name__.replace("Detector", "").lower(), subtype)
        return Finding(
            detector_type=self.__class__.__name__.replace("Detector", "").lower(),
            subtype=subtype,
            value=value,
            line=line,
            column=column,
            file_path=file_path,
            context=context,
            severity=cls["severity"],
            category=cls["category"],
            risk=cls["risk"],
        )
