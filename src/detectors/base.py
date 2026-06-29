import re
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


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
        v = self.value
        if len(v) <= 6:
            return v[:1] + "*" * (len(v) - 1)
        return v[:2] + "*" * (len(v) - 4) + v[-2:]

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

            start = max(0, match.start() - context_chars)
            end = min(len(content), match.end() + context_chars)
            context = content[start:end].replace("\n", " ").strip()

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
