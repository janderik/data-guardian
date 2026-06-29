import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    target: str
    total_files: int = 0
    total_findings: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    scan_duration: float = 0.0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_files": self.total_files,
            "total_findings": self.total_findings,
            "findings": self.findings,
            "scan_duration": round(self.scan_duration, 2),
            "errors": self.errors,
            "metadata": self.metadata,
        }


class BaseScanner(ABC):
    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity
        self.detectors: List = []

    def add_detector(self, detector: Any) -> None:
        self.detectors.append(detector)

    @abstractmethod
    def scan(self, target: str, **kwargs) -> ScanResult:
        ...

    def detect_in_content(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for detector in self.detectors:
            try:
                results = detector.scan(content, file_path)
                for f in results:
                    findings.append(f.to_dict())
            except Exception as e:
                logger.error(f"Detector {detector.__class__.__name__} failed on {file_path}: {e}")
        return findings
