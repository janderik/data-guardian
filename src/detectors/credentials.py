from typing import List, Dict
from .base import BaseDetector, Finding


class CredentialDetector(BaseDetector):
    PATTERNS: Dict[str, str] = {
        "aws_key": r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])",
        # Needs AWS context: a bare 40-char token also matches every SHA-1 / git hash.
        "aws_secret": r"(?i)aws.{0,20}?(?:secret|key).{0,20}?[:=]\s*['\"]?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "api_key": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,64}['\"]?",
        "password": r"(?i)(?:password|passwd|pwd|secret|senha)\s*[:=]\s*['\"]?[^\s'\"\n,;]{6,}['\"]?",
        # RSA, EC, DSA, OPENSSH, ENCRYPTED and plain PKCS#8 keys.
        "private_key": r"-----BEGIN\s+(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY-----",
        "jwt_token": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "generic_secret": (
            r"(?i)(?:(?:token|secret|auth)\s*[:=]\s*['\"]?|bearer\s+)[A-Za-z0-9_\-\.]{16,}['\"]?"
        ),
    }

    def __init__(self, sensitivity: str = "medium"):
        super().__init__(sensitivity)
        self._compile_patterns(self.PATTERNS)

    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        findings: List[Finding] = []
        for pattern_name in self._compiled_patterns:
            results = self._match_pattern(pattern_name, content, file_path)
            findings.extend(results)
        return findings
