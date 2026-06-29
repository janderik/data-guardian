import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional
from .base import BaseDetector, Finding


class CustomRulesDetector(BaseDetector):
    def __init__(self, rules_file: Optional[str] = None, sensitivity: str = "medium"):
        super().__init__(sensitivity)
        self.rules: Dict[str, str] = {}
        if rules_file:
            self.load_rules(rules_file)

    def load_rules(self, rules_file: str) -> None:
        path = Path(rules_file)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {rules_file}")

        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            data = yaml.safe_load(content)
        elif path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(f"Unsupported rules file format: {path.suffix}")

        if not isinstance(data, dict):
            raise ValueError("Rules file must contain a dictionary of name: pattern pairs")

        for name, pattern in data.items():
            if isinstance(pattern, str):
                self.rules[name] = pattern

        self._compile_patterns(self.rules)

    def add_rule(self, name: str, pattern: str) -> None:
        self.rules[name] = pattern
        self._compile_patterns({name: pattern})

    def scan(self, content: str, file_path: str = "") -> List[Finding]:
        findings: List[Finding] = []
        for pattern_name in self._compiled_patterns:
            results = self._match_pattern(pattern_name, content, file_path)
            findings.extend(results)
        return findings
