import json
from typing import Any, List
from .base import BaseReporter


class JSONReporter(BaseReporter):
    def generate(self, results: Any, output_path: str = "") -> str:
        if isinstance(results, list):
            data = [r.to_dict() if hasattr(r, "to_dict") else r for r in results]
        elif hasattr(results, "to_dict"):
            data = results.to_dict()
        else:
            data = results

        payload = {
            "tool": "DataGuardian",
            "version": "1.0.0",
            "results": data,
            "summary": self._build_summary(results),
        }

        output = json.dumps(payload, indent=2, ensure_ascii=False)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(output)

        return output

    @classmethod
    def _build_summary(cls, results: Any) -> dict:
        if isinstance(results, list):
            total = sum(
                r.total_findings if hasattr(r, "total_findings") else len(r.get("findings", [])) if isinstance(r, dict) else 0
                for r in results
            )
            files = sum(
                r.total_files if hasattr(r, "total_files") else 0 for r in results
            )
        elif hasattr(results, "total_findings"):
            total = results.total_findings
            files = results.total_files
        else:
            total = 0
            files = 0

        return {
            "total_findings": total,
            "total_scanned": files,
            "severity_counts": cls._count_severities(results),
        }

    @staticmethod
    def _count_severities(results: Any) -> dict:
        counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        findings: List[dict] = []

        if isinstance(results, list):
            for r in results:
                if hasattr(r, "findings"):
                    findings.extend(r.findings)
                elif isinstance(r, dict):
                    findings.extend(r.get("findings", []))
        elif hasattr(results, "findings"):
            findings = results.findings

        for f in findings:
            sev = f.get("severity", "medium") if isinstance(f, dict) else "medium"
            if sev in counts:
                counts[sev] += 1

        return counts
