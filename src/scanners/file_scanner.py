import logging
from pathlib import Path
from typing import List, Optional
from .base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pyc", ".pyo",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cpp", ".c", ".h",
    ".rb", ".go", ".rs", ".swift", ".kt", ".scala",
    ".php", ".pl", ".pm", ".lua",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini", ".cfg", ".conf",
    ".md", ".txt", ".rst", ".csv", ".log",
    ".env", ".envrc",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".sql", ".db", ".sqlite",
    ".html", ".htm", ".css", ".scss", ".less",
    ".tf", ".tfvars", ".hcl",
    ".dockerfile", ".dockerignore",
    ".gitignore", ".gitattributes",
    ".pem", ".key", ".cert",
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", "node_modules",
    ".venv", "venv", "env", ".env", ".tox", ".eggs",
    "dist", "build", ".idea", ".vscode",
}


class FileScanner(BaseScanner):
    def __init__(
        self,
        sensitivity: str = "medium",
        max_size_mb: int = 10,
        skip_binary: bool = True,
    ):
        super().__init__(sensitivity)
        self.max_size = max_size_mb * 1024 * 1024
        self.skip_binary = skip_binary

    def scan(self, target: str, **kwargs) -> ScanResult:
        path = Path(target)
        if not path.exists():
            return ScanResult(
                target=target,
                errors=[f"Path does not exist: {target}"],
            )

        if path.is_file():
            return self._scan_file(path)
        return self._scan_directory(path)

    def _scan_file(self, file_path: Path) -> ScanResult:
        result = ScanResult(target=str(file_path))
        try:
            content = self._read_file(file_path)
            if content is not None:
                result.total_files = 1
                findings = self.detect_in_content(content, str(file_path))
                result.findings = findings
                result.total_findings = len(findings)
        except Exception as e:
            result.errors.append(f"Error scanning {file_path}: {e}")
        return result

    def _scan_directory(self, directory: Path) -> ScanResult:
        result = ScanResult(target=str(directory))
        for file_path in self._walk_files(directory):
            try:
                content = self._read_file(file_path)
                if content is not None:
                    result.total_files += 1
                    findings = self.detect_in_content(content, str(file_path))
                    result.findings.extend(findings)
                    result.total_findings = len(result.findings)
            except Exception as e:
                result.errors.append(f"Error scanning {file_path}: {e}")
        return result

    def _walk_files(self, directory: Path) -> List[Path]:
        files: List[Path] = []
        try:
            for entry in directory.rglob("*"):
                if not entry.is_file():
                    continue
                if any(part in SKIP_DIRS for part in entry.relative_to(directory).parts):
                    continue
                if self.skip_binary and entry.suffix.lower() in BINARY_EXTENSIONS:
                    continue
                if entry.suffix.lower() not in TEXT_EXTENSIONS:
                    continue
                files.append(entry)
        except PermissionError as e:
            logger.warning(f"Permission denied: {e}")
        return files

    def _read_file(self, file_path: Path) -> Optional[str]:
        try:
            if file_path.stat().st_size > self.max_size:
                logger.debug(f"Skipping large file: {file_path}")
                return None
            return file_path.read_text(encoding="utf-8", errors="replace")
        except (UnicodeDecodeError, PermissionError, OSError) as e:
            logger.debug(f"Cannot read {file_path}: {e}")
            return None
