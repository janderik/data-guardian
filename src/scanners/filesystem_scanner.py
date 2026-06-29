from pathlib import Path
from typing import Optional
from .file_scanner import FileScanner
from .base import ScanResult


class FilesystemScanner(FileScanner):
    def __init__(
        self,
        sensitivity: str = "medium",
        max_size_mb: int = 10,
        max_depth: Optional[int] = None,
        skip_binary: bool = True,
    ):
        super().__init__(sensitivity, max_size_mb, skip_binary)
        self.max_depth = max_depth

    def _walk_files(self, directory: Path) -> list:
        from .file_scanner import SKIP_DIRS

        files: list = []
        try:
            for entry in directory.rglob("*"):
                if not entry.is_file():
                    continue
                rel = entry.relative_to(directory)
                if any(part in SKIP_DIRS for part in rel.parts):
                    continue
                if self.max_depth is not None and len(rel.parts) > self.max_depth:
                    continue
                if self.skip_binary and entry.suffix.lower() in {
                    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                    ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll",
                    ".mp3", ".mp4", ".avi", ".pyc",
                }:
                    continue
                if entry.suffix.lower() not in {
                    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb",
                    ".yml", ".yaml", ".json", ".xml", ".toml", ".ini",
                    ".md", ".txt", ".csv", ".log",
                    ".env", ".sh", ".bash", ".ps1", ".bat",
                    ".sql", ".html", ".css",
                    ".tf", ".hcl",
                    ".pem", ".key",
                    ".gitignore", ".dockerfile",
                }:
                    continue
                files.append(entry)
        except PermissionError:
            pass
        return files

    def scan(self, target: str, **kwargs) -> ScanResult:
        return super().scan(target, **kwargs)
