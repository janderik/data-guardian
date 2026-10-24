import sys
import os
import tempfile
import pytest
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from scanners.file_scanner import FileScanner
from scanners.filesystem_scanner import FilesystemScanner
from scanners.database_scanner import DatabaseScanner
from scanners.base import ScanResult
from detectors.pii_detector import PIIDetector
from detectors.credit_card import CreditCardDetector
from detectors.credentials import CredentialDetector


class TestFileScanner:
    def test_scan_file_with_pii(self, tmp_path):
        d = tmp_path / "test.txt"
        d.write_text("CPF: 529.982.247-25 and email: user@test.com", encoding="utf-8")

        scanner = FileScanner()
        scanner.add_detector(PIIDetector())
        result = scanner.scan(str(d))
        assert result.total_findings >= 1
        assert result.total_files == 1

    def test_scan_clean_file(self, tmp_path):
        d = tmp_path / "clean.txt"
        d.write_text("This is a clean file with no sensitive data.", encoding="utf-8")

        scanner = FileScanner()
        scanner.add_detector(PIIDetector())
        result = scanner.scan(str(d))
        assert result.total_findings == 0

    def test_scan_nonexistent(self):
        scanner = FileScanner()
        result = scanner.scan("/nonexistent/path/12345")
        assert len(result.errors) > 0

    def test_scan_directory(self, tmp_path):
        (tmp_path / "file1.txt").write_text("user@example.com", encoding="utf-8")
        (tmp_path / "file2.txt").write_text("normal text", encoding="utf-8")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "file3.txt").write_text("password=secret123", encoding="utf-8")

        scanner = FileScanner()
        scanner.add_detector(PIIDetector())
        scanner.add_detector(CredentialDetector())
        result = scanner.scan(str(tmp_path))
        assert result.total_findings >= 2
        assert result.total_files == 3


class TestDatabaseScanner:
    def test_classify_column(self):
        scanner = DatabaseScanner()
        assert scanner._classify_column("cpf") == "cpf"
        assert scanner._classify_column("email_address") == "email"
        assert scanner._classify_column("user_password") == "password"
        assert scanner._classify_column("telefone_celular") == "phone"
        assert scanner._classify_column("id") is None
        assert scanner._classify_column("created_at") is None

    def test_scan_sqlite(self, tmp_path):
        import sqlite3
        db_path = str(tmp_path / "test.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE users (id INTEGER, cpf TEXT, email TEXT, name TEXT)")
        conn.execute("INSERT INTO users VALUES (1, '529.982.247-25', 'test@test.com', 'Joao')")
        conn.commit()
        conn.close()

        scanner = DatabaseScanner()
        result = scanner.scan(target=db_path, db_type="sqlite")
        assert result.total_findings >= 2
        assert any("cpf" in str(f) for f in result.findings)
        assert any("email" in str(f) for f in result.findings)

    def test_scan_sqlite_empty(self, tmp_path):
        import sqlite3
        db_path = str(tmp_path / "empty.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE logs (id INTEGER, message TEXT)")
        conn.commit()
        conn.close()

        scanner = DatabaseScanner()
        result = scanner.scan(target=db_path, db_type="sqlite")
        assert result.total_findings == 0

    def test_unsupported_db(self):
        scanner = DatabaseScanner()
        result = scanner.scan(db_type="oracle")
        assert len(result.errors) > 0


class TestScanResult:
    def test_to_dict(self):
        result = ScanResult(
            target="/test",
            total_files=5,
            total_findings=3,
            findings=[{"type": "cpf", "severity": "high"}],
            scan_duration=1.5,
        )
        d = result.to_dict()
        assert d["target"] == "/test"
        assert d["total_files"] == 5
        assert d["total_findings"] == 3
        assert d["scan_duration"] == 1.5


class TestIntegration:
    def test_full_scan_pipeline(self, tmp_path):
        sensitive = tmp_path / "sensitive.txt"
        sensitive.write_text(
            "CPF: 529.982.247-25\nCredit: 4111 1111 1111 1111\nEmail: admin@company.com",
            encoding="utf-8",
        )

        scanner = FilesystemScanner()
        scanner.add_detector(PIIDetector())
        scanner.add_detector(CreditCardDetector())

        result = scanner.scan(str(tmp_path))
        assert result.total_findings >= 3

        types = {f["subtype"] for f in result.findings}
        assert "cpf" in types
        assert "credit_card" in types
        assert "email" in types


SECRETS = {
    "cpf": "529.982.247-25",
    "card": "4111 1111 1111 1111",
    "password": "MyS3cur3P@ss!",
    "email": "admin@company.com",
}


def _scan_sensitive_file(tmp_path):
    (tmp_path / "leak.txt").write_text(
        f"CPF: {SECRETS['cpf']} Card: {SECRETS['card']}\n"
        f"password = {SECRETS['password']}\n"
        f"Email: {SECRETS['email']}\n",
        encoding="utf-8",
    )
    scanner = FilesystemScanner()
    for detector in (PIIDetector(), CreditCardDetector(), CredentialDetector()):
        scanner.add_detector(detector)
    return scanner.scan(str(tmp_path))


@pytest.mark.parametrize("fmt", ["json", "html"])
def test_reports_never_contain_the_sensitive_values(tmp_path, fmt):
    from reporters.html_reporter import HTMLReporter
    from reporters.json_reporter import JSONReporter

    result = _scan_sensitive_file(tmp_path)
    assert result.total_findings >= 4
    reporter = JSONReporter() if fmt == "json" else HTMLReporter()
    output = reporter.generate(result)
    for name, secret in SECRETS.items():
        assert secret not in output, f"{name} leaked into the {fmt} report"


def test_html_report_escapes_scanned_content(tmp_path):
    from reporters.html_reporter import HTMLReporter

    (tmp_path / "x.txt").write_text("<script>alert(1)</script> CPF: 529.982.247-25", encoding="utf-8")
    scanner = FilesystemScanner()
    scanner.add_detector(PIIDetector())
    output = HTMLReporter().generate(scanner.scan(str(tmp_path)))
    assert "<script>alert(1)" not in output
