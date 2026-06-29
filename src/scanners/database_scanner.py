import logging
from typing import List, Dict, Any, Optional
from .base import BaseScanner, ScanResult

logger = logging.getLogger(__name__)

SENSITIVE_COLUMN_PATTERNS = {
    "cpf": ["cpf", "documento", "doc"],
    "cnpj": ["cnpj"],
    "email": ["email", "e_mail", "mail"],
    "phone": ["phone", "telefone", "celular", "cel", "fone", "tel"],
    "cep": ["cep", "zip", "postal"],
    "credit_card": ["credit_card", "card_number", "cartao", "cc_number", "pan"],
    "password": ["password", "passwd", "pwd", "senha", "hash_pass"],
    "rg": ["rg", "identidade", "identity"],
}

DB_TYPE_CONFIGS = {
    "postgresql": {
        "column_query": """
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
            ORDER BY table_name, ordinal_position
        """,
        "sample_query": "SELECT {columns} FROM {table} LIMIT 5",
    },
    "mysql": {
        "column_query": """
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            ORDER BY table_name, ordinal_position
        """,
        "sample_query": "SELECT {columns} FROM {table} LIMIT 5",
    },
    "sqlite": {
        "column_query": (
            "SELECT tbl_name as table_name, name as column_name, type as data_type "
            "FROM sqlite_master CROSS JOIN pragma_table_info(sqlite_master.name) "
            "WHERE type='table' ORDER BY tbl_name"
        ),
        "sample_query": "SELECT {columns} FROM {table} LIMIT 5",
    },
}


class DatabaseScanner(BaseScanner):
    def __init__(self, sensitivity: str = "medium"):
        super().__init__(sensitivity)

    def scan(
        self,
        target: str = "",
        db_type: str = "sqlite",
        host: str = "localhost",
        port: Optional[int] = None,
        dbname: str = "",
        user: str = "",
        password: str = "",
        **kwargs,
    ) -> ScanResult:
        result = ScanResult(target=f"{db_type}://{host}/{dbname}")

        if db_type == "sqlite":
            return self._scan_sqlite(target, result)

        if db_type == "postgresql":
            return self._scan_postgresql(host, port or 5432, dbname, user, password, result)

        if db_type == "mysql":
            return self._scan_mysql(host, port or 3306, dbname, user, password, result)

        result.errors.append(f"Unsupported database type: {db_type}")
        return result

    def _scan_sqlite(self, db_path: str, result: ScanResult) -> ScanResult:
        import sqlite3
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            columns = self._get_columns_sqlite(cursor)
            for table, col_list in columns.items():
                for col_name, col_type in col_list:
                    match = self._classify_column(col_name)
                    if match:
                        result.total_findings += 1
                        result.findings.append({
                            "detector_type": "database",
                            "subtype": match,
                            "value": col_name,
                            "file_path": f"{db_path}/{table}",
                            "severity": "medium",
                            "category": "sensitive_column",
                            "risk": f"Sensitive column: {col_name} ({match})",
                        })
                        result.total_files += 1
            conn.close()
        except Exception as e:
            result.errors.append(f"SQLite error: {e}")
        return result

    def _scan_postgresql(
        self, host: str, port: int, dbname: str, user: str, password: str, result: ScanResult
    ) -> ScanResult:
        try:
            import psycopg2
            conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)
            cursor = conn.cursor()
            cursor.execute(DB_TYPE_CONFIGS["postgresql"]["column_query"])
            rows = cursor.fetchall()
            tables: Dict[str, List] = {}
            for table, col, dtype in rows:
                tables.setdefault(table, []).append((col, dtype))
            for table, col_list in tables.items():
                for col_name, col_type in col_list:
                    match = self._classify_column(col_name)
                    if match:
                        result.total_findings += 1
                        result.findings.append({
                            "detector_type": "database",
                            "subtype": match,
                            "value": col_name,
                            "file_path": f"{dbname}/{table}",
                            "severity": "medium",
                            "category": "sensitive_column",
                            "risk": f"Sensitive column: {col_name} ({match})",
                        })
                        result.total_files += 1
            conn.close()
        except ImportError:
            result.errors.append("psycopg2 not installed. Install with: pip install psycopg2-binary")
        except Exception as e:
            result.errors.append(f"PostgreSQL error: {e}")
        return result

    def _scan_mysql(
        self, host: str, port: int, dbname: str, user: str, password: str, result: ScanResult
    ) -> ScanResult:
        try:
            import mysql.connector
            conn = mysql.connector.connect(host=host, port=port, database=dbname, user=user, password=password)
            cursor = conn.cursor()
            cursor.execute(DB_TYPE_CONFIGS["mysql"]["column_query"])
            rows = cursor.fetchall()
            tables: Dict[str, List] = {}
            for table, col, dtype in rows:
                tables.setdefault(table, []).append((col, dtype))
            for table, col_list in tables.items():
                for col_name, col_type in col_list:
                    match = self._classify_column(col_name)
                    if match:
                        result.total_findings += 1
                        result.findings.append({
                            "detector_type": "database",
                            "subtype": match,
                            "value": col_name,
                            "file_path": f"{dbname}/{table}",
                            "severity": "medium",
                            "category": "sensitive_column",
                            "risk": f"Sensitive column: {col_name} ({match})",
                        })
                        result.total_files += 1
            conn.close()
        except ImportError:
            result.errors.append("mysql-connector-python not installed. Install with: pip install mysql-connector-python")
        except Exception as e:
            result.errors.append(f"MySQL error: {e}")
        return result

    @staticmethod
    def _get_columns_sqlite(cursor) -> Dict[str, List]:
        tables: Dict[str, List] = {}
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        for (tname,) in cursor.fetchall():
            cursor.execute(f"PRAGMA table_info(\"{tname}\")")
            cols = [(row[1], row[2]) for row in cursor.fetchall()]
            tables[tname] = cols
        return tables

    @staticmethod
    def _classify_column(col_name: str) -> Optional[str]:
        lower = col_name.lower().replace("_", "").replace("-", "")
        for pii_type, patterns in SENSITIVE_COLUMN_PATTERNS.items():
            for p in patterns:
                if p in lower:
                    return pii_type
        return None
