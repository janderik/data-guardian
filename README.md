# 🛡️ DataGuardian - Data Security Scanner

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
[![CI](https://github.com/janderik/data-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/janderik/data-guardian/actions/workflows/ci.yml)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)

**DataGuardian** is a powerful, extensible data security scanner that discovers sensitive information across databases, filesystems, and file archives. It detects PII (Brazilian CPF, CNPJ, RG), credit card numbers, credentials, API keys, and custom patterns.

## ✨ Features

- **Database Scanning** — Scan PostgreSQL, MySQL, and SQLite databases for sensitive columns
- **Filesystem Scanning** — Recursively scan directories for files containing sensitive data
- **PII Detection** — Brazilian PII: CPF, CNPJ, RG, phone, CEP, email
- **Credit Card Detection** — Luhn algorithm validation for all major card brands
- **Credential Detection** — API keys, passwords, tokens, AWS keys, private keys
- **Custom Rules** — YAML/JSON-based custom regex rules
- **Multiple Reporters** — JSON and HTML output with detailed findings
- **Rich CLI** — Colored output, progress bars, real-time statistics
- **Docker Support** — Ready-to-run container image

## 📦 Installation

### pip

```bash
pip install dataguardian
```

### From source

```bash
git clone https://github.com/janderik/data-guardian.git
cd data-guardian
pip install -e .
```

### Docker

```bash
docker build -t dataguardian .
docker run --rm -v $(pwd):/scan dataguardian scan /scan
```

## 🚀 Usage

### Scan a directory

```bash
dataguardian scan ./my-project
```

### Scan a database

```bash
dataguardian scan-db --db-type postgresql --host localhost --dbname mydb --user admin
```

### Custom sensitivity

```bash
dataguardian scan ./data --sensitivity high --threads 8
```

### Output to file

```bash
dataguardian scan ./secrets --output report.json
dataguardian scan ./secrets --format html --output report.html
```

## 📊 Output Example

```
╭────────────────────────────────────────────╮
│         DataGuardian Scan Results          │
│────────────────────────────────────────────│
│  Files Scanned:    1,247                   │
│  Findings Found:   23                      │
│  Scan Duration:    12.4s                   │
│  Sensitivity:      medium                  │
╰────────────────────────────────────────────╯

┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Type              ┃ Count  ┃ Risk Level    ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Credit Card       │ 3      │ 🔴 Critical   │
│ CPF/CNPJ          │ 8      │ 🟠 High       │
│ API Key           │ 5      │ 🟠 High       │
│ Email             │ 7      │ 🟡 Medium     │
│ Phone             │ 2      │ 🟢 Low        │
└━━━━━━━━━━━━━━━━━━━┴━━━━━━━━┴━━━━━━━━━━━━━━━┘
```

## 🧪 Running Tests

```bash
pytest tests/ -v
```

## 📄 License

MIT
