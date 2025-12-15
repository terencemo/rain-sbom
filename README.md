# 🌧️ RAIN SBOM

**RAIN Ain't Inventory Notation** - A modern, fast SBOM (Software Bill of Materials) parser, analyzer, and comparison tool.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)

Parse CycloneDX and SPDX files, track dependencies, compare versions, and analyze your software supply chain - all with a clean CLI and web interface.

---

## ✨ Features

- 📦 **Multi-Format Support**: Parse CycloneDX (1.4, 1.5) and SPDX (2.2, 2.3)
- 🔍 **SBOM Comparison**: Visual diff showing added/removed/changed components
- 💾 **Persistent Storage**: SQLite database with full relationship tracking
- 🌐 **REST API**: Complete FastAPI backend with auto-generated docs
- 🎨 **Modern Web UI**: htmx + Tailwind CSS interface (no heavy frameworks)
- ⚡ **Async Everything**: Fast, non-blocking operations throughout
- 🛡️ **Type-Safe**: Full type annotations with Pyright strict mode
- 🧪 **Well-Tested**: Comprehensive test suite with fixtures
- 📋 **CLI Tool**: Parse, store, list, and compare from command line

---

## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/terencemo/rain-sbom.git
cd rain-sbom

# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync --all-extras

# Activate virtual environment
source .venv/bin/activate
```

### CLI Usage
```bash
# Parse an SBOM file
python -m rain parse sbom.json

# Parse and save to database
python -m rain parse sbom.json --save --name "Production v1.2"

# Output as JSON
python -m rain parse sbom.json --json

# List stored SBOMs
python -m rain list

# Compare two SBOMs
python -m rain compare sbom-v1.json sbom-v2.json
```

### Web Interface
```bash
# Start server
uvicorn rain.main:app --reload

# Open browser
http://localhost:8000
```

### API Usage
```bash
# Upload SBOM
curl -X POST http://localhost:8000/api/sboms \
  -F "file=@sbom.json" \
  -F "name=My App v1.0"

# List all SBOMs
curl http://localhost:8000/api/sboms

# Get SBOM details
curl http://localhost:8000/api/sboms/1

# Compare two SBOMs
curl -X POST "http://localhost:8000/api/compare?sbom1_id=1&sbom2_id=2"

# API Documentation
http://localhost:8000/docs
```

---

## 📖 Documentation

### Supported Formats

#### CycloneDX
- ✅ Version 1.4
- ✅ Version 1.5
- ✅ Components, dependencies, licenses
- ✅ Vulnerability data (if present)

#### SPDX
- ✅ Version 2.2
- ✅ Version 2.3
- ✅ Packages, relationships, licenses
- ✅ External references (purl support)

### Comparison Features

When comparing two SBOMs, RAIN shows:
- **Added Components**: New dependencies in the second SBOM
- **Removed Components**: Dependencies removed from the first SBOM
- **Version Changes**: Components with different versions
- **License Changes**: Components with modified licenses
- **Summary Statistics**: Quick overview of changes

### Database Schema

RAIN stores SBOMs in a SQLite database with three main tables:
- `sboms`: SBOM metadata and raw JSON
- `components`: Individual software components/packages
- `vulnerabilities`: Security vulnerabilities (if present)

Database location: `~/.local/share/rain/sboms.db`

---

## 🏗️ Architecture

### Project Structure
```
rain-sbom/
├── src/
│   ├── rain/
│   │   ├── api/              # FastAPI routes (future)
│   │   ├── cli.py            # Command-line interface
│   │   ├── main.py           # FastAPI application
│   │   ├── models/           # Data models
│   │   │   ├── database.py   # SQLAlchemy ORM models
│   │   │   └── domain.py     # Business logic models
│   │   ├── parsers/          # Format parsers
│   │   │   ├── base.py       # Abstract parser interface
│   │   │   ├── cyclonedx.py  # CycloneDX parser
│   │   │   └── spdx.py       # SPDX parser
│   │   ├── services/         # Business logic
│   │   │   ├── sbom_service.py     # SBOM operations
│   │   │   └── compare_service.py  # Comparison logic
│   │   ├── db/               # Database layer
│   │   │   └── session.py    # Async session management
│   │   └── templates/        # Jinja2 templates
│   └── static/               # CSS, JS (future)
├── tests/                    # Test suite
│   ├── fixtures/             # Sample SBOM files
│   └── test_parsers/         # Parser tests
├── pyproject.toml            # Project configuration
└── README.md
```

### Technology Stack

- **Backend**: FastAPI 0.109+, SQLAlchemy 2.0+ (async), aiosqlite
- **Frontend**: htmx 1.9+, Alpine.js 3.13+, Tailwind CSS 3+
- **Database**: SQLite (with async support)
- **Type Checking**: Pyright (strict mode)
- **Linting**: Ruff
- **Testing**: pytest, pytest-asyncio, httpx
- **Package Management**: uv

---

## 🧪 Development

### Setup Development Environment
```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
pytest -v

# Run tests with coverage
pytest --cov=rain --cov-report=html

# Type checking
pyright src/

# Linting
ruff check .

# Auto-format
ruff format .
```

### Running Tests
```bash
# All tests
pytest

# Specific test file
pytest tests/test_parsers/test_cyclonedx.py -v

# With coverage report
pytest --cov=rain --cov-report=term-missing

# Watch mode (auto-run on file changes)
pip install pytest-watch
ptw
```

### Adding a New SBOM Format

1. Create parser in `src/rain/parsers/yourformat.py`
2. Inherit from `BaseParser`
3. Implement `parse()` and `can_parse()` methods
4. Register in `parsers/__init__.py`
5. Add test fixtures and tests

Example:
```python
from .base import BaseParser, ParserError
from ..models.domain import ParsedSBOM

class YourFormatParser(BaseParser):
    async def parse(self, data: dict) -> ParsedSBOM:
        # Implementation
        pass
    
    @staticmethod
    def can_parse(data: dict) -> bool:
        return data.get("format") == "your-format"
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`pytest -v`)
5. Run type checking (`pyright src/`)
6. Format code (`ruff format .`)
7. Commit changes (`git commit -m 'Add amazing feature'`)
8. Push to branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

### Development Guidelines

- Maintain 80%+ test coverage
- Follow type annotations (Pyright strict mode)
- Use `ruff format` before committing
- Write descriptive commit messages
- Update documentation for new features

---

## 📊 Use Cases

### Supply Chain Security
Track dependencies across application versions, identify when vulnerable components are introduced, and ensure license compliance.

### Release Management
Compare SBOMs between releases to understand what changed in your dependency tree.

### Compliance Auditing
Store historical SBOMs for compliance requirements, generate reports showing dependency evolution over time.

### CI/CD Integration
Integrate RAIN into your CI/CD pipeline to automatically analyze SBOMs on every build.

---

## 🎯 Roadmap

- [x] CycloneDX parser (1.4, 1.5)
- [x] SPDX parser (2.2, 2.3)
- [x] Database storage
- [x] REST API
- [x] Web UI with htmx
- [x] SBOM comparison
- [ ] Vulnerability database integration (OSV, NVD)
- [ ] Historical trend analysis
- [ ] Export reports (PDF, HTML)
- [ ] SWID tags support
- [ ] Docker image
- [ ] GitHub Action
- [ ] CLI as standalone binary

---

## 📝 License

Apache License 2.0 - See [LICENSE](LICENSE) file for details

---

## 👤 Author

**Terence Monteiro**
- GitHub: [@terencemo](https://github.com/terencemo)
- Apache Fineract PMC Member
- Solutions Architect at SanJose Solutions LLC

---

## 🙏 Acknowledgments

- Inspired by the need for better SBOM tooling in the open source community
- Built with support from the Apache Software Foundation community
- CycloneDX and SPDX specifications from OWASP and Linux Foundation

---

## 📚 Resources

- [CycloneDX Specification](https://cyclonedx.org)
- [SPDX Specification](https://spdx.dev)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [FastAPI Documentation](https://fastapi.tiangolo.com)
- [htmx Documentation](https://htmx.org)

---

**RAIN Ain't Inventory Notation** - Because your dependencies deserve clarity, not chaos. ☔
