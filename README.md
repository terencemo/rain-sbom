# 🌧️ RAIN SBOM

**RAIN Ain't Inventory Notation**

A fast, lightweight SBOM (Software Bill of Materials) parser, comparator, and analyzer. Parse CycloneDX and SPDX files, compare versions, and track your software supply chain dependencies.

> "Not all those who wander are lost... but they should track their dependencies." 

## Features

- 📦 **Parse Multiple Formats**
  - CycloneDX (1.4, 1.5)
  - SPDX (2.2, 2.3)
  - Auto-detection of format

- 🔍 **Compare SBOMs**
  - Identify added/removed components
  - Track version changes
  - Highlight license changes
  - Flag new vulnerabilities

- ⚡ **Fast & Async**
  - Async file processing
  - Handle large SBOMs (10MB+)
  - Concurrent operations

- 🎨 **Lightweight UI**
  - htmx + Alpine.js (no heavy frameworks)
  - Drag-and-drop upload
  - Real-time comparison results
  - Mobile responsive

- 🛡️ **Type-Safe**
  - Full type annotations
  - Pyright strict mode
  - Runtime validation with Pydantic

## Quick Start

### Prerequisites

 - Python 3.11 or higher
 - uv (Python package manager)

### Installation
	```bash
# Clone repository
	git clone https://github.com/terencemo/rain-sbom.git
cd rain-sbom

# Install dependencies
uv sync

# Activate virtual environment
source .venv/bin/activate

# Run development server
uvicorn rain.main:app --reload
```
Open your browser to http://localhost:8000

### Using the CLI
```bash
# Parse an SBOM
rain parse sbom.json

# Compare two SBOMs
rain compare old.json new.json

# List stored SBOMs
rain list
```

## Usage

### Upload SBOM via Web UI

1. Navigate to http://localhost:8000
2. Drag and drop your SBOM file (or click to select)
3. View parsed components and metadata

### Compare SBOMs

1. Upload two SBOM files
2. Select both from the comparison dropdown
3. Click "Compare"
4. View added/removed/changed components

### REST API
```bash
# Upload SBOM
curl -X POST http://localhost:8000/api/sboms \
  -F "file=@sbom.json"

# List SBOMs
curl http://localhost:8000/api/sboms

# Compare two SBOMs
curl -X POST http://localhost:8000/api/compare \
  -H "Content-Type: application/json" \
  -d '{"sbom1_id": 1, "sbom2_id": 2}'
```

API documentation available at http://localhost:8000/docs

## Development

### Project Structure
```
rain-sbom/
├── src/
│   ├── rain/
│   │   ├── api/           # FastAPI routes
│   │   ├── services/      # Business logic
│   │   ├── parsers/       # SBOM format parsers
│   │   ├── models/        # Data models
│   │   └── db/            # Database layer
│   └── static/            # CSS, JS
├── tests/                 # Test suite
├── pyproject.toml         # Project config
└── README.md
```

### Running Tests
```bash
# Run all tests
pytest -v

# Run with coverage
pytest --cov=rain --cov-report=html
open htmlcov/index.html

# Run specific test file
pytest tests/test_parsers.py -v

# Watch mode (auto-run on changes)
pip install pytest-watch
ptw
```

### Code Quality
```bash
# Type checking
pyright src/

# Linting
ruff check .

# Auto-format
ruff format .

# Run all checks
ruff check . && pyright src/ && pytest -v
```

### Adding a New SBOM Format

1. Create parser in `src/rain/parsers/yourformat.py`
2. Inherit from `BaseParser`
3. Implement `parse()` method
4. Register in `parsers/__init__.py`
5. Add tests in `tests/test_parsers.py`

## Technology Stack

- **Backend**: FastAPI, SQLAlchemy, aiosqlite
- **Frontend**: htmx, Alpine.js, Tailwind CSS (CDN)
- **Database**: SQLite
- **Type Checking**: Pyright
- **Linting**: Ruff
- **Testing**: pytest, pytest-asyncio, httpx
- **Package Management**: uv

## Supported Formats

### CycloneDX
- ✅ Version 1.4
- ✅ Version 1.5
- 📦 Components, dependencies, licenses
- 🛡️ Vulnerabilities (if present)

### SPDX
- ✅ Version 2.2
- ✅ Version 2.3
- 📦 Packages, relationships, licenses
- ⚖️ License compliance data

## Roadmap

- [ ] CLI tool (standalone binary)
- [ ] Additional formats (SWID tags, etc.)
- [ ] Vulnerability database integration (OSV, NVD)
- [ ] Export comparison reports (PDF, HTML)
- [ ] Historical trend analysis
- [ ] Docker image
- [ ] Integration with CI/CD pipelines

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Maintain 80%+ test coverage
- Follow type annotations (Pyright strict)
- Run `ruff format` before committing
- Write descriptive commit messages
- Update tests for new features

## License

Apache License 2.0 - See [LICENSE](LICENSE) file for details

## Credits

Built by [Terence Monteiro](https://github.com/terencemo)

Inspired by:
- The need for clear software supply chain visibility
- Apache Software Foundation's commitment to secure software
- The rain that nourishes Middle-earth 🌧️

## Support

- 📫 Issues: [GitHub Issues](https://github.com/terencemo/rain-sbom/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/terencemo/rain-sbom/discussions)

---

**RAIN Ain't Inventory Notation** - Because your dependencies deserve clarity, not chaos. ☔
