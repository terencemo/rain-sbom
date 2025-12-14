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
