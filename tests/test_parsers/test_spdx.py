"""Tests for SPDX parser."""

import json
import pytest
from pathlib import Path

from rain.parsers.spdx import SPDXParser


@pytest.fixture
def simple_spdx() -> dict:
    """Load simple SPDX fixture."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "spdx-simple.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_parse_simple_spdx(simple_spdx: dict) -> None:
    """Test parsing simple SPDX SBOM."""
    parser = SPDXParser()
    result = await parser.parse(simple_spdx)
    
    assert result.format == "spdx"
    assert result.spec_version == "SPDX-2.3"
    assert len(result.components) >= 1
    
    # Check first component
    if result.components:
        comp = result.components[0]
        assert comp.name
        # SPDX packages should have basic fields


def test_can_parse_spdx(simple_spdx: dict) -> None:
    """Test format detection for SPDX."""
    assert SPDXParser.can_parse(simple_spdx) is True
    assert SPDXParser.can_parse({"bomFormat": "CycloneDX"}) is False


def test_cannot_parse_invalid() -> None:
    """Test that invalid data is rejected."""
    assert SPDXParser.can_parse({}) is False
    assert SPDXParser.can_parse({"spdxVersion": "not-spdx"}) is False
