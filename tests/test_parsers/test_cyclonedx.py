"""Tests for CycloneDX parser."""

import json
import pytest
from pathlib import Path

from rain.parsers.cyclonedx import CycloneDXParser


@pytest.fixture
def simple_sbom() -> dict:
    """Load simple CycloneDX fixture."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "cyclonedx-simple.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def vuln_sbom() -> dict:
    """Load CycloneDX with vulnerabilities fixture."""
    fixture_path = Path(__file__).parent.parent / "fixtures" / "cyclonedx-with-vulns.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_parse_simple_cyclonedx(simple_sbom: dict) -> None:
    """Test parsing simple CycloneDX SBOM."""
    parser = CycloneDXParser()
    result = await parser.parse(simple_sbom)
    
    assert result.name == "test-app"
    assert result.version == "1.0.0"
    assert result.format == "cyclonedx"
    assert result.spec_version == "1.5"
    assert len(result.components) == 3
    
    # Check first component
    requests = result.components[0]
    assert requests.name == "requests"
    assert requests.version == "2.31.0"
    assert requests.license_id == "Apache-2.0"
    assert requests.purl == "pkg:pypi/requests@2.31.0"


@pytest.mark.asyncio
async def test_parse_with_vulnerabilities(vuln_sbom: dict) -> None:
    """Test parsing SBOM with vulnerabilities."""
    parser = CycloneDXParser()
    result = await parser.parse(vuln_sbom)
    
    assert len(result.vulnerabilities) == 1
    vuln = result.vulnerabilities[0]
    assert vuln.id == "CVE-2023-50447"
    assert vuln.severity == "HIGH"
    assert "denial of service" in vuln.description.lower()


def test_can_parse_cyclonedx(simple_sbom: dict) -> None:
    """Test format detection."""
    assert CycloneDXParser.can_parse(simple_sbom) is True
    assert CycloneDXParser.can_parse({"bomFormat": "SPDX"}) is False
