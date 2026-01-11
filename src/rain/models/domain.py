"""Domain models for RAIN SBOM parser."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal


@dataclass
class Component:
    """Represents a software component/package."""
    
    name: str
    version: str | None = None
    purl: str | None = None
    type: str | None = None
    license_id: str | None = None
    supplier: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    
    id: str  # CVE-2024-1234
    severity: str | None = None
    description: str | None = None
    affected_component: str | None = None


@dataclass
class ParsedSBOM:
    """Represents a parsed SBOM document."""
    
    name: str
    version: str | None
    format: Literal["cyclonedx", "spdx"]
    spec_version: str
    components: list[Component]
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def summary(self) -> dict[str, int | dict[str, int]]:
        """Generate summary statistics."""
        license_counts: dict[str, int] = {}
        for comp in self.components:
            if comp.license_id:
                license_counts[comp.license_id] = license_counts.get(comp.license_id, 0) + 1
        
        severity_counts: dict[str, int] = {}
        for vuln in self.vulnerabilities:
            if vuln.severity:
                severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        return {
            "total_components": len(self.components),
            "licenses": license_counts,
            "vulnerabilities": severity_counts,
        }
