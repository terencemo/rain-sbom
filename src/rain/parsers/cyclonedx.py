"""CycloneDX format parser."""

import logging
from typing import Any

from ..models.domain import Component, ParsedSBOM, Vulnerability
from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


class CycloneDXParser(BaseParser):
    """Parser for CycloneDX SBOM format."""
    
    async def parse(self, data: dict[str, Any]) -> ParsedSBOM:
        """Parse CycloneDX SBOM."""
        try:
            # Extract metadata
            metadata = data.get("metadata", {})
            component_data = metadata.get("component", {})
            
            name = component_data.get("name", "Unknown")
            version = component_data.get("version")
            spec_version = data.get("specVersion", "unknown")
            
            # Parse components (lenient - skip invalid ones)
            components = []
            for comp_data in data.get("components", []):
                try:
                    component = self._parse_component(comp_data)
                    components.append(component)
                except Exception as e:
                    logger.warning(f"Skipping invalid component: {e}")
                    continue
            
            # Parse vulnerabilities (if present)
            vulnerabilities = []
            for vuln_data in data.get("vulnerabilities", []):
                try:
                    vuln = self._parse_vulnerability(vuln_data)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"Skipping invalid vulnerability: {e}")
                    continue
            
            return ParsedSBOM(
                name=name,
                version=version,
                format="cyclonedx",
                spec_version=spec_version,
                components=components,
                vulnerabilities=vulnerabilities,
                metadata={
                    "serial_number": data.get("serialNumber", ""),
                    "timestamp": metadata.get("timestamp", ""),
                }
            )
            
        except Exception as e:
            raise ParserError(f"Failed to parse CycloneDX: {e}") from e
    
    def _parse_component(self, data: dict[str, Any]) -> Component:
        """Parse a single component."""
        # Extract license
        license_id = None
        licenses = data.get("licenses", [])
        if licenses and isinstance(licenses, list) and len(licenses) > 0:
            license_data = licenses[0].get("license", {})
            license_id = license_data.get("id") or license_data.get("name")
        
        # Extract hashes
        hashes = {}
        for hash_data in data.get("hashes", []):
            alg = hash_data.get("alg", "").upper()
            content = hash_data.get("content", "")
            if alg and content:
                hashes[alg] = content
        
        return Component(
            name=data.get("name", ""),
            version=data.get("version"),
            purl=data.get("purl"),
            type=data.get("type"),
            license_id=license_id,
            supplier=data.get("supplier", {}).get("name"),
            hashes=hashes
        )
    
    def _parse_vulnerability(self, data: dict[str, Any]) -> Vulnerability:
        """Parse a single vulnerability."""
        # Extract severity from ratings
        severity = None
        ratings = data.get("ratings", [])
        if ratings and isinstance(ratings, list) and len(ratings) > 0:
            severity = ratings[0].get("severity")
        
        # Extract affected component
        affected = None
        affects = data.get("affects", [])
        if affects and isinstance(affects, list) and len(affects) > 0:
            affected = affects[0].get("ref")
        
        return Vulnerability(
            id=data.get("id", ""),
            severity=severity,
            description=data.get("description"),
            affected_component=affected
        )
    
    @staticmethod
    def can_parse(data: dict[str, Any]) -> bool:
        """Check if data is CycloneDX format."""
        return data.get("bomFormat") == "CycloneDX"
