"""SPDX format parser."""

import logging
from typing import Any

from ..models.domain import Component, ParsedSBOM, Vulnerability
from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


class SPDXParser(BaseParser):
    """Parser for SPDX SBOM format."""
    
    async def parse(self, data: dict[str, Any]) -> ParsedSBOM:
        """Parse SPDX SBOM."""
        try:
            # Extract metadata
            name = data.get("name", "Unknown")
            
            # SPDX uses documentNamespace for versioning info
            namespace = data.get("documentNamespace", "")
            version = None
            if namespace:
                # Try to extract version from namespace URL
                parts = namespace.split("/")
                for part in parts:
                    if any(c.isdigit() for c in part):
                        version = part
                        break
            
            spec_version = data.get("spdxVersion", "unknown")
            
            # Parse packages (SPDX calls them packages, not components)
            components = []
            for pkg_data in data.get("packages", []):
                try:
                    component = self._parse_package(pkg_data)
                    components.append(component)
                except Exception as e:
                    logger.warning(f"Skipping invalid package: {e}")
                    continue
            
            # SPDX doesn't have built-in vulnerability info
            # But we'll check for external refs
            vulnerabilities = []
            
            # Extract creation info for metadata
            creation_info = data.get("creationInfo", {})
            metadata = {
                "document_namespace": namespace,
                "created": creation_info.get("created", ""),
                "creators": ", ".join(creation_info.get("creators", [])),
                "license_list_version": creation_info.get("licenseListVersion", ""),
            }
            
            return ParsedSBOM(
                name=name,
                version=version,
                format="spdx",
                spec_version=spec_version,
                components=components,
                vulnerabilities=vulnerabilities,
                metadata=metadata
            )
            
        except Exception as e:
            raise ParserError(f"Failed to parse SPDX: {e}") from e
    
    def _parse_package(self, data: dict[str, Any]) -> Component:
        """Parse a single SPDX package."""
        # Extract license
        license_id = None
        license_concluded = data.get("licenseConcluded")
        license_declared = data.get("licenseDeclared")
        license_id = license_concluded or license_declared
        
        # Clean up NOASSERTION values
        if license_id == "NOASSERTION":
            license_id = None
        
        # Extract purl from externalRefs
        purl = None
        for ref in data.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        
        # Extract hashes/checksums
        hashes = {}
        for checksum in data.get("checksums", []):
            alg = checksum.get("algorithm", "").upper()
            value = checksum.get("checksumValue", "")
            if alg and value:
                hashes[alg] = value
        
        # Extract supplier/originator
        supplier = data.get("supplier")
        if not supplier or supplier == "NOASSERTION":
            supplier = data.get("originator")
        if supplier and supplier.startswith("Organization: "):
            supplier = supplier.replace("Organization: ", "")
        
        return Component(
            name=data.get("name", ""),
            version=data.get("versionInfo"),
            purl=purl,
            type=None,  # SPDX doesn't have explicit type field
            license_id=license_id,
            supplier=supplier,
            hashes=hashes
        )
    
    @staticmethod
    def can_parse(data: dict[str, Any]) -> bool:
        """Check if data is SPDX format."""
        return data.get("spdxVersion", "").startswith("SPDX-")
