"""Comparison service for SBOM diff analysis."""

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.database import SBOM, Component
from .sbom_service import SBOMService

logger = logging.getLogger(__name__)


@dataclass
class ComponentChange:
    """Represents a changed component."""
    name: str
    old_version: str | None
    new_version: str | None
    old_license: str | None
    new_license: str | None


@dataclass
class ComparisonResult:
    """Result of SBOM comparison."""
    sbom1: dict[str, Any]
    sbom2: dict[str, Any]
    added_components: list[dict[str, Any]]
    removed_components: list[dict[str, Any]]
    changed_components: list[ComponentChange]
    license_changes: list[ComponentChange]
    summary: dict[str, int]


class CompareService:
    """Service for comparing SBOMs."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.sbom_service = SBOMService(session)

    async def compare(self, sbom1_id: int, sbom2_id: int) -> ComparisonResult:
        """
        Compare two SBOMs.

        Args:
            sbom1_id: First SBOM ID (baseline)
            sbom2_id: Second SBOM ID (comparison target)

        Returns:
            ComparisonResult with detailed diff
        """
        # Get both SBOMs
        sbom1 = await self.sbom_service.get_by_id(sbom1_id)
        sbom2 = await self.sbom_service.get_by_id(sbom2_id)

        if not sbom1 or not sbom2:
            raise ValueError("One or both SBOMs not found")

        # Create component maps (keyed by name for easy lookup)
        comp1_map = {comp.name: comp for comp in sbom1.components}
        comp2_map = {comp.name: comp for comp in sbom2.components}

        # Find added components (in sbom2, not in sbom1)
        added = []
        for name, comp in comp2_map.items():
            if name not in comp1_map:
                added.append({
                    "name": comp.name,
                    "version": comp.version,
                    "license": comp.license_id,
                    "purl": comp.purl
                })

        # Find removed components (in sbom1, not in sbom2)
        removed = []
        for name, comp in comp1_map.items():
            if name not in comp2_map:
                removed.append({
                    "name": comp.name,
                    "version": comp.version,
                    "license": comp.license_id,
                    "purl": comp.purl
                })

        # Find changed components (version or license differences)
        changed = []
        license_changes = []

        for name in comp1_map:
            if name in comp2_map:
                comp1 = comp1_map[name]
                comp2 = comp2_map[name]

                version_changed = comp1.version != comp2.version
                license_changed = comp1.license_id != comp2.license_id

                if version_changed:
                    changed.append(ComponentChange(
                        name=name,
                        old_version=comp1.version,
                        new_version=comp2.version,
                        old_license=comp1.license_id,
                        new_license=comp2.license_id
                    ))

                if license_changed and not version_changed:
                    license_changes.append(ComponentChange(
                        name=name,
                        old_version=comp1.version,
                        new_version=comp2.version,
                        old_license=comp1.license_id,
                        new_license=comp2.license_id
                    ))

        # Summary statistics
        summary = {
            "total_sbom1": len(sbom1.components),
            "total_sbom2": len(sbom2.components),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "license_changes": len(license_changes),
            "unchanged": len(comp1_map) - len(removed) - len(changed),
        }

        return ComparisonResult(
            sbom1={
                "id": sbom1.id,
                "name": sbom1.name,
                "version": sbom1.version,
                "format": sbom1.format,
            },
            sbom2={
                "id": sbom2.id,
                "name": sbom2.name,
                "version": sbom2.version,
                "format": sbom2.format,
            },
            added_components=added,
            removed_components=removed,
            changed_components=changed,
            license_changes=license_changes,
            summary=summary
        )
