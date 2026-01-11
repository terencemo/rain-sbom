"""SBOM service for business logic."""

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.database import SBOM, Component, Vulnerability
from ..models.domain import ParsedSBOM
from ..parsers import get_parser

logger = logging.getLogger(__name__)


class SBOMService:
    """Service for SBOM operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def save_parsed_sbom(
        self,
        parsed: ParsedSBOM,
        raw_data: str,
        name: str | None = None
    ) -> SBOM:
        """
        Save parsed SBOM to database.

        Args:
            parsed: Parsed SBOM domain model
            raw_data: Original JSON string
            name: Optional custom name (overrides parsed.name)

        Returns:
            Saved SBOM model with eager-loaded relationships
        """
        # Calculate file hash (SHA-256)
        file_hash = hashlib.sha256(raw_data.encode()).hexdigest()

        # Check if already exists
        existing = await self.get_by_hash(file_hash)
        if existing:
            logger.warning(f"SBOM with hash {file_hash[:8]}... already exists (ID: {existing.id})")
            # Refresh to ensure relationships are loaded
            await self.session.refresh(existing, ["components", "vulnerabilities"])
            return existing

        # Create SBOM record
        sbom = SBOM(
            name=name or parsed.name,
            version=parsed.version,
            format=parsed.format,
            spec_version=parsed.spec_version,
            file_hash=file_hash,
            raw_data=raw_data,
            sbom_metadata=json.dumps(parsed.metadata) if parsed.metadata else None,
        )

        self.session.add(sbom)
        await self.session.flush()  # Get SBOM ID

        # Create component records
        for comp in parsed.components:
            component = Component(
                sbom_id=sbom.id,
                name=comp.name,
                version=comp.version,
                purl=comp.purl,
                type=comp.type,
                license_id=comp.license_id,
                supplier=comp.supplier,
                hashes=json.dumps(comp.hashes) if comp.hashes else None,
            )
            self.session.add(component)

        # Create vulnerability records
        for vuln in parsed.vulnerabilities:
            vulnerability = Vulnerability(
                sbom_id=sbom.id,
                vulnerability_id=vuln.id,
                severity=vuln.severity,
                description=vuln.description,
                affected_component=vuln.affected_component,
            )
            self.session.add(vulnerability)

        await self.session.commit()

        # Refresh with relationships to avoid lazy loading
        await self.session.refresh(sbom, ["components", "vulnerabilities"])

        logger.info(f"Saved SBOM: {sbom.name} (ID: {sbom.id}, {len(parsed.components)} components)")

        return sbom

    async def save_from_file(
        self,
        file_content: str,
        name: str | None = None
    ) -> SBOM:
        """
        Parse and save SBOM from file content.

        Args:
            file_content: JSON string
            name: Optional custom name

        Returns:
            Saved SBOM model
        """
        # Parse JSON
        data = json.loads(file_content)

        # Get parser and parse
        parser = get_parser(data)
        parsed = await parser.parse(data)

        # Save to database
        return await self.save_parsed_sbom(parsed, file_content, name)

    async def get_by_id(self, sbom_id: int) -> SBOM | None:
        """Get SBOM by ID with eager-loaded relationships."""
        result = await self.session.execute(
            select(SBOM)
            .options(
                selectinload(SBOM.components),
                selectinload(SBOM.vulnerabilities)
            )
            .where(SBOM.id == sbom_id)
        )
        sbom = result.scalar_one_or_none()

        if sbom:
            # Explicitly refresh to ensure relationships are loaded
            await self.session.refresh(sbom, ["components", "vulnerabilities"])

        return sbom

    async def get_by_hash(self, file_hash: str) -> SBOM | None:
        """Get SBOM by file hash."""
        result = await self.session.execute(
            select(SBOM).where(SBOM.file_hash == file_hash)
        )
        return result.scalar_one_or_none()

    async def list_all(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> list[SBOM]:
        """List all SBOMs with eager-loaded relationships."""
        result = await self.session.execute(
            select(SBOM)
            .options(
                selectinload(SBOM.components),      # Eager load components
                selectinload(SBOM.vulnerabilities)  # Eager load vulnerabilities
            )
            .order_by(SBOM.uploaded_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def delete(self, sbom_id: int) -> bool:
        """Delete SBOM by ID."""
        sbom = await self.get_by_id(sbom_id)
        if not sbom:
            return False

        await self.session.delete(sbom)
        await self.session.commit()

        logger.info(f"Deleted SBOM: {sbom.name} (ID: {sbom_id})")
        return True

    async def count(self) -> int:
        """Count total SBOMs."""
        from sqlalchemy import func
        result = await self.session.execute(
            select(func.count(SBOM.id))
        )
        return result.scalar_one()
