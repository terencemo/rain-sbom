"""SQLAlchemy database models."""

from datetime import datetime
from typing import List

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class SBOM(Base):
    """SBOM document model."""

    __tablename__ = "sboms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(50))
    format: Mapped[str] = mapped_column(String(20), nullable=False)  # cyclonedx, spdx
    spec_version: Mapped[str] = mapped_column(String(20), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.now,
        nullable=False
    )
    file_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    raw_data: Mapped[str] = mapped_column(Text, nullable=False)
    sbom_metadata: Mapped[str | None] = mapped_column(Text)  # Changed from 'metadata'

    # Relationships
    components: Mapped[List["Component"]] = relationship(
        "Component",
        back_populates="sbom",
        cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="sbom",
        cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<SBOM(id={self.id}, name={self.name}, format={self.format})>"


class Component(Base):
    """Software component/package model."""

    __tablename__ = "components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sboms.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    purl: Mapped[str | None] = mapped_column(String(500))
    type: Mapped[str | None] = mapped_column(String(50))
    license_id: Mapped[str | None] = mapped_column(String(100))
    supplier: Mapped[str | None] = mapped_column(String(255))
    hashes: Mapped[str | None] = mapped_column(Text)  # JSON string

    # Relationships
    sbom: Mapped["SBOM"] = relationship("SBOM", back_populates="components")

    def __repr__(self) -> str:
        return f"<Component(id={self.id}, name={self.name}, version={self.version})>"


class Vulnerability(Base):
    """Security vulnerability model."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sboms.id"), nullable=False)
    vulnerability_id: Mapped[str] = mapped_column(String(50), nullable=False)  # CVE-2024-1234
    severity: Mapped[str | None] = mapped_column(String(20))  # CRITICAL, HIGH, etc.
    description: Mapped[str | None] = mapped_column(Text)
    affected_component: Mapped[str | None] = mapped_column(String(500))  # purl or name

    # Relationships
    sbom: Mapped["SBOM"] = relationship("SBOM", back_populates="vulnerabilities")

    def __repr__(self) -> str:
        return f"<Vulnerability(id={self.id}, cve={self.vulnerability_id})>"
