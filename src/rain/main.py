"""FastAPI application for RAIN SBOM."""
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .db.session import close_db, get_session, init_db
from .models.database import SBOM
from .services.sbom_service import SBOMService

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Lifespan context manager for startup/shutdown."""
    # Startup
    logger.info("Starting RAIN SBOM API...")
    await init_db()
    logger.info("Database initialized")

    yield

    # Shutdown
    logger.info("Shutting down RAIN SBOM API...")
    await close_db()
    logger.info("Database closed")

# Create FastAPI app
app = FastAPI(
    title="RAIN SBOM API",
    description="RAIN Ain't Inventory Notation - SBOM Parser and Analyzer",
    version="0.1.0",
    lifespan=lifespan,
)

# ===== Health Check =====
@app.get("/", tags=["health"])
async def root() -> dict[str, str]:
    """Root endpoint - API status."""
    return {
        "message": "RAIN SBOM API",
        "status": "running",
        "version": "0.1.0"
    }

@app.get("/api/health", tags=["health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}

# ===== SBOM Endpoints =====

@app.post("/api/sboms", tags=["sboms"], status_code=201)
async def upload_sbom(
    file: UploadFile = File(...),
    name: str | None = None,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Upload and parse SBOM file.

    Args:
        file: SBOM file (JSON format - CycloneDX or SPDX)
        name: Optional custom name (default: use name from file)
        session: Database session

    Returns:
        Parsed SBOM with database ID
    """
    # Validate file type
    if not file.filename or not file.filename.endswith('.json'):
        raise HTTPException(
            status_code=400,
            detail="Only JSON files are supported"
        )

    try:
        # Read file content
        content = await file.read()
        file_content = content.decode('utf-8')

        # Parse and save
        service = SBOMService(session)
        sbom = await service.save_from_file(file_content, name=name)

        return {
            "id": sbom.id,
            "name": sbom.name,
            "version": sbom.version,
            "format": sbom.format,
            "spec_version": sbom.spec_version,
            "uploaded_at": sbom.uploaded_at.isoformat(),
            "component_count": len(sbom.components),
            "vulnerability_count": len(sbom.vulnerabilities),
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error uploading SBOM: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/sboms", tags=["sboms"])
async def list_sboms(
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    List all stored SBOMs.

    Args:
        limit: Maximum number of results (default: 100)
        offset: Offset for pagination (default: 0)
        session: Database session

    Returns:
        List of SBOMs with summary info
    """
    service = SBOMService(session)
    sboms = await service.list_all(limit=limit, offset=offset)
    total = await service.count()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": sbom.id,
                "name": sbom.name,
                "version": sbom.version,
                "format": sbom.format,
                "spec_version": sbom.spec_version,
                "uploaded_at": sbom.uploaded_at.isoformat(),
                "component_count": len(sbom.components),
                "vulnerability_count": len(sbom.vulnerabilities),
            }
            for sbom in sboms
        ]
    }

@app.get("/api/sboms/{sbom_id}", tags=["sboms"])
async def get_sbom(
    sbom_id: int,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Get detailed SBOM by ID.

    Args:
        sbom_id: SBOM database ID
        session: Database session

    Returns:
        Detailed SBOM with all components and vulnerabilities
    """
    service = SBOMService(session)
    sbom = await service.get_by_id(sbom_id)

    if not sbom:
        raise HTTPException(status_code=404, detail="SBOM not found")

    return {
        "id": sbom.id,
        "name": sbom.name,
        "version": sbom.version,
        "format": sbom.format,
        "spec_version": sbom.spec_version,
        "uploaded_at": sbom.uploaded_at.isoformat(),
        "file_hash": sbom.file_hash,
        "components": [
            {
                "id": comp.id,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
                "type": comp.type,
                "license_id": comp.license_id,
                "supplier": comp.supplier,
            }
            for comp in sbom.components
        ],
        "vulnerabilities": [
            {
                "id": vuln.id,
                "vulnerability_id": vuln.vulnerability_id,
                "severity": vuln.severity,
                "description": vuln.description,
                "affected_component": vuln.affected_component,
            }
            for vuln in sbom.vulnerabilities
        ],
    }

@app.delete("/api/sboms/{sbom_id}", tags=["sboms"])
async def delete_sbom(
    sbom_id: int,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Delete SBOM by ID.

    Args:
        sbom_id: SBOM database ID
        session: Database session

    Returns:
        Success message
    """
    service = SBOMService(session)
    deleted = await service.delete(sbom_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="SBOM not found")

    return {"message": f"SBOM {sbom_id} deleted successfully"}

# ===== Error Handlers =====

@app.exception_handler(404)
async def not_found_handler(request, exc):
    """Custom 404 handler."""
    return JSONResponse(
        status_code=404,
        content={"detail": "Not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    """Custom 500 handler."""
    logger.error(f"Internal error: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
