"""FastAPI application for RAIN SBOM."""
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from .db.session import close_db, get_session, init_db
from .models.database import SBOM
from .services.sbom_service import SBOMService
from .services.compare_service import CompareService

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

templates = Jinja2Templates(directory="src/rain/templates")
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/", response_class=HTMLResponse, tags=["ui"])
async def home(request: Request):
    """Home page with upload interface."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/sboms-html", response_class=HTMLResponse, tags=["ui"])
async def list_sboms_html(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    """List SBOMs as HTML (for htmx)."""
    service = SBOMService(session)
    sboms = await service.list_all(limit=100)
    total = await service.count()

    # Transform to dict with computed fields
    sbom_data = []
    for sbom in sboms:
        sbom_data.append({
            "id": sbom.id,
            "name": sbom.name,
            "version": sbom.version,
            "format": sbom.format,
            "spec_version": sbom.spec_version,
            "component_count": len(sbom.components),
            "vulnerability_count": len(sbom.vulnerabilities),
            "uploaded_at": sbom.uploaded_at.strftime("%Y-%m-%d %H:%M")
        })

    return templates.TemplateResponse("sbom_list.html", {
        "request": request,
        "sboms": sbom_data,
        "total": total
    })


# In src/rain/main.py
# Replace get_sbom_details_html function:

@app.get("/api/sboms/{sbom_id}/details-html", response_class=HTMLResponse, tags=["ui"])
async def get_sbom_details_html(
    request: Request,
    sbom_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Get SBOM details as HTML (for htmx modal)."""
    service = SBOMService(session)
    sbom = await service.get_by_id(sbom_id)

    if not sbom:
        return "<p class='text-red-600'>SBOM not found</p>"

    # Transform components to dict
    components_data = [
        {
            "name": comp.name,
            "version": comp.version,
            "license_id": comp.license_id
        }
        for comp in sbom.components
    ]

    # Transform vulnerabilities to dict
    vulns_data = [
        {
            "vulnerability_id": vuln.vulnerability_id,
            "severity": vuln.severity,
            "description": vuln.description
        }
        for vuln in sbom.vulnerabilities
    ]

    return templates.TemplateResponse("sbom_details.html", {
        "request": request,
        "sbom": {
            "name": sbom.name,
            "version": sbom.version,
            "format": sbom.format,
            "spec_version": sbom.spec_version,
            "uploaded_at": sbom.uploaded_at.strftime("%Y-%m-%d %H:%M")
        },
        "components": components_data,
        "vulnerabilities": vulns_data
    })

@app.get("/api/compare-html", response_class=HTMLResponse, tags=["ui"])
async def compare_sboms_html(
    request: Request,
    sbom1_id: int,
    sbom2_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Get comparison result as HTML (for htmx)."""
    try:
        service = CompareService(session)
        result = await service.compare(sbom1_id, sbom2_id)

        return templates.TemplateResponse("compare.html", {
            "request": request,
            "result": {
                "sbom1": result.sbom1,
                "sbom2": result.sbom2,
                "added": result.added_components,
                "removed": result.removed_components,
                "changed": [
                    {
                        "name": c.name,
                        "old_version": c.old_version,
                        "new_version": c.new_version,
                    }
                    for c in result.changed_components
                ],
                "license_changes": [
                    {
                        "name": c.name,
                        "old_license": c.old_license,
                        "new_license": c.new_license,
                    }
                    for c in result.license_changes
                ],
                "summary": result.summary
            }
        })
    except ValueError:
        return "<p class='text-red-600'>One or both SBOMs not found</p>"

# ===== Health Check =====
#@app.get("/", tags=["health"])
#async def root() -> dict[str, str]:
#    """Root endpoint - API status."""
#    return {
#        "message": "RAIN SBOM API",
#        "status": "running",
#        "version": "0.1.0"
#    }

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

# Add API endpoint (after existing SBOM endpoints)
@app.post("/api/compare", tags=["compare"])
async def compare_sboms(
    sbom1_id: int,
    sbom2_id: int,
    session: AsyncSession = Depends(get_session)
) -> dict:
    """
    Compare two SBOMs.

    Args:
        sbom1_id: First SBOM ID (baseline)
        sbom2_id: Second SBOM ID (comparison target)
        session: Database session

    Returns:
        Comparison results with added/removed/changed components
    """
    try:
        service = CompareService(session)
        result = await service.compare(sbom1_id, sbom2_id)

        return {
            "sbom1": result.sbom1,
            "sbom2": result.sbom2,
            "added": result.added_components,
            "removed": result.removed_components,
            "changed": [
                {
                    "name": c.name,
                    "old_version": c.old_version,
                    "new_version": c.new_version,
                    "old_license": c.old_license,
                    "new_license": c.new_license,
                }
                for c in result.changed_components
            ],
            "license_changes": [
                {
                    "name": c.name,
                    "version": c.old_version,
                    "old_license": c.old_license,
                    "new_license": c.new_license,
                }
                for c in result.license_changes
            ],
            "summary": result.summary
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error comparing SBOMs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

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
