"""QuantumSafe FastAPI Backend Application.

Connects the HTTP API layer to:
- security_rules.py (NIST PQC assessment engine)
- algorithms.json (Cryptographic standards catalog)
- inventory.py (CSV parsing, schema validation, asset evaluation)
- report.py (Metrics aggregation and RFC-4180 CSV export)

Owned by Member 1 (Frontend & FastAPI Integration).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Query, Response, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.inventory import MAX_UPLOAD_SIZE_BYTES, process_inventory_csv
from backend.report import (
    calculate_report_summary,
    create_csv_report,
    get_safe_report_filename,
)
from backend.security_rules import (
    assess_algorithm,
    get_supported_algorithms,
)

# ---------------------------------------------------------------------------
# FastAPI Application Configuration
# ---------------------------------------------------------------------------
app = FastAPI(
    title="QuantumSafe API",
    description=(
        "Quantum-Safe Cryptographic Security Checker API. Evaluates cryptographic "
        "algorithms against quantum threats (Shor's and Grover's algorithms) and "
        "aligns infrastructure with NIST PQC standards (FIPS 203, 204, 205)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
# ---------------------------------------------------------------------------
# CORS Configuration (restricted to local development origins)
# ---------------------------------------------------------------------------
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8443",
    "http://127.0.0.1:8443",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

env_origins = os.getenv("QUANTUMSAFE_ALLOWED_ORIGINS")
allowed_origins = (
    [origin.strip() for origin in env_origins.split(",") if origin.strip()]
    if env_origins
    else DEFAULT_ALLOWED_ORIGINS
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-Memory Session State (Documented: resets on backend restart)
# ---------------------------------------------------------------------------
_IN_MEMORY_INVENTORY: List[Dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = Field(..., example="healthy")
    version: str = Field(..., example="1.0.0")
    service: str = Field(..., example="QuantumSafe Security Checker API")
    backend_available: bool = Field(True, example=True)
    active_inventory_count: int = Field(..., example=0)
    note: str = Field(
        "In-memory session state active; data resets on backend restart.",
        example="In-memory session state active; data resets on backend restart.",
    )


class ReferenceItem(BaseModel):
    standard_id: str
    title: str
    published: str
    url: str


class AssessRequest(BaseModel):
    algorithm: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Name or recognized alias of the algorithm (e.g. 'RSA', 'ECDH', 'ML-KEM')",
        example="RSA",
    )
    use_case: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="Operational use case (e.g. 'TLS key exchange', 'Digital signatures')",
        example="Digital signatures",
    )
    key_size: Optional[int] = Field(
        None,
        ge=56,
        le=16384,
        description="Optional key length in bits (e.g. 2048, 256)",
        example=2048,
    )


class AssessResponse(BaseModel):
    algorithm: str
    algorithm_id: Optional[str] = None
    family: Optional[str] = None
    use_case: str
    cryptographic_role: Optional[str] = None
    is_valid_use_case: bool = False
    risk_level: str
    reason: str
    quantum_threat: str = ""
    recommendation: str
    prioritization_score: int = 0
    score_rationale: str = ""
    standardization_status: Optional[str] = None
    status_label: Optional[str] = None
    references: List[Any] = []
    reference_citation: Optional[str] = None
    caveats: str = ""

class InventorySummaryModel(BaseModel):
    high_risk: int = 0
    lower_risk: int = 0
    quantum_safe: int = 0
    invalid_use_case: int = 0
    unknown_algorithm: int = 0
    average_prioritization_score: float = 0.0
    high_risk_percentage: float = 0.0
    quantum_safe_percentage: float = 0.0


class InventoryUploadResponse(BaseModel):
    status: str
    message: str
    total_assets: int
    summary: Dict[str, Any]
    assets: List[Dict[str, Any]]
    errors: List[str]
    warnings: List[str]


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get(
    "/api/health",
    response_model=HealthResponse,
    summary="Health and availability check",
    tags=["System"],
)
def get_health() -> HealthResponse:
    """Return backend availability, service version, and current session inventory count."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        service="QuantumSafe Security Checker API",
        backend_available=True,
        active_inventory_count=len(_IN_MEMORY_INVENTORY),
    )


@app.get(
    "/api/algorithms",
    summary="List supported cryptographic standards and catalog",
    tags=["Algorithms"],
)
def list_algorithms() -> Dict[str, Any]:
    """Return all supported classical, post-quantum, and legacy predecessor algorithms with metadata."""
    algorithms = get_supported_algorithms()
    return {
        "status": "success",
        "total": len(algorithms),
        "algorithms": algorithms,
    }


@app.post(
    "/api/assess",
    response_model=AssessResponse,
    summary="Assess an algorithm and use case against quantum threats",
    tags=["Assessment"],
)
def assess_crypto_asset(request: AssessRequest) -> AssessResponse:
    """Assess an algorithm and adapt engine output for the frontend."""

    clean_algo = request.algorithm.strip()
    clean_use_case = request.use_case.strip()

    result = assess_algorithm(
        algorithm=clean_algo,
        use_case=clean_use_case,
    )

    references = result.get("references", [])
    if not isinstance(references, list):
        references = [references]

    # Convert reference URLs into objects expected by the UI.
    normalized_references = []
    for reference in references:
        if isinstance(reference, str):
            normalized_references.append({
                "standard_id": "",
                "title": reference,
                "published": "",
                "url": reference,
            })
        elif isinstance(reference, dict):
            normalized_references.append(reference)

    # Convert the engine's output into the API response format.
    response_data = {
        "algorithm": result.get("algorithm", clean_algo),
        "algorithm_id": result.get("algorithm", clean_algo),
        "family": result.get("family", "Unknown"),
        "use_case": result.get("use_case", clean_use_case),
        "cryptographic_role": result.get("family", "Unknown"),
        "is_valid_use_case": result.get("risk_level") not in {
            "Invalid Input",
            "Unrecognized Algorithm",
            "Unrecognized Use Case",
            "Unsupported Combination",
            "Assessment Unavailable",
            "Error",
        },
        "risk_level": result.get("risk_level", "Unknown algorithm"),
        "reason": result.get("reason", ""),
        "quantum_threat": result.get("reason", ""),
        "recommendation": result.get("recommendation", ""),
        "prioritization_score": 0,
        "score_rationale": (
            f"Qualitative engine priority: {result.get('priority', 'N/A')}. "
            "This prototype does not calculate a numeric score."
        ),
        "standardization_status": "",
        "status_label": result.get("priority", "Not assessed"),
        "references": normalized_references,
        "reference_citation": "; ".join(
            item["url"] for item in normalized_references if item.get("url")
        ),
        "caveats": result.get("disclaimer", ""),
    }

    return AssessResponse(**response_data)

@app.post(
    "/api/inventory/upload",
    response_model=InventoryUploadResponse,
    summary="Upload and assess CSV cryptographic asset inventory",
    tags=["Inventory"],
)
async def upload_inventory_csv(
    file: UploadFile = File(..., description="CSV file with columns: asset_name, algorithm, use_case"),
) -> InventoryUploadResponse:
    """Process an uploaded CSV file containing cryptographic assets.

    Parses data safely, enforces schema, applies security rules to all rows,
    and stores results in session memory for reporting.
    """
    global _IN_MEMORY_INVENTORY

    # 1. Filename validation
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type '{file.filename}'. Please upload a valid .csv file.",
        )

    # 2. Read file content safely in memory
    try:
        content_bytes = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}",
        )

    # 3. Size limit enforcement
    if len(content_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload limit of {MAX_UPLOAD_SIZE_BYTES / (1024 * 1024):.1f} MB.",
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded CSV file is empty (0 bytes).",
        )

    # 4. Process and assess CSV records
    result = process_inventory_csv(content=content_bytes, filename=file.filename)

    if result.get("status") == "error":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message") or "Failed to parse inventory CSV.",
        )

    # 5. Update session in-memory inventory
    _IN_MEMORY_INVENTORY = result.get("assets", [])

    return InventoryUploadResponse(**result)


@app.get(
    "/api/inventory",
    summary="Retrieve current session inventory assets",
    tags=["Inventory"],
)
def get_inventory() -> Dict[str, Any]:
    """Return the list of assessed assets currently in session memory."""
    return {
        "status": "success",
        "total_assets": len(_IN_MEMORY_INVENTORY),
        "assets": _IN_MEMORY_INVENTORY,
    }


@app.delete(
    "/api/inventory",
    summary="Clear current session inventory",
    tags=["Inventory"],
)
def clear_inventory() -> Dict[str, Any]:
    """Reset the in-memory session inventory."""
    global _IN_MEMORY_INVENTORY
    cleared_count = len(_IN_MEMORY_INVENTORY)
    _IN_MEMORY_INVENTORY = []
    return {
        "status": "success",
        "message": f"Cleared {cleared_count} asset(s) from session memory.",
        "active_inventory_count": 0,
    }


@app.get(
    "/api/report/summary",
    summary="Get aggregated assessment metrics and distribution",
    tags=["Reports"],
)
def get_report_summary() -> Dict[str, Any]:
    """Calculate summary statistics and migration guidance from the active session inventory.

    Metrics are calculated strictly from actual assessed assets. No placeholder metrics.
    """
    summary = calculate_report_summary(_IN_MEMORY_INVENTORY)
    return {
        "status": "success",
        "total_assets": summary["total_assets"],
        "summary": summary,
    }


@app.get(
    "/api/report/export",
    summary="Download RFC-4180 CSV assessment audit report",
    tags=["Reports"],
)
def export_csv_report() -> Response:
    """Generate and download a CSV report of assessed assets."""
    csv_text = create_csv_report(_IN_MEMORY_INVENTORY)
    filename = get_safe_report_filename("quantumsafe-assessment")

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache",
        },
    )
