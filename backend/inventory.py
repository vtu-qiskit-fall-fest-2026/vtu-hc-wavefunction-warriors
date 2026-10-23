"""QuantumSafe Asset Inventory Module.

Handles CSV parsing, schema validation, safe string sanitization, and asset-level
quantum risk assessment using the security rules engine.

Owned by Member 3 (Asset Inventory & Reporting).
"""

from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from backend.security_rules import (
    RISK_HIGH,
    RISK_INVALID,
    RISK_LOWER,
    RISK_SAFE,
    RISK_UNKNOWN,
    assess_algorithm,
)

# Maximum upload file size: 5 MB
MAX_UPLOAD_SIZE_BYTES = 5 * 1024 * 1024

# Allowed file extensions
ALLOWED_EXTENSIONS = {".csv"}

# Required CSV headers (normalized lowercase)
REQUIRED_HEADERS = {"asset_name", "algorithm", "use_case"}

# Recognized optional CSV headers
OPTIONAL_HEADERS = {"environment", "owner", "criticality", "description", "key_size"}

# Header alias mappings for forgiving user input (e.g. from Excel exports)
HEADER_ALIASES = {
    "asset": "asset_name",
    "asset name": "asset_name",
    "asset_name": "asset_name",
    "name": "asset_name",
    "algorithm": "algorithm",
    "algo": "algorithm",
    "cipher": "algorithm",
    "cryptographic_algorithm": "algorithm",
    "cryptographic algorithm": "algorithm",
    "use_case": "use_case",
    "usecase": "use_case",
    "use case": "use_case",
    "purpose": "use_case",
    "role": "use_case",
    "environment": "environment",
    "env": "environment",
    "owner": "owner",
    "team": "owner",
    "criticality": "criticality",
    "priority": "criticality",
    "description": "description",
    "notes": "description",
    "key_size": "key_size",
    "keysize": "key_size",
    "key size": "key_size",
}


def sanitize_string(value: Any, max_length: int = 250) -> str:
    """Sanitize input string by stripping whitespace, removing control characters,
    and enforcing maximum length bounds.
    """
    if value is None:
        return ""
    text = str(value).strip()
    # Remove non-printable control characters (except common whitespace)
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
    return text[:max_length]


def validate_file_metadata(
    filename: Optional[str], file_size: int, max_size_bytes: int = MAX_UPLOAD_SIZE_BYTES
) -> Tuple[bool, Optional[str]]:
    """Validate uploaded file metadata (extension and size).
    
    Returns:
        (is_valid, error_message)
    """
    if file_size <= 0:
        return False, "Uploaded file is empty (0 bytes)."

    if file_size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        return False, f"File size exceeds the allowed limit of {max_mb:.1f} MB."

    if filename:
        clean_name = filename.strip().lower()
        if not any(clean_name.endswith(ext) for ext in ALLOWED_EXTENSIONS):
            return False, f"Invalid file format '{filename}'. Only .csv files are supported."

    return True, None


def decode_csv_bytes(content: Union[str, bytes]) -> Tuple[str, Optional[str]]:
    """Safely decode CSV bytes to string using UTF-8-SIG (handling BOM) or fallback encodings."""
    if isinstance(content, str):
        return content, None

    encodings_to_try = ["utf-8-sig", "utf-8", "latin-1", "cp1252"]
    for enc in encodings_to_try:
        try:
            decoded = content.decode(enc)
            return decoded, None
        except (UnicodeDecodeError, LookupError):
            continue

    return "", "Unable to decode CSV file. Please ensure the file is encoded in UTF-8."


def parse_and_validate_csv(
    content: Union[str, bytes],
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Parse and validate CSV content.

    Returns:
        (valid_raw_records, validation_errors, warnings)
    """
    text_content, decode_error = decode_csv_bytes(content)
    if decode_error:
        return [], [decode_error], []

    if not text_content or not text_content.strip():
        return [], ["The provided CSV file contains no content."], []

    errors: List[str] = []
    warnings: List[str] = []
    valid_records: List[Dict[str, Any]] = []

    # Use StringIO with universal newlines
    stream = io.StringIO(text_content.strip(), newline=None)

    # Sniff or default to comma delimiter
    sample = text_content[:2048]
    delimiter = ","
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        delimiter = dialect.delimiter
    except Exception:
        delimiter = ","

    reader = csv.reader(stream, delimiter=delimiter)

    # 1. Read headers
    try:
        raw_headers = next(reader, None)
    except Exception as exc:
        return [], [f"Failed to read CSV header row: {str(exc)}"], []

    if not raw_headers:
        return [], ["CSV file is empty or missing a header row."], []

    # Normalize headers
    normalized_headers: List[str] = []
    for h in raw_headers:
        cleaned = sanitize_string(h).lower()
        canonical = HEADER_ALIASES.get(cleaned, cleaned)
        normalized_headers.append(canonical)

    # Verify required headers
    missing_required = REQUIRED_HEADERS - set(normalized_headers)
    if missing_required:
        readable_missing = ", ".join(sorted(missing_required))
        return (
            [],
            [
                f"Missing required CSV column(s): {readable_missing}. "
                f"Required format: asset_name, algorithm, use_case."
            ],
            [],
        )

    expected_col_count = len(normalized_headers)
    seen_assets: Set[str] = set()

    # 2. Process data rows
    for row_idx, row in enumerate(reader, start=2):
        # Skip completely empty lines
        if not row or not any(cell.strip() for cell in row):
            continue

        if len(row) != expected_col_count:
            errors.append(
                f"Row {row_idx}: Malformed row structure (expected {expected_col_count} columns, found {len(row)})."
            )
            continue

        # Map to dictionary
        row_dict: Dict[str, Any] = {}
        for col_name, val in zip(normalized_headers, row):
            row_dict[col_name] = sanitize_string(val)

        # Validate required fields
        asset_name = row_dict.get("asset_name", "").strip()
        algorithm = row_dict.get("algorithm", "").strip()
        use_case = row_dict.get("use_case", "").strip()

        row_errors: List[str] = []
        if not asset_name:
            row_errors.append("missing 'asset_name'")
        if not algorithm:
            row_errors.append("missing 'algorithm'")
        if not use_case:
            row_errors.append("missing 'use_case'")

        if row_errors:
            errors.append(f"Row {row_idx}: {', '.join(row_errors)}.")
            continue

        # Parse optional key_size if present
        raw_key_size = row_dict.get("key_size")
        parsed_key_size: Optional[int] = None
        if raw_key_size:
            try:
                parsed_key_size = int(re.sub(r"\D", "", raw_key_size))
            except ValueError:
                parsed_key_size = None

        record: Dict[str, Any] = {
            "asset_name": asset_name,
            "algorithm": algorithm,
            "use_case": use_case,
            "key_size": parsed_key_size,
            "environment": row_dict.get("environment") or "Production",
            "owner": row_dict.get("owner") or "Unspecified",
            "criticality": row_dict.get("criticality") or "Medium",
            "description": row_dict.get("description") or "",
            "row_index": row_idx,
        }

        # Check for duplicates
        dedup_key = f"{asset_name.lower()}::{algorithm.lower()}::{use_case.lower()}"
        if dedup_key in seen_assets:
            warnings.append(
                f"Row {row_idx}: Duplicate asset definition for '{asset_name}' with algorithm '{algorithm}'."
            )
        seen_assets.add(dedup_key)

        valid_records.append(record)

    return valid_records, errors, warnings


def assess_inventory(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assess a list of validated cryptographic inventory records using security_rules.py.

    Returns:
        Structured dictionary containing assessed assets, summary metrics, and distribution counts.
    """
    assessed_assets: List[Dict[str, Any]] = []

    high_risk_count = 0
    lower_risk_count = 0
    safe_count = 0
    invalid_use_case_count = 0
    unknown_count = 0
    total_score = 0

    for rec in records:
        asset_name = rec["asset_name"]
        algorithm_input = rec["algorithm"]
        use_case_input = rec["use_case"]
        key_size = rec.get("key_size")

        # Evaluate against cryptographic rules engine
        
        assessment = assess_algorithm(
            algorithm=algorithm_input,
            use_case=use_case_input,
        )


        risk = assessment.get("risk_level", RISK_UNKNOWN)
        score = assessment.get("prioritization_score", 50)
        total_score += score

        if risk == RISK_HIGH:
            high_risk_count += 1
        elif risk == RISK_LOWER:
            lower_risk_count += 1
        elif risk == RISK_SAFE:
            safe_count += 1
        elif risk == RISK_INVALID:
            invalid_use_case_count += 1
        else:
            unknown_count += 1

        # Combine asset record with assessment details
        assessed_row = {
            # Canonical backend keys
            "asset_name": asset_name,
            "algorithm": assessment.get("algorithm", algorithm_input),
            "use_case": use_case_input,
            "risk_level": risk,
            "recommendation": assessment.get("recommendation", ""),
            "prioritization_score": score,
            "score_rationale": assessment.get("score_rationale", ""),
            "reason": assessment.get("reason", ""),
            "quantum_threat": assessment.get("quantum_threat", ""),
            "is_valid_use_case": assessment.get("is_valid_use_case", True),
            "standardization_status": assessment.get("standardization_status", ""),
            "status_label": assessment.get("status_label", ""),
            "reference_citation": assessment.get("reference_citation", ""),
            "environment": rec.get("environment", "Production"),
            "owner": rec.get("owner", "Unspecified"),
            "criticality": rec.get("criticality", "Medium"),
            "description": rec.get("description", ""),
            "row_index": rec.get("row_index"),
            # Frontend compatibility aliases (matching App.tsx InventoryRow schema)
            "asset": asset_name,
            "useCase": use_case_input,
            "risk": risk,
            "alternative": assessment.get("recommendation", ""),
        }
        assessed_assets.append(assessed_row)

    total_count = len(assessed_assets)
    avg_score = round(total_score / total_count, 1) if total_count > 0 else 0.0

    return {
        "total_assets": total_count,
        "summary": {
            "high_risk": high_risk_count,
            "lower_risk": lower_risk_count,
            "quantum_safe": safe_count,
            "invalid_use_case": invalid_use_case_count,
            "unknown_algorithm": unknown_count,
            "average_prioritization_score": avg_score,
            "high_risk_percentage": round((high_risk_count / total_count * 100), 1) if total_count > 0 else 0.0,
            "quantum_safe_percentage": round((safe_count / total_count * 100), 1) if total_count > 0 else 0.0,
        },
        "assets": assessed_assets,
    }


def process_inventory_csv(
    content: Union[str, bytes],
    filename: Optional[str] = None,
    max_size_bytes: int = MAX_UPLOAD_SIZE_BYTES,
) -> Dict[str, Any]:
    """End-to-end processing pipeline for uploaded inventory CSV files.

    Performs:
    1. File metadata validation.
    2. Safe decoding and universal line parsing.
    3. Schema and required header checks.
    4. Row-level data sanitization and missing field detection.
    5. Cryptographic risk evaluation per asset via security_rules.py.
    6. Metric aggregation and structured JSON response formatting.

    Returns:
        Structured API response dictionary.
    """
    file_bytes_len = len(content.encode("utf-8")) if isinstance(content, str) else len(content)

    # 1. Metadata check
    valid_meta, meta_err = validate_file_metadata(filename, file_bytes_len, max_size_bytes)
    if not valid_meta:
        return {
            "status": "error",
            "message": meta_err or "File validation failed.",
            "total_assets": 0,
            "summary": {},
            "assets": [],
            "errors": [meta_err or "File validation failed."],
            "warnings": [],
        }

    # 2. Parse CSV
    valid_records, parsing_errors, warnings = parse_and_validate_csv(content)

    if not valid_records:
        return {
            "status": "error",
            "message": "No valid cryptographic asset records could be parsed from the file.",
            "total_assets": 0,
            "summary": {},
            "assets": [],
            "errors": parsing_errors or ["No valid records found."],
            "warnings": warnings,
        }

    # 3. Assess valid records
    assessment_result = assess_inventory(valid_records)

    return {
        "status": "success" if not parsing_errors else "partial_success",
        "message": (
            f"Successfully assessed {assessment_result['total_assets']} cryptographic assets."
            if not parsing_errors
            else f"Imported {assessment_result['total_assets']} assets with {len(parsing_errors)} row error(s)."
        ),
        "total_assets": assessment_result["total_assets"],
        "summary": assessment_result["summary"],
        "assets": assessment_result["assets"],
        "errors": parsing_errors,
        "warnings": warnings,
    }
