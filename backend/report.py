"""QuantumSafe Report Generation Module.

Generates structured audit summaries and downloadable RFC-4180-compliant CSV reports
derived strictly from actual cryptographic assessment results.

Owned by Member 3 (Asset Inventory & Reporting).
"""

from __future__ import annotations

import csv
import datetime
import io
import re
from typing import Any, Dict, List, Optional, Union

# Standard CSV Headers for the downloadable audit report
STANDARD_REPORT_HEADERS = [
    "asset_name",
    "algorithm",
    "use_case",
    "risk_level",
    "prioritization_score",
    "risk_explanation",
    "quantum_threat",
    "recommended_alternative",
    "nist_reference",
    "environment",
    "owner",
    "criticality",
]


def extract_field(record: Dict[str, Any], primary_key: str, fallback_keys: List[str], default: str = "") -> str:
    """Extract a field from a record using primary key or fallback aliases."""
    if primary_key in record and record[primary_key] is not None:
        return str(record[primary_key]).strip()
    for fb in fallback_keys:
        if fb in record and record[fb] is not None:
            return str(record[fb]).strip()
    return default


def sanitize_filename(name: str, max_length: int = 64) -> str:
    """Sanitize custom filename to prevent path traversal and invalid characters."""
    clean = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name)
    clean = re.sub(r"_{2,}", "_", clean).strip("._")
    return clean[:max_length] or "quantumsafe-report"


def get_safe_report_filename(prefix: str = "quantumsafe-assessment") -> str:
    """Generate a safe, timestamped CSV report filename."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    clean_prefix = sanitize_filename(prefix)
    return f"{clean_prefix}_{timestamp}.csv"


def calculate_report_summary(records: Union[List[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate summary metrics and risk distribution strictly from actual assessment records.

    Args:
        records: List of assessed asset dictionaries, or dictionary containing an "assets" list.

    Returns:
        Structured dictionary containing counts, percentages, algorithm distribution,
        and contextual migration guidance.
    """
    raw_list: List[Dict[str, Any]]
    if isinstance(records, dict):
        raw_list = records.get("assets", [])
    elif isinstance(records, list):
        raw_list = records
    else:
        raw_list = []

    total_assessed = len(raw_list)

    if total_assessed == 0:
        return {
            "total_assets": 0,
            "risk_distribution": {
                "High risk": 0,
                "Lower quantum risk": 0,
                "Quantum-safe": 0,
                "Invalid use case": 0,
                "Unknown algorithm": 0,
            },
            "risk_percentages": {
                "High risk": 0.0,
                "Lower quantum risk": 0.0,
                "Quantum-safe": 0.0,
            },
            "algorithm_distribution": {},
            "criticality_distribution": {},
            "recommendations_count": 0,
            "average_prioritization_score": 0.0,
            "high_priority_assets": [],
            "migration_guidance": [
                "No cryptographic assets currently assessed. Upload an inventory CSV to generate actionable guidance."
            ],
        }

    risk_counts: Dict[str, int] = {
        "High risk": 0,
        "Lower quantum risk": 0,
        "Quantum-safe": 0,
        "Invalid use case": 0,
        "Unknown algorithm": 0,
    }

    algorithm_counts: Dict[str, int] = {}
    criticality_counts: Dict[str, int] = {}
    recommendations_count = 0
    total_score = 0
    high_priority_assets: List[Dict[str, Any]] = []

    for row in raw_list:
        # Resolve risk level
        risk = extract_field(row, "risk_level", ["risk"], default="Unknown algorithm")
        if risk in risk_counts:
            risk_counts[risk] += 1
        else:
            risk_counts["Unknown algorithm"] += 1

        # Resolve algorithm
        algo = extract_field(row, "algorithm", ["algo"], default="Unknown")
        algorithm_counts[algo] = algorithm_counts.get(algo, 0) + 1

        # Resolve criticality
        crit = extract_field(row, "criticality", [], default="Medium")
        criticality_counts[crit] = criticality_counts.get(crit, 0) + 1

        # Resolve recommendations
        rec = extract_field(row, "recommendation", ["alternative"], default="")
        if rec and "no replacement required" not in rec.lower():
            recommendations_count += 1

        # Resolve prioritization score
        score_val = row.get("prioritization_score")
        if score_val is not None:
            try:
                score_num = int(score_val)
            except (ValueError, TypeError):
                score_num = 50
        else:
            score_num = 50
        total_score += score_num

        if score_num >= 75:
            high_priority_assets.append({
                "asset_name": extract_field(row, "asset_name", ["asset"], default="Unnamed"),
                "algorithm": algo,
                "risk_level": risk,
                "score": score_num,
            })

    avg_score = round(total_score / total_assessed, 1) if total_assessed > 0 else 0.0

    # Risk percentages
    risk_pct = {
        "High risk": round((risk_counts["High risk"] / total_assessed) * 100, 1),
        "Lower quantum risk": round((risk_counts["Lower quantum risk"] / total_assessed) * 100, 1),
        "Quantum-safe": round((risk_counts["Quantum-safe"] / total_assessed) * 100, 1),
    }

    # Generate targeted migration guidance based strictly on actual findings
    guidance: List[str] = []
    if risk_counts["High risk"] > 0:
        hr = risk_counts["High risk"]
        guidance.append(
            f"Prioritize migration planning for the {hr} high-risk asset(s) exposed to Shor's algorithm "
            f"(RSA, ECDH, ECDSA). Implement hybrid key exchange (e.g. X25519 + ML-KEM) to protect data against "
            f"'harvest now, decrypt later' threats."
        )

    if risk_counts["Invalid use case"] > 0:
        inv = risk_counts["Invalid use case"]
        guidance.append(
            f"Remediate {inv} asset(s) with mismatched cryptographic roles (e.g. key exchange algorithms "
            f"assigned to digital signatures). Cryptographic algorithms must never be repurposed across roles."
        )

    if risk_counts["Lower quantum risk"] > 0:
        guidance.append(
            "Review symmetric encryption keys. Confirm that bulk data at rest uses AES-256 to ensure "
            "a minimum 128-bit quantum security work factor against Grover's algorithm."
        )

    if risk_counts["Quantum-safe"] > 0:
        qs = risk_counts["Quantum-safe"]
        guidance.append(
            f"Maintain and validate parameters for the {qs} asset(s) already deploying standardized PQC "
            f"(NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)."
        )

    if not guidance:
        guidance.append("Continue regular cryptographic discovery and maintain an active software bill of materials (SBOM).")

    return {
        "total_assets": total_assessed,
        "risk_distribution": risk_counts,
        "risk_percentages": risk_pct,
        "algorithm_distribution": algorithm_counts,
        "criticality_distribution": criticality_counts,
        "recommendations_count": recommendations_count,
        "average_prioritization_score": avg_score,
        "high_priority_assets": high_priority_assets[:10],
        "migration_guidance": guidance,
    }


def create_csv_report(
    records: Union[List[Dict[str, Any]], Dict[str, Any]],
    include_header: bool = True,
) -> str:
    """Generate an RFC-4180-compliant CSV report from assessment results.

    Args:
        records: List of assessed asset dictionaries, or dictionary with an "assets" key.
        include_header: Whether to include the header row in output.

    Returns:
        Formatted CSV string.
    """
    raw_list: List[Dict[str, Any]]
    if isinstance(records, dict):
        raw_list = records.get("assets", [])
    elif isinstance(records, list):
        raw_list = records
    else:
        raw_list = []

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\r\n")

    if include_header:
        writer.writerow(STANDARD_REPORT_HEADERS)

    # Empty list handling: write headers and return valid CSV
    if not raw_list:
        return output.getvalue()

    for row in raw_list:
        asset_name = extract_field(row, "asset_name", ["asset"], default="Unnamed Asset")
        algorithm = extract_field(row, "algorithm", ["algo"], default="Unknown")
        use_case = extract_field(row, "use_case", ["useCase"], default="Unspecified")
        risk_level = extract_field(row, "risk_level", ["risk"], default="Unknown")
        score = str(row.get("prioritization_score", ""))
        explanation = extract_field(row, "reason", ["explanation", "risk_explanation"], default="")
        threat = extract_field(row, "quantum_threat", ["threat", "attack"], default="")
        recommendation = extract_field(row, "recommendation", ["alternative"], default="")
        reference = extract_field(row, "reference_citation", ["reference"], default="")
        environment = extract_field(row, "environment", ["env"], default="Production")
        owner = extract_field(row, "owner", ["team"], default="Unspecified")
        criticality = extract_field(row, "criticality", [], default="Medium")

        writer.writerow([
            asset_name,
            algorithm,
            use_case,
            risk_level,
            score,
            explanation,
            threat,
            recommendation,
            reference,
            environment,
            owner,
            criticality,
        ])

    return output.getvalue()
