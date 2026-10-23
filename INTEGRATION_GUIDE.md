# QuantumSafe-Checker — Security Engine Integration Guide

**Author:** Member 2 (Security Engine Lead)  
**Target Audience:** Member 1 (Streamlit Frontend / UI) & Member 3 (Inventory, CSV Validation & Reporting)  
**Target Module:** `security_rules.py` (supported by `algorithms.json`)  
**Status:** Tested & Verified (85 tests passing, 0 failures, 0 skips)

---

## 1. Dashboard Integration (Member 1)

The security assessment engine is deterministic, rule-based, and decoupled from Streamlit. It provides helper functions to dynamically populate UI dropdown menus and an evaluation function returning structured risk data.

### Exact Import Statement

```python
from security_rules import (
    assess_algorithm,
    get_supported_algorithms,
    get_supported_use_cases,
)
```

### Minimal Streamlit Example (`app.py`)

```python
import streamlit as st
from security_rules import (
    assess_algorithm,
    get_supported_algorithms,
    get_supported_use_cases,
)

st.set_page_config(page_title="QuantumSafe-Checker", page_icon="🛡️", layout="wide")
st.title("🛡️ QuantumSafe-Checker — Cryptographic Risk Assessment")

# 1. Populate algorithm dropdown dynamically
algorithms = get_supported_algorithms()
selected_algorithm = st.selectbox("Select Cryptographic Algorithm", options=algorithms)

# 2. Populate use cases based on selected algorithm
supported_cases = get_supported_use_cases(selected_algorithm)
selected_use_case = st.selectbox("Select Use Case", options=supported_cases)

# 3. Assess on button click
if st.button("Evaluate Quantum Risk", type="primary"):
    result = assess_algorithm(selected_algorithm, selected_use_case)

    # Risk badge with priority
    risk_level = result["risk_level"]
    priority = result["priority"]

    if "High" in risk_level:
        st.error(f"**Risk Level:** {risk_level} &nbsp;|&nbsp; **Migration Priority:** {priority}")
    elif "Moderate" in risk_level:
        st.warning(f"**Risk Level:** {risk_level} &nbsp;|&nbsp; **Migration Priority:** {priority}")
    else:
        st.success(f"**Risk Level:** {risk_level} &nbsp;|&nbsp; **Migration Priority:** {priority}")

    # Rationale and Recommendations
    st.markdown(f"**Cryptographic Family:** `{result['family']}`")
    st.markdown(f"**Technical Rationale:** {result['reason']}")
    st.markdown(f"**Recommended Action:** {result['recommendation']}")

    # Standardized Alternatives
    if result["recommended_algorithms"]:
        st.info(f"**Recommended PQC Target(s):** {', '.join(result['recommended_algorithms'])}")

    # Authoritative NIST CSRC References
    with st.expander("Authoritative Standards & References", expanded=False):
        for ref_url in result["references"]:
            st.markdown(f"- [{ref_url}]({ref_url})")

    # Prototype Notice / Disclaimer
    st.caption(f"⚠️ {result['disclaimer']}")
```

---

## 2. Inventory & Report Integration (Member 3)

Member 3 processes customer cryptographic inventories (e.g., CSV/JSON files) and compiles Markdown/PDF assessment reports.

### Batch Evaluation Loop Pattern

The engine is engineered with a **zero-unhandled-exception guarantee**: inputs with invalid types, nulls, empty strings, unrecognized names, or mismatched roles return a consistent dictionary without crashing batch loops.

```python
import csv
from security_rules import assess_algorithm

def process_inventory(csv_file_path: str) -> list[dict]:
    """
    Reads an inventory CSV and enriches each row with a quantum risk assessment.
    Expected CSV columns: 'Algorithm', 'Use_Case' (or 'Function')
    """
    enriched_records = []

    with open(csv_file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alg = row.get("Algorithm", "")
            use_case = row.get("Use_Case", "")

            # Call the assessment engine
            assessment = assess_algorithm(alg, use_case)

            # Flatten/map into report record without altering the engine schema
            record = {
                "inventory_id": row.get("ID", ""),
                "asset_name": row.get("Asset_Name", ""),
                "algorithm": assessment["algorithm"],
                "use_case": assessment["use_case"],
                "family": assessment["family"],
                "risk_level": assessment["risk_level"],
                "priority": assessment["priority"],
                "reason": assessment["reason"],
                "recommendation": assessment["recommendation"],
                # Serialize list fields cleanly for CSV tabular export
                "recommended_algorithms": ", ".join(assessment["recommended_algorithms"]),
                "references": "; ".join(assessment["references"]),
                "disclaimer": assessment["disclaimer"],
            }
            enriched_records.append(record)

    return enriched_records
```

### Report Aggregation Tips
- **HNDL Metric:** Count occurrences where `priority == "Immediate"` to highlight systems vulnerable to *Harvest Now, Decrypt Later* (RSA / ECDH key establishment).
- **Risk Breakdown:** Group records by `risk_level` (`High Quantum Risk`, `Moderate Quantum Consideration`, `Quantum Resistant (Symmetric)`, `Standardized Post-Quantum / Quantum Safe`, `Unsupported Combination`, `Unrecognized Algorithm`).

---

## 3. Supported Inputs & Validation Handling

### Canonical Algorithms (`get_supported_algorithms()`)
The engine curates 8 initial algorithms:

| Algorithm Name | Cryptographic Family | Supported Canonical Use Cases |
| :--- | :--- | :--- |
| `RSA` | Asymmetric / Public-Key (Integer Factorization) | `key_establishment`, `digital_signatures` |
| `ECDH` | Asymmetric / Public-Key (Elliptic Curve Cryptography) | `key_establishment` |
| `ECDSA` | Asymmetric / Public-Key (Elliptic Curve Cryptography) | `digital_signatures` |
| `AES-128` | Symmetric (Block Cipher) | `symmetric_encryption` |
| `AES-256` | Symmetric (Block Cipher) | `symmetric_encryption` |
| `ML-KEM` | Post-Quantum Cryptography (Lattice-Based KEM) | `key_establishment` |
| `ML-DSA` | Post-Quantum Cryptography (Lattice-Based Signature) | `digital_signatures` |
| `SLH-DSA` | Post-Quantum Cryptography (Hash-Based Signature) | `digital_signatures` |

### Canonical Use Cases (`get_supported_use_cases()`)
1. `key_establishment`: Shared secret negotiation, key encapsulation (KEM), and key transport.
2. `digital_signatures`: Authenticity, data integrity, and non-repudiation signing.
3. `symmetric_encryption`: Confidentiality of bulk data using shared secret keys.

### Accepted Semantically Valid Aliases
- **Algorithms:** Case-insensitive, hyphen-tolerant, and standard-specific (e.g., `crystals-kyber` &rarr; `ML-KEM`, `fips 204` &rarr; `ML-DSA`, `sphincs+` &rarr; `SLH-DSA`, `p-256` &rarr; `ECDH`, `secp256k1` &rarr; `ECDSA`, `aes256` &rarr; `AES-256`).
- **Use Cases:** `key_exchange`, `key_agreement`, `kem` &rarr; `key_establishment`; `signature`, `signatures`, `signing` &rarr; `digital_signatures`; `bulk_encryption`, `data_encryption` &rarr; `symmetric_encryption`.

### Distinct Schemes & Ambiguous Inputs

1. **Ambiguous `"encryption"` Input:**
   - Unqualified `"encryption"` is rejected because it does not distinguish between asymmetric key transport/encapsulation and bulk symmetric data encryption.
   - **Result:** `risk_level: "Unrecognized Use Case"` with an explanatory message guiding the user to select either `key_establishment` or `symmetric_encryption`.
2. **Distinct Schemes (`X25519`, `Ed25519`):**
   - `X25519` is not aliased to ECDH (it is a Montgomery-curve Diffie-Hellman function, RFC 7748).
   - `Ed25519` is not aliased to ECDSA (it is an Edwards-curve signature scheme, RFC 8032).
   - **Result:** `risk_level: "Unrecognized Algorithm"` with technical context distinguishing them from NIST curves and guiding toward PQC transition.
3. **Incompatible Algorithm/Use-Case Combinations:**
   - Evaluating an algorithm for an unsupported role (e.g., `ML-KEM` for `digital_signatures` or `AES-256` for `key_establishment`) returns `risk_level: "Unsupported Combination"`, explains why the scheme cannot perform that function, and provides the appropriate PQC recommendation.

---

## 4. Output Contract (`assess_algorithm()` Schema)

Every call returns a Python `dict[str, Any]` guaranteed to contain exactly these 10 keys:

| Field | Type | Description | Example Value |
| :--- | :--- | :--- | :--- |
| `algorithm` | `str` | Canonical name (or raw input if unrecognized) | `"RSA"` |
| `use_case` | `str` | Evaluated canonical use case | `"key_establishment"` |
| `risk_level` | `str` | Qualitative prototype category | `"High Quantum Risk"` |
| `reason` | `str` | Rationale detailing Shor's/Grover's impact or PQC design | `"Vulnerable to Shor's algorithm on a CRQC..."` |
| `recommendation` | `str` | Actionable transition guidance and hybrid architecture advice | `"Migrate key establishment to ML-KEM (FIPS 203)..."` |
| `recommended_algorithms`| `list[str]` | List of standardized alternatives (empty if none/invalid) | `["ML-KEM"]` |
| `priority` | `str` | Urgency tier (`Immediate`, `High`, `Medium`, `Low`, `Maintain`, `N/A`) | `"Immediate"` |
| `family` | `str` | Cryptographic family | `"Asymmetric / Public-Key (Integer Factorization)"` |
| `references` | `list[str]` | Direct authoritative NIST CSRC URLs | `["https://csrc.nist.gov/pubs/fips/203/final", ...]` |
| `disclaimer` | `str` | Educational prototype and holistic system security notice | `"Educational Prototype Disclaimer: Assessments are..."` |

---

## 5. Teammate Smoke Test Script

Teammates can run this quick verification snippet to validate their local integration:

```python
"""smoke_test_security_engine.py - Run by teammates to test integration."""
from security_rules import (
    assess_algorithm,
    get_supported_algorithms,
    get_supported_use_cases,
)

def run_smoke_tests():
    # 1. Test supported algorithms and use cases
    algs = get_supported_algorithms()
    assert "RSA" in algs and "ML-KEM" in algs
    assert "key_establishment" in get_supported_use_cases()
    print("✅ Helper functions verified.")

    # 2. Test valid assessment (RSA key establishment)
    res_valid = assess_algorithm("RSA", "key_establishment")
    assert res_valid["risk_level"] == "High Quantum Risk"
    assert res_valid["priority"] == "Immediate"
    assert "ML-KEM" in res_valid["recommended_algorithms"]
    assert len(res_valid["references"]) >= 1
    print("✅ Valid assessment verified.")

    # 3. Test ambiguous use case rejection
    res_ambiguous = assess_algorithm("RSA", "encryption")
    assert res_ambiguous["risk_level"] == "Unrecognized Use Case"
    assert "ambiguous" in res_ambiguous["reason"].lower()
    print("✅ Ambiguous use case rejection verified.")

    # 4. Test distinct scheme handling (X25519 not silently mapped to ECDH)
    res_unsupported = assess_algorithm("X25519", "key_establishment")
    assert res_unsupported["risk_level"] == "Unrecognized Algorithm"
    assert "X25519" in res_unsupported["reason"]
    print("✅ Distinct algorithm separation verified.")

    # 5. Test output contract (all 10 keys present)
    expected_keys = {
        "algorithm", "use_case", "risk_level", "reason", "recommendation",
        "recommended_algorithms", "priority", "family", "references", "disclaimer"
    }
    assert set(res_valid.keys()) == expected_keys
    print("✅ Full 10-field output contract verified.")

    print("\n🎉 ALL SECURITY ENGINE SMOKE TESTS PASSED!")

if __name__ == "__main__":
    run_smoke_tests()
```

---

## 6. Environment Setup (Windows PowerShell)

The project has its own dedicated virtual environment located at `G:\QuantumSafe-Checker\.venv`.

### Activate the Environment
```powershell
Set-Location "G:\QuantumSafe-Checker"
.\.venv\Scripts\Activate.ps1
```

### Run the Full Test Suite
```powershell
# Option A: Direct python pytest execution
.\.venv\Scripts\python.exe -m pytest -v

# Option B: Active environment pytest execution
pytest -v
```

*Expected output: `85 passed in 0.2X seconds`.*

---

## 7. File Placement & Import Configurations

The security engine consists of two co-dependent files:
- `security_rules.py`
- `algorithms.json` (Knowledge base)

> **CRITICAL:** `algorithms.json` must always remain in the **exact same directory** as `security_rules.py`. `security_rules.py` loads `algorithms.json` using `Path(__file__).resolve().parent / "algorithms.json"`, making it resilient to whatever working directory a user runs the application from.

### Scenario A: Flat Structure (Root Directory)
If teammates place their scripts (`app.py`, `report_generator.py`) in the root directory:
```text
G:\QuantumSafe-Checker\
├── app.py
├── report_generator.py
├── security_rules.py
└── algorithms.json
```
**Import syntax:**
```python
from security_rules import assess_algorithm, get_supported_algorithms, get_supported_use_cases
```

### Scenario B: Subfolder / Package Structure
If the team organizes modules into a subfolder (e.g., `engine/` or `core/`):
```text
G:\QuantumSafe-Checker\
├── app.py
├── core/
│   ├── __init__.py
│   ├── security_rules.py
│   └── algorithms.json
```
**Import syntax from `app.py`:**
```python
from core.security_rules import assess_algorithm, get_supported_algorithms, get_supported_use_cases
```
*(No path adjustments needed inside `security_rules.py`; it will still automatically locate `core/algorithms.json`).*

### Scenario C: Standalone Scripts in Nested Folders
If running a script located inside a subfolder (e.g., `reports/generate.py`) importing from the parent root:
```python
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_rules import assess_algorithm
```
