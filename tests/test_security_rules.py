"""
Automated unit and integration test suite for QuantumSafe-Checker Security Assessment Engine.

Covers:
- Every supported algorithm and valid use case.
- Input validation (empty, malformed, non-string, null).
- Unrecognized algorithm names and unsupported use cases.
- Unsupported algorithm / use-case combinations.
- Accurate recommendation purposes (KEM vs digital signatures vs symmetric).
- Proper differentiation between Shor's algorithm (asymmetric) and Grover's algorithm (symmetric).
- Verification of all required return dictionary fields and data types.
- Loading knowledge base relative to module path under varying working directories.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path so tests can run from anywhere
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from security_rules import (
    assess_algorithm,
    get_supported_algorithms,
    get_supported_use_cases,
    load_knowledge_base,
    normalize_algorithm_name,
    normalize_use_case,
    DEFAULT_DISCLAIMER,
    GENERAL_PQC_REFERENCE,
)

REQUIRED_FIELDS = {
    "algorithm",
    "use_case",
    "risk_level",
    "reason",
    "recommendation",
    "recommended_algorithms",
    "priority",
    "family",
    "references",
    "disclaimer",
}

EXPECTED_SUPPORTED_ALGORITHMS = [
    "RSA",
    "ECDH",
    "ECDSA",
    "AES-128",
    "AES-256",
    "ML-KEM",
    "ML-DSA",
    "SLH-DSA",
]


# ==============================================================================
# 1. Structure and Data Model Tests
# ==============================================================================

def test_knowledge_base_loads_successfully():
    """Verify that algorithms.json loads properly and contains expected structure."""
    kb = load_knowledge_base()
    assert isinstance(kb, dict)
    assert "algorithms" in kb
    assert "use_cases" in kb
    assert "metadata" in kb

    for alg in EXPECTED_SUPPORTED_ALGORITHMS:
        assert alg in kb["algorithms"], f"Expected algorithm {alg} missing from knowledge base"


def test_get_supported_algorithms_returns_expected_set():
    """Verify get_supported_algorithms lists all target algorithms."""
    algorithms = get_supported_algorithms()
    for expected in EXPECTED_SUPPORTED_ALGORITHMS:
        assert expected in algorithms


def test_get_supported_use_cases():
    """Verify get_supported_use_cases behavior globally and per algorithm."""
    all_cases = get_supported_use_cases()
    assert "key_establishment" in all_cases
    assert "digital_signatures" in all_cases
    assert "symmetric_encryption" in all_cases

    # Algorithm specific
    assert get_supported_use_cases("RSA") == ["key_establishment", "digital_signatures"]
    assert get_supported_use_cases("ECDH") == ["key_establishment"]
    assert get_supported_use_cases("ECDSA") == ["digital_signatures"]
    assert get_supported_use_cases("ML-KEM") == ["key_establishment"]
    assert get_supported_use_cases("ML-DSA") == ["digital_signatures"]
    assert get_supported_use_cases("SLH-DSA") == ["digital_signatures"]
    assert get_supported_use_cases("AES-256") == ["symmetric_encryption"]


def test_load_knowledge_base_independent_of_cwd(tmp_path: Path):
    """Verify knowledge base loads relative to module path even if cwd changes."""
    original_cwd = os.getcwd()
    try:
        os.chdir(tmp_path)
        # Verify cwd changed
        assert Path.cwd() == tmp_path
        kb = load_knowledge_base()
        assert "algorithms" in kb
        result = assess_algorithm("RSA", "key_establishment")
        assert result["algorithm"] == "RSA"
        assert result["risk_level"] == "High Quantum Risk"
    finally:
        os.chdir(original_cwd)


# ==============================================================================
# 2. Valid Algorithm and Use Case Combinations
# ==============================================================================

@pytest.mark.parametrize(
    "algorithm, use_case, expected_risk, expected_priority, expected_recommendations",
    [
        # RSA
        (
            "RSA",
            "key_establishment",
            "High Quantum Risk",
            "Immediate",
            ["ML-KEM"],
        ),
        (
            "RSA",
            "digital_signatures",
            "High Quantum Risk",
            "High",
            ["ML-DSA", "SLH-DSA"],
        ),
        # ECDH
        (
            "ECDH",
            "key_establishment",
            "High Quantum Risk",
            "Immediate",
            ["ML-KEM"],
        ),
        # ECDSA
        (
            "ECDSA",
            "digital_signatures",
            "High Quantum Risk",
            "High",
            ["ML-DSA", "SLH-DSA"],
        ),
        # AES-128
        (
            "AES-128",
            "symmetric_encryption",
            "Moderate Quantum Consideration",
            "Medium",
            ["AES-256"],
        ),
        # AES-256
        (
            "AES-256",
            "symmetric_encryption",
            "Quantum Resistant (Symmetric)",
            "Low",
            ["AES-256"],
        ),
        # ML-KEM
        (
            "ML-KEM",
            "key_establishment",
            "Standardized Post-Quantum / Quantum Safe",
            "Maintain",
            ["ML-KEM"],
        ),
        # ML-DSA
        (
            "ML-DSA",
            "digital_signatures",
            "Standardized Post-Quantum / Quantum Safe",
            "Maintain",
            ["ML-DSA"],
        ),
        # SLH-DSA
        (
            "SLH-DSA",
            "digital_signatures",
            "Standardized Post-Quantum / Quantum Safe",
            "Maintain",
            ["SLH-DSA"],
        ),
    ],
)
def test_valid_algorithm_assessments(
    algorithm: str,
    use_case: str,
    expected_risk: str,
    expected_priority: str,
    expected_recommendations: list[str],
):
    """Test every supported algorithm and valid use case produces correct fields and values."""
    res = assess_algorithm(algorithm, use_case)

    # Check all required fields are present
    assert set(res.keys()) == REQUIRED_FIELDS

    # Verify types
    assert isinstance(res["algorithm"], str)
    assert isinstance(res["use_case"], str)
    assert isinstance(res["risk_level"], str)
    assert isinstance(res["reason"], str)
    assert isinstance(res["recommendation"], str)
    assert isinstance(res["recommended_algorithms"], list)
    assert isinstance(res["priority"], str)
    assert isinstance(res["family"], str)
    assert isinstance(res["references"], list)
    assert isinstance(res["disclaimer"], str)

    # Content checks
    assert res["algorithm"] == algorithm
    assert res["use_case"] == use_case
    assert res["risk_level"] == expected_risk
    assert res["priority"] == expected_priority
    assert res["recommended_algorithms"] == expected_recommendations
    assert len(res["reason"]) > 20
    assert len(res["recommendation"]) > 20
    assert len(res["references"]) >= 1
    assert res["disclaimer"] == DEFAULT_DISCLAIMER


# ==============================================================================
# 3. Normalization and Alias Handling Tests
# ==============================================================================

@pytest.mark.parametrize(
    "raw_input, expected_canonical",
    [
        ("rsa", "RSA"),
        ("  RSA  ", "RSA"),
        ("rsa-2048", "RSA"),
        ("rsa-4096", "RSA"),
        ("ecdh", "ECDH"),
        ("ec-dh", "ECDH"),
        ("p-256", "ECDH"),
        ("p-384", "ECDH"),
        ("secp256r1", "ECDH"),
        ("ecdsa", "ECDSA"),
        ("ec-dsa", "ECDSA"),
        ("secp256k1", "ECDSA"),
        ("aes-128", "AES-128"),
        ("aes128", "AES-128"),
        ("AES 128", "AES-128"),
        ("aes-256", "AES-256"),
        ("aes256", "AES-256"),
        ("AES 256", "AES-256"),
        ("ml-kem", "ML-KEM"),
        ("mlkem", "ML-KEM"),
        ("fips 203", "ML-KEM"),
        ("crystals-kyber", "ML-KEM"),
        ("kyber", "ML-KEM"),
        ("ml-dsa", "ML-DSA"),
        ("mldsa", "ML-DSA"),
        ("fips 204", "ML-DSA"),
        ("crystals-dilithium", "ML-DSA"),
        ("slh-dsa", "SLH-DSA"),
        ("slhdsa", "SLH-DSA"),
        ("fips 205", "SLH-DSA"),
        ("sphincs+", "SLH-DSA"),
    ],
)
def test_algorithm_normalization(raw_input: str, expected_canonical: str):
    """Test resolution of various user casings, spacings, and aliases."""
    canonical = normalize_algorithm_name(raw_input)
    assert canonical == expected_canonical
    # Also verify through assess_algorithm
    res = assess_algorithm(raw_input, "key_establishment" if "KEM" in expected_canonical or "ECDH" in expected_canonical or expected_canonical == "RSA" else "digital_signatures" if "DSA" in expected_canonical else "symmetric_encryption")
    assert res["algorithm"] == expected_canonical


@pytest.mark.parametrize(
    "raw_use_case, expected_canonical",
    [
        ("key_establishment", "key_establishment"),
        ("KEY ESTABLISHMENT", "key_establishment"),
        ("key_exchange", "key_establishment"),
        ("key exchange", "key_establishment"),
        ("kem", "key_establishment"),
        ("digital_signatures", "digital_signatures"),
        ("DIGITAL SIGNATURES", "digital_signatures"),
        ("digital_signature", "digital_signatures"),
        ("signature", "digital_signatures"),
        ("signatures", "digital_signatures"),
        ("symmetric_encryption", "symmetric_encryption"),
        ("symmetric encryption", "symmetric_encryption"),
        ("bulk_encryption", "symmetric_encryption"),
    ],
)
def test_use_case_normalization(raw_use_case: str, expected_canonical: str):
    """Test resolution of use case variations."""
    assert normalize_use_case(raw_use_case) == expected_canonical


def test_encryption_use_case_rejected_as_ambiguous():
    """Verify 'encryption' is rejected as ambiguous and not automatically mapped based on algorithm."""
    # normalize_use_case must return None regardless of algorithm_hint
    assert normalize_use_case("encryption") is None
    assert normalize_use_case("encryption", algorithm_hint="RSA") is None
    assert normalize_use_case("encryption", algorithm_hint="AES-256") is None
    assert normalize_use_case("encryption", algorithm_hint="ML-KEM") is None
    assert normalize_use_case("public_key_encryption") is None
    assert normalize_use_case("asymmetric_encryption") is None

    # assess_algorithm must return Unrecognized Use Case with clear ambiguous diagnostic
    res_rsa = assess_algorithm("RSA", "encryption")
    assert set(res_rsa.keys()) == REQUIRED_FIELDS
    assert res_rsa["risk_level"] == "Unrecognized Use Case"
    assert "ambiguous" in res_rsa["reason"].lower()
    assert res_rsa["recommended_algorithms"] == []
    assert res_rsa["priority"] == "N/A"

    res_aes = assess_algorithm("AES-256", "encryption")
    assert set(res_aes.keys()) == REQUIRED_FIELDS
    assert res_aes["risk_level"] == "Unrecognized Use Case"
    assert "ambiguous" in res_aes["reason"].lower()
    assert res_aes["recommended_algorithms"] == []

    res_mlkem = assess_algorithm("ML-KEM", "encryption")
    assert res_mlkem["risk_level"] == "Unrecognized Use Case"
    assert "ambiguous" in res_mlkem["reason"].lower()


def test_valid_explicit_use_case_aliases_preserved():
    """Verify semantically valid aliases continue to normalize and assess correctly."""
    # Key establishment aliases
    assert normalize_use_case("key_exchange") == "key_establishment"
    assert normalize_use_case("key agreement") == "key_establishment"
    assert normalize_use_case("kem") == "key_establishment"

    res_ke = assess_algorithm("ECDH", "key_exchange")
    assert res_ke["use_case"] == "key_establishment"
    assert res_ke["risk_level"] == "High Quantum Risk"
    assert res_ke["recommended_algorithms"] == ["ML-KEM"]

    # Symmetric encryption aliases
    assert normalize_use_case("bulk_encryption") == "symmetric_encryption"
    assert normalize_use_case("data encryption") == "symmetric_encryption"

    res_bulk = assess_algorithm("AES-256", "bulk_encryption")
    assert res_bulk["use_case"] == "symmetric_encryption"
    assert res_bulk["risk_level"] == "Quantum Resistant (Symmetric)"
    assert res_bulk["recommended_algorithms"] == ["AES-256"]


def test_x25519_and_ed25519_not_silently_classified_as_ecdh_ecdsa():
    """Verify Ed25519 and X25519 are not silently mapped to ECDSA and ECDH."""
    # Normalization check
    assert normalize_algorithm_name("x25519") is None
    assert normalize_algorithm_name("X25519") is None
    assert normalize_algorithm_name("ed25519") is None
    assert normalize_algorithm_name("Ed25519") is None
    assert normalize_algorithm_name("ed448") is None
    assert normalize_algorithm_name("eddsa") is None

    # Assessment check: X25519
    res_x = assess_algorithm("X25519", "key_establishment")
    assert set(res_x.keys()) == REQUIRED_FIELDS
    assert res_x["risk_level"] == "Unrecognized Algorithm"
    assert res_x["algorithm"] == "X25519"
    assert "X25519" in res_x["reason"]
    assert "distinct scheme" in res_x["reason"].lower()
    assert res_x["recommended_algorithms"] == []

    # Assessment check: Ed25519
    res_ed = assess_algorithm("Ed25519", "digital_signatures")
    assert set(res_ed.keys()) == REQUIRED_FIELDS
    assert res_ed["risk_level"] == "Unrecognized Algorithm"
    assert res_ed["algorithm"] == "Ed25519"
    assert "Ed25519" in res_ed["reason"]
    assert "distinct signature scheme" in res_ed["reason"].lower()
    assert res_ed["recommended_algorithms"] == []

    # Legitimate NIST curve aliases for ECDH and ECDSA must still work
    assert normalize_algorithm_name("p-256") == "ECDH"
    assert normalize_algorithm_name("secp256k1") == "ECDSA"


# ==============================================================================
# 4. Input Validation and Malformed Inputs Tests
# ==============================================================================

@pytest.mark.parametrize(
    "bad_algorithm, bad_use_case",
    [
        (None, "key_establishment"),
        ("", "key_establishment"),
        ("   ", "key_establishment"),
        (12345, "key_establishment"),
        (["RSA"], "key_establishment"),
        ("RSA", None),
        ("RSA", ""),
        ("RSA", "   "),
        ("RSA", 999),
        (None, None),
        ("", ""),
    ],
)
def test_invalid_and_empty_inputs_handled_safely(bad_algorithm, bad_use_case):
    """Verify invalid inputs return predictable dictionary with Invalid Input risk level."""
    res = assess_algorithm(bad_algorithm, bad_use_case)
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Invalid Input"
    assert res["priority"] == "N/A"
    assert res["recommended_algorithms"] == []
    assert res["references"] == [GENERAL_PQC_REFERENCE]
    assert res["disclaimer"] == DEFAULT_DISCLAIMER


def test_unknown_algorithm_name():
    """Verify unrecognized algorithm returns informative dictionary without crashing."""
    res = assess_algorithm("DES", "symmetric_encryption")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unrecognized Algorithm"
    assert res["priority"] == "N/A"
    assert "DES" in res["reason"]
    assert "Currently supported algorithms" in res["reason"]
    assert res["recommended_algorithms"] == []


def test_unrecognized_use_case():
    """Verify unsupported use case returns informative dictionary."""
    res = assess_algorithm("RSA", "quantum_teleportation")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unrecognized Use Case"
    assert res["priority"] == "N/A"
    assert "quantum_teleportation" in res["reason"]
    assert "key_establishment" in res["reason"]


# ==============================================================================
# 5. Unsupported Algorithm / Use-Case Combinations Tests
# ==============================================================================

def test_ml_kem_cannot_sign():
    """
    ML-KEM is a Key-Encapsulation Mechanism and cannot be used for digital signatures.
    Assessments must clearly explain this and recommend ML-DSA/SLH-DSA.
    """
    res = assess_algorithm("ML-KEM", "digital_signatures")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unsupported Combination"
    assert "Key-Encapsulation Mechanism" in res["reason"]
    assert "digital signatures" in res["reason"].lower()
    assert res["recommended_algorithms"] == ["ML-DSA", "SLH-DSA"]


def test_ml_dsa_cannot_do_key_establishment():
    """
    ML-DSA is a signature scheme and cannot be used for key establishment.
    Engine must recommend ML-KEM.
    """
    res = assess_algorithm("ML-DSA", "key_establishment")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unsupported Combination"
    assert "digital signature" in res["reason"].lower()
    assert res["recommended_algorithms"] == ["ML-KEM"]


def test_slh_dsa_cannot_do_key_establishment():
    """
    SLH-DSA is a signature scheme and cannot be used for key establishment.
    Engine must recommend ML-KEM.
    """
    res = assess_algorithm("SLH-DSA", "key_establishment")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unsupported Combination"
    assert "digital signature" in res["reason"].lower()
    assert res["recommended_algorithms"] == ["ML-KEM"]


def test_ecdsa_cannot_do_key_establishment():
    """
    ECDSA is a signature scheme, not a key agreement protocol.
    """
    res = assess_algorithm("ECDSA", "key_establishment")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unsupported Combination"
    assert "ECDSA" in res["reason"]
    assert "ECDH" in res["reason"]
    assert res["recommended_algorithms"] == ["ML-KEM"]


def test_ecdh_cannot_do_digital_signatures():
    """
    ECDH is a key agreement protocol, not a signature scheme.
    """
    res = assess_algorithm("ECDH", "digital_signatures")
    assert set(res.keys()) == REQUIRED_FIELDS
    assert res["risk_level"] == "Unsupported Combination"
    assert "ECDH" in res["reason"]
    assert res["recommended_algorithms"] == ["ML-DSA", "SLH-DSA"]


def test_aes_cannot_do_digital_signatures_or_asymmetric_key_exchange():
    """
    AES is a symmetric cipher and cannot serve as asymmetric signatures or KEM.
    """
    res_sig = assess_algorithm("AES-256", "digital_signatures")
    assert res_sig["risk_level"] == "Unsupported Combination"
    assert "symmetric block cipher" in res_sig["reason"]
    assert res_sig["recommended_algorithms"] == ["ML-DSA", "SLH-DSA"]

    res_kem = assess_algorithm("AES-256", "key_establishment")
    assert res_kem["risk_level"] == "Unsupported Combination"
    assert "symmetric" in res_kem["reason"].lower()
    assert res_kem["recommended_algorithms"] == ["ML-KEM"]


def test_rsa_cannot_do_bulk_symmetric_encryption():
    """RSA is asymmetric and cannot be used for bulk symmetric encryption."""
    res = assess_algorithm("RSA", "symmetric_encryption")
    assert res["risk_level"] == "Unsupported Combination"
    assert "asymmetric" in res["reason"].lower()
    assert res["recommended_algorithms"] == ["AES-256"]


# ==============================================================================
# 6. Cryptographic Correctness & Distinction Tests
# ==============================================================================

def test_shors_algorithm_cited_for_asymmetric():
    """RSA, ECDH, and ECDSA assessments must cite Shor's algorithm and their mathematical problems."""
    rsa_res = assess_algorithm("RSA", "key_establishment")
    assert "Shor's algorithm" in rsa_res["reason"]
    assert "factor" in rsa_res["reason"].lower()

    ecdh_res = assess_algorithm("ECDH", "key_establishment")
    assert "Shor's algorithm" in ecdh_res["reason"]
    assert "discrete logarithm" in ecdh_res["reason"].lower() or "ecdlp" in ecdh_res["reason"].lower()

    ecdsa_res = assess_algorithm("ECDSA", "digital_signatures")
    assert "Shor's algorithm" in ecdsa_res["reason"]
    assert "discrete logarithm" in ecdsa_res["reason"].lower() or "ecdlp" in ecdsa_res["reason"].lower()


def test_grovers_algorithm_cited_for_symmetric():
    """
    AES assessments must cite Grover's algorithm and key length halving,
    and must NOT treat AES as vulnerable to Shor's algorithm.
    """
    aes128_res = assess_algorithm("AES-128", "symmetric_encryption")
    assert "Grover's algorithm" in aes128_res["reason"]
    assert "64" in aes128_res["reason"]
    assert "Shor" not in aes128_res["reason"] or "immune to shor" in aes128_res["reason"].lower()

    aes256_res = assess_algorithm("AES-256", "symmetric_encryption")
    assert "Grover's algorithm" in aes256_res["reason"]
    assert "128" in aes256_res["reason"]
    assert "Shor" not in aes256_res["reason"] or "immune to shor" in aes256_res["reason"].lower()


def test_harvest_now_decrypt_later_distinction():
    """
    Key establishment algorithms (RSA, ECDH) must highlight Harvest Now, Decrypt Later (HNDL)
    risks warranting Immediate priority, while signature algorithms have High priority.
    """
    rsa_ke = assess_algorithm("RSA", "key_establishment")
    assert "Harvest Now, Decrypt Later" in rsa_ke["reason"] or "HNDL" in rsa_ke["reason"]
    assert rsa_ke["priority"] == "Immediate"

    ecdh = assess_algorithm("ECDH", "key_establishment")
    assert "Harvest Now, Decrypt Later" in ecdh["reason"] or "HNDL" in ecdh["reason"]
    assert ecdh["priority"] == "Immediate"

    ecdsa = assess_algorithm("ECDSA", "digital_signatures")
    assert ecdsa["priority"] == "High"


def test_post_quantum_algorithms_do_not_claim_absolute_system_security():
    """
    Verify recommendations and disclaimers do not claim PQC guarantees total system security.
    """
    for pqc_alg, uc in [("ML-KEM", "key_establishment"), ("ML-DSA", "digital_signatures"), ("SLH-DSA", "digital_signatures")]:
        res = assess_algorithm(pqc_alg, uc)
        assert "does not alone guarantee" in res["disclaimer"].lower() or "not alone guarantee" in res["disclaimer"].lower()
        assert "hybrid" in res["recommendation"].lower() or "parameter" in res["recommendation"].lower() or "deploy" in res["recommendation"].lower()


# ==============================================================================
# 7. Authoritative References Tests
# ==============================================================================

def test_authoritative_nist_references():
    """Ensure all references use official NIST CSRC URLs with no invented URLs."""
    valid_prefixes = (
        "https://csrc.nist.gov/pubs/fips/203/final",
        "https://csrc.nist.gov/pubs/fips/204/final",
        "https://csrc.nist.gov/pubs/fips/205/final",
        "https://csrc.nist.gov/projects/post-quantum-cryptography",
    )

    for alg in EXPECTED_SUPPORTED_ALGORITHMS:
        use_cases = get_supported_use_cases(alg)
        for uc in use_cases:
            res = assess_algorithm(alg, uc)
            assert isinstance(res["references"], list)
            assert len(res["references"]) >= 1
            for ref in res["references"]:
                assert any(ref.startswith(prefix) for prefix in valid_prefixes), (
                    f"Unexpected reference URL '{ref}' found for {alg} in {uc}"
                )
