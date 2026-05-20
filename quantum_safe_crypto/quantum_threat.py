"""Quantum Threat Analyzer - 1M Qubit Assessment.

References:
    arXiv:2505.15917 - Gidney (2025)
    arXiv:2602.11457 - Iceberg (2026)
    Mosca's Inequality: X + Y > Z
"""

from typing import Dict, Tuple


class QuantumThreatAnalyzer:
    """Assess quantum risk based on Mosca's framework."""

    QUBIT_TIMELINE = {
        2012: 1_000_000_000,
        2019: 20_000_000,
        2025: 1_000_000,
        2026: 100_000,
    }

    ALGORITHMS = {
        "banking": ("ML-KEM-1024", "ML-DSA-87"),
        "iot": ("HQC", "FN-DSA"),
        "government": ("ML-KEM-1024", "SLH-DSA"),
    }

    def estimate_risk(self, data_sensitivity_years: int) -> Tuple[str, str]:
        """Return (risk_level, recommended_algorithm).

        Args:
            data_sensitivity_years: Years data must remain confidential
        """
        X = data_sensitivity_years
        Y = 7  # Transition time estimate (years)
        Z = 10  # CRQC timeline estimate (years)

        if X + Y > Z:
            return "HIGH", "ML-KEM-1024 + ML-DSA-65"
        elif X + Y > Z * 0.7:
            return "MEDIUM", "ML-KEM-768 + ML-DSA-44"
        else:
            return "LOW", "ML-KEM-512 + ML-DSA-44"

    def get_recommendation(self, use_case: str) -> Tuple[str, str]:
        """Return algorithm pair for use case."""
        uc = use_case.lower()
        if uc in self.ALGORITHMS:
            return self.ALGORITHMS[uc]
        return "ML-KEM-768", "ML-DSA-44"
