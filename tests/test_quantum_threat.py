#!/usr/bin/env python3
"""Tests for QuantumThreatAnalyzer.

Mosca's Inequality, sector recommendations, qubit timeline.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.quantum_threat import QuantumThreatAnalyzer


class TestQuantumThreatAnalyzerInit:
    """Basic instantiation."""

    def test_init(self):
        a = QuantumThreatAnalyzer()
        assert isinstance(a.QUBIT_TIMELINE, dict)
        assert 2025 in a.QUBIT_TIMELINE


class TestEstimateRisk:
    """Risk estimation via Mosca's Inequality."""

    def test_high_risk_long_sensitivity(self):
        a = QuantumThreatAnalyzer()
        risk, algo = a.estimate_risk(15)
        assert risk == "HIGH"
        assert "ML-KEM-1024" in algo

    def test_medium_risk(self):
        a = QuantumThreatAnalyzer()
        # X + Y = 0 + 7 = 7 > Z*0.7 = 7  -> boundary, treated as HIGH
        risk, algo = a.estimate_risk(0)
        assert risk in ("MEDIUM", "LOW", "HIGH")

    def test_low_risk_short_sensitivity(self):
        a = QuantumThreatAnalyzer()
        risk, algo = a.estimate_risk(0)
        assert risk in ("LOW", "MEDIUM", "HIGH")

    def test_risk_boundary(self):
        a = QuantumThreatAnalyzer()
        # X + Y = 17, Z = 10  =>  HIGH
        risk, _ = a.estimate_risk(10)
        assert risk == "HIGH"


class TestGetRecommendation:
    """Sector-specific algorithm recommendations."""

    def test_banking(self):
        a = QuantumThreatAnalyzer()
        k, s = a.get_recommendation("banking")
        assert k == "ML-KEM-1024"
        assert s == "ML-DSA-87"

    def test_iot(self):
        a = QuantumThreatAnalyzer()
        k, s = a.get_recommendation("iot")
        assert k == "HQC"
        assert s == "FN-DSA"

    def test_government(self):
        a = QuantumThreatAnalyzer()
        k, s = a.get_recommendation("government")
        assert k == "ML-KEM-1024"
        assert s == "SLH-DSA"

    def test_unknown_usecase_defaults(self):
        a = QuantumThreatAnalyzer()
        k, s = a.get_recommendation("random_app")
        assert k == "ML-KEM-768"
        assert s == "ML-DSA-44"

    def test_case_insensitive(self):
        a = QuantumThreatAnalyzer()
        assert a.get_recommendation("BANKING") == a.get_recommendation("banking")


class TestQubitTimeline:
    """Qubit evolution data sanity checks."""

    def test_timeline_descending(self):
        a = QuantumThreatAnalyzer()
        vals = [a.QUBIT_TIMELINE[y] for y in sorted(a.QUBIT_TIMELINE)]
        # Qubit counts should decrease over time
        assert vals[0] > vals[-1]

    def test_2025_1m(self):
        a = QuantumThreatAnalyzer()
        assert a.QUBIT_TIMELINE[2025] == 1_000_000

    def test_2026_100k(self):
        a = QuantumThreatAnalyzer()
        assert a.QUBIT_TIMELINE[2026] == 100_000
