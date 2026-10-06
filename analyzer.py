"""Backwards-compatible import path: ``from analyzer import PasswordReuseAnalyzer``."""
from reuse_analyzer import PasswordReuseAnalyzer, Settings
from reuse_analyzer.scoring import SENSITIVITY_WEIGHTS, VALID_SENSITIVITIES

__all__ = ["PasswordReuseAnalyzer", "Settings", "SENSITIVITY_WEIGHTS", "VALID_SENSITIVITIES"]
