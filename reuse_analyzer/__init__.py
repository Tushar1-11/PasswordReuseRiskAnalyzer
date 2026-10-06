"""Smart Password Reuse Risk Analyzer - local, privacy-preserving reuse detection."""
from .config import Settings
from .service import PasswordReuseAnalyzer

__all__ = ["PasswordReuseAnalyzer", "Settings"]
__version__ = "2.0.0"
