"""Encryption category scanners."""
from __future__ import annotations

from graybox.scanners.encryption.scanners import (
    GBENC01_TLSVersions,
    GBENC02_CertificateValidation,
    GBENC03_CredentialsOverHTTPS,
    GBENC04_LoginFormOverHTTPS,
    GBENC05_SessionTokensOverHTTPS,
    GBENC06_HSTS,
    GBENC07_SensitiveInfoInURL,
    GBENC08_SSLStripping,
)

__all__ = [
    "GBENC01_TLSVersions",
    "GBENC02_CertificateValidation",
    "GBENC03_CredentialsOverHTTPS",
    "GBENC04_LoginFormOverHTTPS",
    "GBENC05_SessionTokensOverHTTPS",
    "GBENC06_HSTS",
    "GBENC07_SensitiveInfoInURL",
    "GBENC08_SSLStripping",
]
