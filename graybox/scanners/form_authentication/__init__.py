"""Form Field and Authentication category scanners."""
from __future__ import annotations

from graybox.scanners.form_authentication.scanners import (
    GBFORM01_ShoulderSurfing,
    GBFORM02_SensitiveDataEncryption,
    GBFORM03_Autocomplete,
    GBFORM04_RememberMe,
    GBFORM05_CaptchaFunctionality,
    GBFORM06_BruteForceProtection,
    GBFORM07_StrongPasswordPolicy,
    GBFORM08_UserEnumeration,
    GBFORM09_MFA,
    GBFORM10_DefaultCredentials,
    GBFORM11_CacheControls,
    GBFORM12_DefaultOTP,
    GBFORM13_EmailFlooding,
    GBFORM14_OTPFlooding,
    GBFORM15_OTPBypass,
    GBFORM16_OTPInvalidation,
)

__all__ = [
    "GBFORM01_ShoulderSurfing",
    "GBFORM02_SensitiveDataEncryption",
    "GBFORM03_Autocomplete",
    "GBFORM04_RememberMe",
    "GBFORM05_CaptchaFunctionality",
    "GBFORM06_BruteForceProtection",
    "GBFORM07_StrongPasswordPolicy",
    "GBFORM08_UserEnumeration",
    "GBFORM09_MFA",
    "GBFORM10_DefaultCredentials",
    "GBFORM11_CacheControls",
    "GBFORM12_DefaultOTP",
    "GBFORM13_EmailFlooding",
    "GBFORM14_OTPFlooding",
    "GBFORM15_OTPBypass",
    "GBFORM16_OTPInvalidation",
]
