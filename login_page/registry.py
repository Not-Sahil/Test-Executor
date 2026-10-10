"""Canonical registry for the 17 login-page assessment testcases."""

LOGIN_PAGE_TESTS = [
    ("tc01_autocomplete", "Autocomplete", "login_page.scanners.tc01_autocomplete"),
    ("tc02_default_credentials", "Default Credentials", "login_page.scanners.tc02_default_credentials"),
    ("tc03_blank_credentials", "Blank Credentials", "login_page.scanners.tc03_blank_credentials"),
    ("tc04_user_enumeration", "User Enumeration", "login_page.scanners.tc04_user_enumeration"),
    ("tc05_password_validation", "Password Validation", "login_page.scanners.tc05_password_validation"),
    ("tc06_method_interchange", "Method Interchange", "login_page.scanners.tc06_method_interchange"),
    ("tc07_browser_memory_dump", "Browser Memory Dump", "login_page.scanners.tc07_browser_memory_dump"),
    ("tc08_login_over_http", "Login Over HTTP", "login_page.scanners.tc08_login_over_http"),
    ("tc09_cleartext_traffic", "Cleartext Traffic", "login_page.scanners.tc09_cleartext_traffic"),
    ("tc10_remember_me", "Remember Me", "login_page.scanners.tc10_remember_me"),
    ("tc11_shoulder_surfing", "Shoulder Surfing", "login_page.scanners.tc11_shoulder_surfing"),
    ("tc12_captcha_missing", "CAPTCHA Missing", "login_page.scanners.tc12_captcha_missing"),
    ("tc13_cors", "CORS", "login_page.scanners.tc13_cors"),
    ("tc14_sql_injection", "SQL Injection", "login_page.scanners.tc14_sql_injection"),
    ("tc15_ldap_ad", "LDAP / Active Directory Injection", "login_page.scanners.tc15_ldap_ad"),
    ("tc16_weak_password_encoding", "Weak Password Encoding", "login_page.scanners.tc16_weak_password_encoding"),
    ("tc17_rate_limit", "Rate Limit", "login_page.scanners.tc17_rate_limit"),
]
