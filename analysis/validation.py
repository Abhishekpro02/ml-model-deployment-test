from difflib import Differ
from typing import Dict, List, Optional
import re


class HighRiskValidator:
    """Updated with 2023 CWE Critical List and False Positive Reduction"""

    # Updated Critical CWE List (OWASP Top 10 2023 + CWE Top 25 2023)
    CRITICAL_CWE = {
        # Injection Flaws
        "CWE-787",  # Out-of-bounds Write
        "CWE-79",  # Cross-site Scripting (XSS)
        "CWE-89",  # SQL Injection
        "CWE-78",  # OS Command Injection
        "CWE-20",  # Improper Input Validation

        # Memory Safety
        "CWE-125",  # Out-of-bounds Read
        "CWE-119",  # Improper Restriction of Operations within Memory Buffer

        # Sensitive Data Exposure
        "CWE-798",  # Use of Hard-coded Credentials
        "CWE-327",  # Broken Crypto

        # Access Control
        "CWE-862",  # Missing Authorization
        "CWE-287",  # Improper Authentication

        # Risky Resource Management
        "CWE-416",  # Use After Free
        "CWE-190",  # Integer Overflow
        "CWE-502",  # Deserialization of Untrusted Data

        # Common Exploit Targets
        "CWE-352",  # Cross-Site Request Forgery (CSRF)
        "CWE-434",  # Unrestricted Upload of File
        "CWE-732",  # Incorrect Permission Assignment
        "CWE-918"  # Server-Side Request Forgery (SSRF)
    }

    def __init__(self):
        self.differ = Differ()
        self.safe_patterns = {
            "CWE-89": [  # SQL Injection
                r"execute\(.*%s",  # Python parameterized
                r"SqlParameter",  # C# parameterized
                r"PreparedStatement",  # Java
                r"pg-escape"  # Node.js
            ],
            "CWE-78": [  # OS Command Injection
                r"subprocess\.run\(.*shell=False",
                r"ProcessStartInfo\(.*UseShellExecute\s*=\s*false",
                r"execve\("
            ],
            "CWE-79": [  # XSS
                r"escape\(\)",
                r"HtmlEncode\(\)",
                r"DOMPurify\.sanitize\("
            ]
        }

    def validate(self, result: Dict) -> Dict:
        """Enhanced validation with pattern checks and context analysis"""
        validation = {
            "valid": False,
            "confidence": 0.0,
            "warnings": [],
            "critical_cwe_verified": False
        }

        if not self._is_critical_cwe(result):
            return {**validation, "valid": True}  # Non-critical passes automatically

        # Base validation
        base_checks = [
            self._validate_cwe_mapping(result),
            self._validate_fix_impact(result),
            self._validate_safe_patterns(result)
        ]

        # Confidence scoring
        validation["confidence"] = sum(1 for check in base_checks if check) / len(base_checks)

        # Context-aware validation
        context_checks = [
            self._validate_blacklist(result),
            self._validate_whitelist(result),
            self._validate_unit_test_coverage(result)
        ]

        validation["confidence"] += sum(0.2 for check in context_checks if check)
        validation["confidence"] = min(validation["confidence"], 1.0)

        # Final determination
        validation["valid"] = validation["confidence"] >= 0.8
        validation["critical_cwe_verified"] = validation["valid"]

        return validation

    def _is_critical_cwe(self, result: Dict) -> bool:
        return result.get("cwe") in self.CRITICAL_CWE

    def _validate_cwe_mapping(self, result: Dict) -> bool:
        """Verify CWE is properly mapped to vulnerability type"""
        cwe = result.get("cwe", "")
        vuln_type = result.get("vulnerabilityType", "").lower()

        mapping = {
            "CWE-89": ["sql", "injection"],
            "CWE-78": ["command", "os"],
            "CWE-79": ["xss", "cross-site"],
            "CWE-787": ["overflow", "buffer", "memory"],
            "CWE-20": ["input", "validation"]
        }

        required_keywords = mapping.get(cwe, [])
        return all(kw in vuln_type for kw in required_keywords)

    def _validate_fix_impact(self, result: Dict) -> bool:
        """Enhanced diff analysis with semantic validation"""
        original = '\n'.join(line['lineCode'] for line in result.get("vulnerabilityLines", []))
        fixed = result.get("fixCode", "")

        # 1. Line-level diff check
        diff = list(self.differ.compare(original.splitlines(), fixed.splitlines()))
        line_changes = any(line.startswith('-') for line in diff)

        # 2. Semantic pattern check
        cwe = result.get("cwe")
        patterns = self.safe_patterns.get(cwe, [])
        pattern_found = any(
            re.search(pattern, fixed, re.IGNORECASE)
            for pattern in patterns
        )

        return line_changes and pattern_found

    def _validate_safe_patterns(self, result: Dict) -> bool:
        """Check for language-specific safe patterns"""
        cwe = result.get("cwe")
        code = result.get("fixCode", "")
        patterns = self.safe_patterns.get(cwe, [])

        return any(
            re.search(pattern, code, re.IGNORECASE)
            for pattern in patterns
        )

    def _validate_blacklist(self, result: Dict) -> bool:
        """Check for dangerous functions in fixed code"""
        blacklist = {
            "CWE-78": ["system(", "popen(", "exec(", "ShellExecute("],
            "CWE-89": ["sql += ", "execute(", "raw_query("],
            "CWE-79": ["innerHTML", "document.write("]
        }

        cwe = result.get("cwe")
        dangerous_funcs = blacklist.get(cwe, [])
        fixed_code = result.get("fixCode", "")

        return not any(func in fixed_code for func in dangerous_funcs)

    def _validate_whitelist(self, result: Dict) -> bool:
        """Verify use of approved security libraries"""
        whitelist = {
            "CWE-89": ["SQLAlchemy", "Hibernate", "Entity Framework"],
            "CWE-79": ["React", "DOMPurify", "OWASP Java Encoder"],
            "CWE-327": ["Bouncy Castle", "OpenSSL", "cryptography"]
        }

        cwe = result.get("cwe")
        approved_libs = whitelist.get(cwe, [])
        fixed_code = result.get("fixCode", "")

        return any(lib in fixed_code for lib in approved_libs)

    def _validate_unit_test_coverage(self, result: Dict) -> bool:
        """Check if fix includes test coverage indicators"""
        test_indicators = [
            "# Test case for vulnerability fix",
            "// Vulnerability test",
            "describe('Security fix verification'",
            "@Test public void testVulnerabilityFix()"
        ]

        return any(indicator in result.get("fixCode", "")
                   for indicator in test_indicators)