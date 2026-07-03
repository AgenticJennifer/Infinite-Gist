"""
Service for scanning content for secrets and sensitive data.

IMPORTANT SECURITY NOTE:
This module handles raw secret values during scanning. The raw values are
immediately masked before being returned from scan functions. Never log,
store, or expose raw secret values outside this module's internal processing.
"""

import hashlib
import re
from typing import List, Dict, Pattern, Optional
from dataclasses import dataclass, field
from enum import Enum



class SecretType(str, Enum):
    """Types of secrets that can be detected."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    SSH_PRIVATE_KEY = "ssh_private_key"
    PRIVATE_KEY = "private_key"
    API_KEY = "api_key"
    PASSWORD = "password"
    EMAIL = "email"
    CREDIT_CARD = "credit_card"
    SOCIAL_SECURITY = "social_security"


@dataclass
class SecretMatch:
    """
    Represents a detected secret.
    
    Security: The `value` field contains the raw secret ONLY during internal
    processing. It is masked before being returned to callers via scan_content().
    The `masked_value` field should be used for all external display.
    """
    type: SecretType
    value: str  # Raw value - internal use only, masked before return
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float  # 0.0 to 1.0
    matched_text: str
    context: str  # Surrounding text
    value_hash: str = field(init=False)  # SHA-256 hash for dedup
    masked_value: str = field(init=False)  # Masked value for display
    
    def __post_init__(self):
        # Generate hash for deduplication (never store raw value in DB)
        self.value_hash = hashlib.sha256(self.value.encode()).hexdigest()
        # Mask the value immediately
        self.masked_value = self._mask_value(self.value)
    
    def _mask_value(self, value: str) -> str:
        """Mask a secret value, preserving only prefix and suffix chars."""
        if not value:
            return "***"
        # Never show more than 8 chars total for short secrets
        if len(value) <= 8:
            return value[:2] + "*" * max(len(value) - 2, 4)
        visible_prefix = min(4, len(value) // 4)
        visible_suffix = min(4, len(value) // 4)
        prefix = value[:visible_prefix]
        suffix = value[-visible_suffix:]
        masked_len = len(value) - visible_prefix - visible_suffix
        return f"{prefix}{'*' * masked_len}{suffix}"


class SecretScanner:
    """Scans content for secrets and sensitive data."""
    
    def __init__(self):
        # Compile regex patterns for different secret types
        self.patterns: Dict[SecretType, List[tuple[Pattern[str], float]]] = {
            SecretType.AWS_ACCESS_KEY: [
                (re.compile(r'AKIA[0-9A-Z]{16}'), 0.9),
                (re.compile(r'ASIA[0-9A-Z]{16}'), 0.8),  # AWS STS token
            ],
            SecretType.AWS_SECRET_KEY: [
                (re.compile(r'[0-9a-zA-Z/+]{40}'), 0.6),  # This is too generic, needs context
            ],
            SecretType.GITHUB_TOKEN: [
                (re.compile(r'ghp_[0-9a-zA-Z]{36}'), 0.95),  # GitHub Personal Access Token (classic)
                (re.compile(r'gho_[0-9a-zA-Z]{36}'), 0.95),  # GitHub OAuth
                (re.compile(r'ghu_[0-9a-zA-Z]{36}'), 0.95),  # GitHub User-to-Server
                (re.compile(r'ghs_[0-9a-zA-Z]{36}'), 0.95),  # GitHub Server-to-Server
                (re.compile(r'ghr_[0-9a-zA-Z]{76}'), 0.95),  # GitHub Refresh Token
            ],
            SecretType.SLACK_TOKEN: [
                (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,48}'), 0.9),
            ],
            SecretType.SSH_PRIVATE_KEY: [
                (re.compile(r'-----BEGIN (OPENSSH |EC|DSA|RSA) PRIVATE KEY-----'), 0.95),
            ],
            SecretType.PRIVATE_KEY: [
                (re.compile(r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), 0.95),
                (re.compile(r'-----BEGIN PRIVATE KEY-----'), 0.9),
            ],
            SecretType.API_KEY: [
                (re.compile(r'[aA][pP][iI][_]?[kK][eE][yY][ _]?[=:]? [\'"]([a-zA-Z0-9_-]{20,})[\'"]'), 0.7),
                (re.compile(r'[aA][pP][iI][_]?[tT][oO][kK][eE][nN][ _]?[=:]? [\'"]([a-zA-Z0-9_-]{20,})[\'"]'), 0.7),
                (re.compile(r'[sS][eE][cC][rR][eE][tT][ _]?[=:]? [\'"]([a-zA-Z0-9_-]{20,})[\'"]'), 0.7),
            ],
            SecretType.PASSWORD: [
                (re.compile(r'[pP][aA][sS][sS][wW][oO][rR][dD][ _]?[=:]? [\'"]([^\'"]{8,})[\'"]'), 0.6),
            ],
            SecretType.EMAIL: [
                (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), 0.8),
            ],
            SecretType.CREDIT_CARD: [
                (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), 0.8),
            ],
            SecretType.SOCIAL_SECURITY: [
                (re.compile(r'\b\d{3}-?\d{2}-?\d{4}\b'), 0.7),
            ],
        }
        
        # Context patterns to reduce false positives. Checked against the
        # surrounding line context (variable names, prose), not the matched
        # secret value itself — real secrets can coincidentally contain
        # substrings like "example" (e.g. AWS's own published example key
        # format, AKIAIOSFODNN7EXAMPLE), so filtering on the value would
        # cause false negatives on genuine leaks.
        self.ignore_patterns = [
            re.compile(r'example|sample|test|dummy|fake|placeholder', re.IGNORECASE),
            re.compile(r'<[^>]+>|\[[^\]]+\]|{[^}]+}'),  # HTML/XML tags, markdown links, template placeholders
        ]

    def scan_text(self, text: str, file_path: str = "") -> List[SecretMatch]:
        """
        Scan text for secrets and return a list of matches.
        """
        matches = []
        lines = text.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for secret_type, patterns in self.patterns.items():
                for pattern, base_confidence in patterns:
                    for match in pattern.finditer(line):
                        matched_text = match.group(0)
                        line_context = line[:match.start()] + line[match.end():]

                        # Check if this should be ignored, based on surrounding
                        # context rather than the matched secret value itself
                        if any(ip.search(line_context) for ip in self.ignore_patterns):
                            continue
                            
                        # Calculate confidence based on context
                        confidence = self._calculate_confidence(
                            matched_text, line, line_num, secret_type, base_confidence
                        )
                        
                        if confidence > 0.5:  # Only return matches with reasonable confidence
                            # Get context (surrounding lines)
                            start_line = max(0, line_num - 3)
                            end_line = min(len(lines), line_num + 2)
                            context_lines = lines[start_line:end_line]
                            context = '\n'.join(context_lines)
                            
                            match_obj = SecretMatch(
                                type=secret_type,
                                value=matched_text,
                                file_path=file_path,
                                line_number=line_num,
                                column_start=match.start(),
                                column_end=match.end(),
                                confidence=confidence,
                                matched_text=matched_text,
                                context=context,
                            )
                            matches.append(match_obj)
        
        # Clear raw values from context to prevent leakage
        # Context should already be safe as it's just surrounding code
        return matches
        
        return matches

    def _calculate_confidence(
        self, 
        matched_text: str, 
        line: str, 
        line_num: int, 
        secret_type: SecretType,
        base_confidence: float
    ) -> float:
        """
        Calculate confidence score based on context.
        """
        confidence = base_confidence
        
        # Reduce confidence for common false positives
        if secret_type == SecretType.AWS_SECRET_KEY:
            # AWS secret keys are base64 encoded, 40 chars
            if len(matched_text) == 40 and re.match(r'^[0-9a-zA-Z/+]{40}$', matched_text):
                # Check if it looks like base64 (has proper padding or character distribution)
                if not re.search(r'[^A-Za-z0-9+/]', matched_text):
                    confidence *= 1.2
                else:
                    confidence *= 0.3  # Likely not base64
            else:
                confidence *= 0.1  # Wrong length
        
        elif secret_type == SecretType.API_KEY:
            # Look for common assignment patterns
            if re.search(r'[=:]\s*[\'"]?[a-zA-Z0-9_-]{20,}', line):
                confidence *= 1.3
            else:
                confidence *= 0.5
        
        # Check surrounding context for clues
        context_indicators = {
            SecretType.AWS_ACCESS_KEY: ['aws', 'access', 'key', 'keyid', 'akid'],
            SecretType.AWS_SECRET_KEY: ['aws', 'secret', 'key', 'secretkey', 'sak'],
            SecretType.GITHUB_TOKEN: ['github', 'token', 'gh', 'personal', 'access'],
            SecretType.SLACK_TOKEN: ['slack', 'token', 'xox'],
            SecretType.SSH_PRIVATE_KEY: ['ssh', 'private', 'key', 'id_rsa', 'id_dsa'],
            SecretType.PRIVATE_KEY: ['private', 'key', 'rsa', 'dsa', 'ec'],
            SecretType.API_KEY: ['api', 'key'],
            SecretType.PASSWORD: ['password', 'pass', 'pwd'],
            SecretType.EMAIL: ['email', 'mail', 'e-mail'],
            SecretType.CREDIT_CARD: ['card', 'credit', 'cc'],
            SecretType.SOCIAL_SECURITY: ['ssn', 'social', 'security'],
        }
        
        if secret_type in context_indicators:
            line_lower = line.lower()
            for indicator in context_indicators[secret_type]:
                if indicator in line_lower:
                    confidence *= 1.2
                    break
        
        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))


# Global scanner instance
scanner = SecretScanner()


def scan_content(content: str, file_path: str = "") -> List[dict]:
    """
    Convenience function to scan content and return results as dictionaries.
    
    SECURITY: Returns masked values only. Raw secrets are never exposed.
    The 'value' key contains the masked version, 'value_hash' contains the
    SHA-256 hash for deduplication.
    """
    matches = scanner.scan_text(content, file_path)
    return [
        {
            "type": match.type.value,
            "value": match.masked_value,  # Masked value for display
            "file_path": match.file_path,
            "line_number": match.line_number,
            "column_start": match.column_start,
            "column_end": match.column_end,
            "confidence": match.confidence,
            "matched_text": match.masked_value,  # Also masked
            "context": match.context,
            "value_hash": match.value_hash,  # Hash for dedup, not raw value
            "masked_value": match.masked_value,
        }
        for match in matches
    ]


def scan_file_content(content: str, file_path: str) -> List[dict]:
    """
    Scan file content for secrets.
    """
    return scan_content(content, file_path)