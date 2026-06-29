"""
Service for scanning content for secrets and sensitive data.
"""

import re
import base64
import hashlib
from typing import List, Dict, Any, Optional, Pattern
from dataclasses import dataclass
from enum import Enum

from src.backend.core.config import settings


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
    """Represents a detected secret."""
    type: SecretType
    value: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    confidence: float  # 0.0 to 1.0
    matched_text: str
    context: str  # Surrounding text


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
        
        # Context patterns to reduce false positives
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
                        
                        # Check if this should be ignored
                        if any(ip.search(matched_text) for ip in self.ignore_patterns):
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
    """
    matches = scanner.scan_text(content, file_path)
    return [
        {
            "type": match.type.value,
            "value": match.value,
            "file_path": match.file_path,
            "line_number": match.line_number,
            "column_start": match.column_start,
            "column_end": match.column_end,
            "confidence": match.confidence,
            "matched_text": match.matched_text,
            "context": match.context,
        }
        for match in matches
    ]


def scan_file_content(content: str, file_path: str) -> List[dict]:
    """
    Scan file content for secrets.
    """
    return scan_content(content, file_path)