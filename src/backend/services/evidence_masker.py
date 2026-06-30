"""
Evidence masking service.

Redacts secret values for safe display in UI, API responses,
and logs. Never exposes raw secret values outside scanning pipeline.
"""

from dataclasses import dataclass


@dataclass
class MaskedEvidence:
    """Result of masking a finding for display."""
    masked_value: str           # e.g. "ghp_************456"
    context_masked: str         # Surrounding code with the secret redacted
    snippet: str                # Single-line excerpt for quick preview
    value_hash: str             # SHA-256 hash for dedup (no raw value)
    secret_type: str
    severity: str
    confidence: float


class EvidenceMasker:
    """Masks secret values in findings for safe display."""

    def __init__(self, visible_prefix: int = 4, visible_suffix: int = 4):
        self.visible_prefix = visible_prefix
        self.visible_suffix = visible_suffix

    def mask_value(self, value: str) -> str:
        """
        Mask a secret value, preserving only prefix and suffix chars.

        Short values get heavier masking to prevent reconstruction.
        """
        if not value:
            return "***"

        # Never show more than 8 chars total for short secrets
        if len(value) <= 8:
            return value[:2] + "*" * max(len(value) - 2, 4)

        prefix = value[:self.visible_prefix]
        suffix = value[-self.visible_suffix:]
        masked_len = len(value) - self.visible_prefix - self.visible_suffix
        return f"{prefix}{'*' * masked_len}{suffix}"

    def mask_context(self, context: str, matched_text: str) -> str:
        """
        Replace the matched secret in context text with a masked version.

        Preserves surrounding code structure while hiding the actual value.
        """
        if not matched_text or not context:
            return context or ""

        masked = self.mask_value(matched_text)
        # Replace all occurrences (a secret might appear multiple times in context)
        result = context.replace(matched_text, masked)

        return result

    def create_masked_evidence(
        self,
        value: str,
        matched_text: str,
        context: str,
        value_hash: str,
        secret_type: str,
        severity: str,
        confidence: float,
    ) -> MaskedEvidence:
        """
        Create a fully masked evidence object for API/UI display.
        """
        masked_value = self.mask_value(value)
        context_masked = self.mask_context(context, matched_text)

        # Extract a single-line snippet from the masked context
        lines = context_masked.split("\n")
        snippet = ""
        for line in lines:
            if masked_value in line:
                snippet = line.strip()
                break
        if not snippet and lines:
            snippet = lines[0].strip()[:120]

        return MaskedEvidence(
            masked_value=masked_value,
            context_masked=context_masked,
            snippet=snippet,
            value_hash=value_hash,
            secret_type=secret_type,
            severity=severity,
            confidence=confidence,
        )

    def mask_line(self, line: str, secret: str) -> str:
        """Mask a single line containing a secret."""
        return line.replace(secret, self.mask_value(secret))


# Module-level instance
evidence_masker = EvidenceMasker()
