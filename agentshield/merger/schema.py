"""Validator for `.agentshield/tier2-findings.json` (Phase F.5).

Implements the schema documented in `agentshield/skills/tier2_output_schema.md.tmpl`.
Returns errors as `SchemaError` objects with a `field_path` so the merger
can print `findings[2].severity: invalid value 'urgent' (allowed: ...)` —
specific enough that the user can re-prompt Copilot to fix that one item.

Why hand-rolled instead of jsonschema:
- No new runtime dependency. Keeps `agentshield` a small install.
- Tier 2 JSON is small (≤ 200 findings typical); a 100-line validator is
  faster to grok than a JSON-schema dialect.
- Field-path messages tailored for "Copilot got the schema slightly wrong"
  are more actionable than generic jsonschema errors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- Enums per tier2_output_schema.md.tmpl ---

SEVERITY_ENUM = {"critical", "high", "medium", "low", "info"}
CATEGORY_ENUM = {"detect", "defend", "respond"}
VERDICT_ENUM = {"FP", "CD", "TP"}
CONFIDENCE_ENUM = {"high", "medium", "low"}  # optional field
SAIGE_TIER_ENUM = {"non-agent", "0", "1", "2", "3"}  # optional top-level field

# Required top-level fields.
TOP_LEVEL_REQUIRED = {
    "tier": int,
    "scanned_at": str,
    "agentshield_tier1_fingerprint": str,
    "scanned_files": list,
    "skipped_files": list,
    "findings": list,
    "tier1_fp_callouts": list,
}

# Required Finding fields.
FINDING_REQUIRED = {
    "rule_id": str,
    "category": str,
    "severity": str,
    "file": str,
    "line": int,
    "snippet": str,
    "message": str,
    "owasp_llm": list,
    "owasp_agentic": list,
    "mitre_atlas": list,
    "cwe": list,
    "remediation": str,
}

# Required Tier1FPCallout fields.
TIER1_CALLOUT_REQUIRED = {
    "tier1_finding_index": int,
    "file": str,
    "line": int,
    "tier1_rule": str,
    "verdict": str,
    "reasoning": str,
}


@dataclass
class SchemaError:
    """One validation failure. `field_path` points at the offending location.

    Examples:
        field_path="findings[2].severity", message="invalid value 'urgent'..."
        field_path="agentshield_tier1_fingerprint", message="missing required field"
    """

    field_path: str
    message: str

    def __str__(self) -> str:
        return f"{self.field_path}: {self.message}"


@dataclass
class ValidationResult:
    errors: list[SchemaError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _check_type(
    value: Any, expected: type, path: str, errors: list[SchemaError]
) -> bool:
    """Return True if `value` is of `expected` type. Records error on mismatch."""
    if expected is int and isinstance(value, bool):
        # Python `bool` is `int`-subclass; reject booleans where int expected.
        errors.append(
            SchemaError(path, f"expected int, got bool ({value!r})")
        )
        return False
    if not isinstance(value, expected):
        errors.append(
            SchemaError(
                path,
                f"expected {expected.__name__}, got {type(value).__name__} ({value!r})",
            )
        )
        return False
    return True


def _check_array_of_strings(
    value: Any, path: str, errors: list[SchemaError]
) -> None:
    """Framework arrays (owasp_llm, cwe, etc.) must be array[string]; null forbidden."""
    if not _check_type(value, list, path, errors):
        return
    for i, item in enumerate(value):
        if not isinstance(item, str):
            errors.append(
                SchemaError(
                    f"{path}[{i}]",
                    f"expected string, got {type(item).__name__} ({item!r})",
                )
            )


def _check_enum(
    value: Any, allowed: set[str], path: str, errors: list[SchemaError]
) -> None:
    if not isinstance(value, str):
        errors.append(
            SchemaError(path, f"expected string, got {type(value).__name__}")
        )
        return
    if value not in allowed:
        errors.append(
            SchemaError(
                path,
                f"invalid value {value!r} (allowed: {sorted(allowed)})",
            )
        )


def _validate_finding(
    finding: dict, path: str, errors: list[SchemaError]
) -> None:
    if not isinstance(finding, dict):
        errors.append(
            SchemaError(path, f"expected object, got {type(finding).__name__}")
        )
        return

    for fname, ftype in FINDING_REQUIRED.items():
        if fname not in finding:
            errors.append(SchemaError(f"{path}.{fname}", "missing required field"))
            continue
        if ftype is list:
            # framework arrays validated separately for array-of-string
            if fname in {"owasp_llm", "owasp_agentic", "mitre_atlas", "cwe"}:
                _check_array_of_strings(finding[fname], f"{path}.{fname}", errors)
            else:
                _check_type(finding[fname], list, f"{path}.{fname}", errors)
        else:
            _check_type(finding[fname], ftype, f"{path}.{fname}", errors)

    # F.24: Optional `ast` array (OWASP Agentic Skills Top 10). Permitted but
    # not required — only manifest-scanner findings tend to populate it.
    if "ast" in finding:
        _check_array_of_strings(finding["ast"], f"{path}.ast", errors)

    # Enum checks
    if "severity" in finding:
        _check_enum(finding["severity"], SEVERITY_ENUM, f"{path}.severity", errors)
    if "category" in finding:
        _check_enum(finding["category"], CATEGORY_ENUM, f"{path}.category", errors)

    # Line must be positive
    if "line" in finding and isinstance(finding["line"], int) and not isinstance(finding["line"], bool):
        if finding["line"] < 1:
            errors.append(
                SchemaError(
                    f"{path}.line",
                    f"line must be a positive integer, got {finding['line']}",
                )
            )

    # F.27: rule_id must start with the new "AS-C-" Copilot prefix OR
    # the legacy "TIER2-" prefix (back-compat for in-flight Copilot
    # outputs written before the rename).
    if "rule_id" in finding and isinstance(finding["rule_id"], str):
        rid = finding["rule_id"]
        if not (rid.startswith("AS-C-") or rid.startswith("TIER2-")):
            errors.append(
                SchemaError(
                    f"{path}.rule_id",
                    f"Tier 2 rule_id must start with 'AS-C-' (or legacy 'TIER2-'), "
                    f"got {finding['rule_id']!r}",
                )
            )

    # Optional confidence enum
    if "confidence" in finding:
        _check_enum(
            finding["confidence"], CONFIDENCE_ENUM, f"{path}.confidence", errors
        )


def _validate_callout(
    callout: dict, path: str, errors: list[SchemaError]
) -> None:
    if not isinstance(callout, dict):
        errors.append(
            SchemaError(path, f"expected object, got {type(callout).__name__}")
        )
        return

    for fname, ftype in TIER1_CALLOUT_REQUIRED.items():
        if fname not in callout:
            errors.append(SchemaError(f"{path}.{fname}", "missing required field"))
            continue
        _check_type(callout[fname], ftype, f"{path}.{fname}", errors)

    if "verdict" in callout:
        _check_enum(callout["verdict"], VERDICT_ENUM, f"{path}.verdict", errors)

    if "tier1_finding_index" in callout and isinstance(
        callout["tier1_finding_index"], int
    ) and not isinstance(callout["tier1_finding_index"], bool):
        if callout["tier1_finding_index"] < 0:
            errors.append(
                SchemaError(
                    f"{path}.tier1_finding_index",
                    "must be >= 0",
                )
            )


def validate_tier2_findings(payload: Any) -> ValidationResult:
    """Validate a parsed `tier2-findings.json` payload.

    Returns a ValidationResult; check `.ok` and iterate `.errors` for
    field-path-specific messages.
    """
    result = ValidationResult()
    errors = result.errors

    if not isinstance(payload, dict):
        errors.append(
            SchemaError(
                "<root>",
                f"expected object, got {type(payload).__name__}",
            )
        )
        return result

    # Top-level required fields + types
    for fname, ftype in TOP_LEVEL_REQUIRED.items():
        if fname not in payload:
            errors.append(SchemaError(fname, "missing required field"))
            continue
        _check_type(payload[fname], ftype, fname, errors)

    # tier must be exactly 2
    if "tier" in payload and isinstance(payload["tier"], int) and not isinstance(
        payload["tier"], bool
    ):
        if payload["tier"] != 2:
            errors.append(
                SchemaError(
                    "tier",
                    f"must be 2 for Tier 2 output, got {payload['tier']}",
                )
            )

    # Optional SAIGE classification (F.16). If saige_tier is present, the value
    # must be a valid enum member AND saige_tier_reasoning must also be a string.
    if "saige_tier" in payload:
        _check_enum(payload["saige_tier"], SAIGE_TIER_ENUM, "saige_tier", errors)
        if "saige_tier_reasoning" not in payload:
            errors.append(
                SchemaError(
                    "saige_tier_reasoning",
                    "missing required field — saige_tier_reasoning must be present "
                    "whenever saige_tier is present",
                )
            )
        else:
            _check_type(
                payload["saige_tier_reasoning"], str, "saige_tier_reasoning", errors
            )

    # Per-finding validation
    if isinstance(payload.get("findings"), list):
        for i, finding in enumerate(payload["findings"]):
            _validate_finding(finding, f"findings[{i}]", errors)

    # Per-callout validation
    if isinstance(payload.get("tier1_fp_callouts"), list):
        for i, callout in enumerate(payload["tier1_fp_callouts"]):
            _validate_callout(callout, f"tier1_fp_callouts[{i}]", errors)

    return result
