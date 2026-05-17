"""Safety profiles for probe execution.

`safe` (default): skips any payload flagged `destructive=True`. Suitable
for first-pass scans against staging environments without explicit
operator sign-off.

`destructive`: includes destructive payloads. Requires `--confirm` on
the CLI so operators can't run it accidentally — destructive payloads
can change state on the target (cancel real subscriptions, delete
records, etc.) even with a sandboxed harness.
"""

from __future__ import annotations

VALID_PROFILES = ("safe", "destructive")


def is_valid(profile: str) -> bool:
    return profile in VALID_PROFILES
