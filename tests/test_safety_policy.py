"""Tests for the production-safety policy (#6).

Covers:
  * `SafetyPolicy.allows` decision matrix across profile / env /
    confirm / confirm_destructive
  * MOCK_CAMPAIGN_CATALOGUE has the right destructive markings (5
    of 6 campaigns are destructive; guardrail-bypass is read-only)
  * `run_campaigns` skips disallowed campaigns and surfaces the
    reason on stderr
  * `target.yaml` loader recognises `env` field and rejects typos
  * Adapter exposes the resolved env so the CLI can inherit it
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.probe.campaign import (
    MOCK_CAMPAIGN_CATALOGUE,
    CampaignObjective,
    SafetyPolicy,
    run_campaigns,
)
from agentshield.probe.target_adapter import (
    AdapterConfigError,
    HttpGenericAdapter,
    TargetRequest,
    TargetResponse,
    load_adapter,
)


# ---------- decision matrix ----------


def _obj(*, destructive: bool) -> CampaignObjective:
    """Build a minimal CampaignObjective for the policy under test."""
    return CampaignObjective(
        name="t", title="t", category="detect", severity="high",
        objective="t", rationale="t", max_turns=1,
        destructive=destructive,
    )


@pytest.mark.parametrize("profile,env,confirm,confirm_destructive,destructive,expected", [
    # Non-destructive is always allowed.
    ("safe",        "staging",    False, False, False, True),
    ("safe",        "production", False, False, False, True),
    ("destructive", "production", True,  True,  False, True),
    # Safe profile blocks destructive regardless of other flags.
    ("safe",        "staging",    True,  True,  True,  False),
    ("safe",        "production", True,  True,  True,  False),
    # Destructive profile without --confirm blocks destructive.
    ("destructive", "staging",    False, False, True,  False),
    # Destructive profile with --confirm runs destructive in staging.
    ("destructive", "staging",    True,  False, True,  True),
    ("destructive", "mock",       True,  False, True,  True),
    # Destructive in production requires the extra confirm flag.
    ("destructive", "production", True,  False, True,  False),
    ("destructive", "production", True,  True,  True,  True),
])
def test_safety_policy_decision_matrix(
    profile, env, confirm, confirm_destructive, destructive, expected,
) -> None:
    policy = SafetyPolicy(
        profile=profile, target_env=env,
        confirm=confirm, confirm_destructive=confirm_destructive,
    )
    allowed, _ = policy.allows(_obj(destructive=destructive))
    assert allowed is expected


def test_safety_policy_rejects_bad_profile() -> None:
    with pytest.raises(ValueError, match="profile"):
        SafetyPolicy(profile="paranoid")


def test_safety_policy_rejects_bad_env() -> None:
    with pytest.raises(ValueError, match="target_env"):
        SafetyPolicy(target_env="qa")


def test_safety_policy_reason_strings_are_informative() -> None:
    """The reason gets surfaced on stderr at run time — make sure
    it actually explains the block."""
    policy = SafetyPolicy(profile="safe")
    _, reason = policy.allows(_obj(destructive=True))
    assert "safe" in reason and "destructive" in reason

    policy = SafetyPolicy(profile="destructive", confirm=False)
    _, reason = policy.allows(_obj(destructive=True))
    assert "--confirm" in reason

    policy = SafetyPolicy(
        profile="destructive", confirm=True,
        target_env="production", confirm_destructive=False,
    )
    _, reason = policy.allows(_obj(destructive=True))
    assert "production" in reason and "confirm-destructive" in reason


# ---------- catalogue markings ----------


def test_catalogue_marks_state_mutating_campaigns_destructive() -> None:
    """The five state-mutating / exfil / cross-tenant campaigns are
    marked destructive; guardrail-bypass (read-only system-prompt
    extraction) is the only non-destructive one."""
    by_name = {c.name: c for c in MOCK_CAMPAIGN_CATALOGUE}
    destructive_names = {
        "memory-poison-cross-session-exfil",
        "authority-escalation-destructive-action",
        "recon-tool-chain-exfil",
        "cross-tenant-data-fishing",
        "repudiation-deny-prior-action",
    }
    for name, c in by_name.items():
        if name in destructive_names:
            assert c.destructive is True, (
                f"{name} should be marked destructive"
            )
        else:
            assert c.destructive is False, (
                f"{name} should NOT be marked destructive (read-only)"
            )
    # The non-destructive one is the bypass campaign — sanity-check.
    assert by_name["guardrail-bypass-via-mutation"].destructive is False


# ---------- run_campaigns filtering ----------


class _NoopAdapter:
    """Adapter that returns the same canned reply for every send.
    We only use it to confirm run_campaigns reaches send_turn at
    all (or doesn't, for skipped campaigns)."""

    name = "noop-test"
    target_env = "staging"

    def __init__(self) -> None:
        self.calls = 0

    def send_turn(self, request: TargetRequest) -> TargetResponse:
        self.calls += 1
        return TargetResponse(
            reply_text="canned",
            raw_body=json.dumps({"reply": "canned"}),
            tool_calls=(),
            elapsed_ms=1,
            http_status=200,
        )

    def discover_metadata(self):
        from agentshield.probe.target_adapter import AgentMetadata
        return AgentMetadata()


def test_run_campaigns_skips_destructive_under_safe_profile(
    capsys: pytest.CaptureFixture,
) -> None:
    """Default policy is profile=safe; only the non-destructive
    campaign in the catalogue (guardrail-bypass) should run."""
    adapter = _NoopAdapter()
    out = run_campaigns(
        adapter=adapter,
        target_url="http://t",
        catalogue=MOCK_CAMPAIGN_CATALOGUE,
        safety=SafetyPolicy(profile="safe"),
    )
    # Only the read-only bypass campaign survives.
    assert {f.name for f in out} == {"guardrail-bypass-via-mutation"}
    # Skip reasons surfaced on stderr — one per destructive
    # campaign (5 of 6).
    err = capsys.readouterr().err
    skip_lines = [ln for ln in err.splitlines()
                  if "[redteam-safety] skipping" in ln]
    assert len(skip_lines) == 5
    assert all("--profile safe" in ln for ln in skip_lines)


def test_run_campaigns_runs_destructive_in_staging_with_confirm() -> None:
    adapter = _NoopAdapter()
    out = run_campaigns(
        adapter=adapter,
        target_url="http://t",
        catalogue=MOCK_CAMPAIGN_CATALOGUE,
        safety=SafetyPolicy(
            profile="destructive", confirm=True,
            target_env="staging",
        ),
    )
    # All 6 campaigns run.
    assert len(out) == 6


def test_run_campaigns_blocks_destructive_in_production_without_extra_flag(
    capsys: pytest.CaptureFixture,
) -> None:
    """The whole point of --target-env=production: even with
    --profile destructive --confirm, destructive campaigns are
    blocked unless --confirm-destructive is ALSO passed."""
    adapter = _NoopAdapter()
    out = run_campaigns(
        adapter=adapter,
        target_url="http://t",
        catalogue=MOCK_CAMPAIGN_CATALOGUE,
        safety=SafetyPolicy(
            profile="destructive", confirm=True,
            target_env="production", confirm_destructive=False,
        ),
    )
    assert {f.name for f in out} == {"guardrail-bypass-via-mutation"}
    err = capsys.readouterr().err
    assert "confirm-destructive" in err


def test_run_campaigns_authorizes_destructive_in_production_with_all_flags() -> None:
    adapter = _NoopAdapter()
    out = run_campaigns(
        adapter=adapter,
        target_url="http://t",
        catalogue=MOCK_CAMPAIGN_CATALOGUE,
        safety=SafetyPolicy(
            profile="destructive", confirm=True,
            target_env="production", confirm_destructive=True,
        ),
    )
    assert len(out) == 6


# ---------- target.yaml env loading ----------


def test_target_yaml_env_defaults_to_staging(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://localhost:8765/\n"
    )
    adapter = load_adapter(cfg)
    assert adapter.target_env == "staging"


def test_target_yaml_env_can_be_set_to_production(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://prod.example/agent\n"
        "  env: production\n"
    )
    adapter = load_adapter(cfg)
    assert adapter.target_env == "production"


def test_target_yaml_env_typo_rejected(tmp_path: Path) -> None:
    cfg = tmp_path / "target.yaml"
    cfg.write_text(
        "target:\n"
        "  type: http-generic\n"
        "  url: http://x/\n"
        "  env: prod\n"          # 'prod' is not a valid value; must
                                  # use 'production' explicitly
    )
    with pytest.raises(AdapterConfigError, match="target.env"):
        load_adapter(cfg)
