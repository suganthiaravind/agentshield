"""AgentShield — pre-production security evaluator for AI agents.

Two-tier architecture (v2, Phase F shipped 2026-05-06): Tier 1 = semgrep
with a 6-family high-precision rule pack; Tier 2 = LLM-as-scanner via
Copilot in the user's IDE. See ARCHITECTURE_V2.md for the design and
TIER2_USAGE.md for the Copilot walkthrough.
"""

__version__ = "0.1.0"
