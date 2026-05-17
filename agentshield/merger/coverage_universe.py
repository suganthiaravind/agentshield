"""Per-framework universes + scanner-coverage computation for the
report's Coverage Matrix.

The matrix shows three states per framework item:

  - "issues"      → in this run's findings (≥1 finding tagged with it)
  - "clean"       → scanner has at least one rule that *could* fire on
                    this item, but nothing fired in this run
  - "not scanned" → item is in the framework's universe but no rule in
                    the bundled pack maps to it (a real coverage gap)

`FRAMEWORK_UNIVERSES` enumerates the canonical IDs per framework. For
OWASP LLM / Agentic / AST10 these are the full official top-N lists.
For MITRE ATLAS and CWE — whose universes are unbounded in practice —
we curate the LLM/Agent-app-code-relevant subset. The principle is:
the scanner's coverage (union of `framework_mappings` across the rule
pack) MUST be a subset of `FRAMEWORK_UNIVERSES[<key>]`. Any rule-pack
addition that references a previously-unlisted ID will fail the
`test_universe_contains_all_scanner_ids` check (added so the universe
stays honest as rules evolve).
"""

from __future__ import annotations

from typing import Iterable


# ---------- canonical IDs per framework ----------
#
# Order matters — chips render in declaration order, which makes the
# matrix scannable left-to-right for the common case (LLM01 first, …).

# OWASP LLM Top 10 for LLM Applications v2 (2025 release) — curated subset.
# https://genai.owasp.org/llm-top-10/
#
# The full Top 10 mixes LLM-application threats with model-layer / data-
# pipeline threats. AgentShield targets *agent* code (the call-site, the
# tool surface, the orchestration layer, the SKILL.md manifest), so we
# scope this universe to the items that manifest in app code:
#
#   Kept (call-site / agent-layer):
#     LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure,
#     LLM05 Improper Output Handling, LLM06 Excessive Agency,
#     LLM07 System Prompt Leakage, LLM10 Unbounded Consumption.
#
#   Dropped (model-layer / data-pipeline — better covered by ML-Ops or
#   ATLAS scanners than by a code-side tool):
#     LLM03 Supply Chain     → covered by ATLAS T0010 / CWE-494/829
#     LLM04 Data Poisoning   → covered by ATLAS T0019
#     LLM08 Vector/Embedding → covered by ATLAS / CWE
#     LLM09 Misinformation   → covered by OWASP Agentic T5 (Cascading
#                              Hallucination), the agent-layer framing
#
# Rule IDs that still contain `LLM03`/`LLM04`/`LLM08`/`LLM09` as their
# anchor segment are preserved verbatim (no ID renames) — the rules
# remain but their `owasp_llm` tag list no longer includes the dropped
# items. Suppression comments and external dashboards keyed on those
# IDs continue to work.
OWASP_LLM_UNIVERSE: list[str] = [
    "LLM01",  # Prompt Injection
    "LLM02",  # Sensitive Information Disclosure
    "LLM05",  # Improper Output Handling
    "LLM06",  # Excessive Agency
    "LLM07",  # System Prompt Leakage
    "LLM10",  # Unbounded Consumption
]

# OWASP Agentic AI Top 10 (T1–T15 as of the late-2025 working draft).
# https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
OWASP_AGENTIC_UNIVERSE: list[str] = [
    "T1",   # Memory Poisoning
    "T2",   # Tool Misuse
    "T3",   # Privilege Compromise
    "T4",   # Resource Overload
    "T5",   # Cascading Hallucination
    "T6",   # Intent Breaking & Goal Manipulation
    "T7",   # Misaligned & Deceptive Behaviors
    "T8",   # Repudiation & Untraceability
    "T9",   # Identity Spoofing & Impersonation
    "T10",  # Overwhelmed Human-in-the-Loop
    "T11",  # Unexpected RCE & Code Attacks
    "T12",  # Agent Communication Poisoning
    "T13",  # Rogue Agents in Multi-Agent Systems
    "T14",  # Human Attacks on Multi-Agent Systems
    "T15",  # Human Manipulation
]

# OWASP Agentic Skills Top 10 (AST10) preview.
# https://github.com/OWASP/www-project-agentic-skills-top-10
OWASP_AST_UNIVERSE: list[str] = [
    "AST01",  # Untrusted Skill Loading
    "AST02",  # Skill Hijacking
    "AST03",  # Insecure Skill Manifest
    "AST04",  # Excessive Permissions
    "AST05",  # Skill Supply Chain
    "AST06",  # Secrets in Skill Bundle
    "AST07",  # Skill Output Injection
    "AST08",  # Cross-Skill Privilege Escalation
    "AST09",  # Inadequate Skill Logging
    "AST10",  # Skill Behavior Drift
]

# MITRE ATLAS — curated LLM / agent-relevant techniques.
# https://atlas.mitre.org/techniques
# Full ATLAS has ~80 techniques across many ML threat surfaces; the
# subset below is the one that maps to threats an app-code scanner can
# plausibly detect or defend against. "Not scanned" here means "in this
# curated relevant subset but not yet covered by any AgentShield rule."
MITRE_ATLAS_UNIVERSE: list[str] = [
    "AML.T0010",  # ML Supply Chain Compromise
    "AML.T0011",  # User Execution: Unsafe ML Artifacts
    "AML.T0012",  # Valid Accounts
    "AML.T0018",  # Backdoor ML Model
    "AML.T0019",  # Publish Poisoned Datasets
    "AML.T0024",  # Exfiltration via ML Inference API
    "AML.T0029",  # Denial of ML Service
    "AML.T0050",  # Command and Scripting Interpreter
    "AML.T0051",  # LLM Prompt Injection
    "AML.T0052",  # Phishing (LLM-aided)
    "AML.T0053",  # LLM Plugin Compromise
    "AML.T0054",  # LLM Jailbreak
    "AML.T0055",  # Unsecured Credentials
    "AML.T0056",  # LLM Meta Prompt Extraction
    "AML.T0057",  # LLM Data Leakage
]

# CWE — curated subset most relevant to LLM/agent app code surfaces.
# Full CWE is 1000+ weaknesses; we list the ones that show up in the
# kinds of code AgentShield actually targets (request handlers, tool
# wrappers, secret handling, agent config, agent logging). The list
# is deliberately tight: generic AppSec CWEs (CWE-22 path traversal,
# CWE-295 cert validation, CWE-522 credential transit, etc.) are
# OUT of scope by design — a general-purpose static scanner
# (semgrep-pro, CodeQL, Snyk) covers those better than we would. The
# Coverage tab's CWE matrix should read as "what AgentShield can speak
# to in the agent's threat model," not "everything in CWE."
# MUST be a superset of every CWE the bundled rule pack references —
# `test_universe_contains_all_scanner_ids` enforces this.
CWE_UNIVERSE: list[str] = [
    "CWE-78",   # OS Command Injection
    "CWE-79",   # XSS
    "CWE-89",   # SQL Injection
    "CWE-94",   # Code Injection
    "CWE-200",  # Information Exposure
    "CWE-269",  # Improper Privilege Management
    "CWE-287",  # Improper Authentication
    "CWE-319",  # Cleartext Transmission
    "CWE-322",  # Key Exchange Without Entity Authentication
    "CWE-345",  # Insufficient Verification of Authenticity
    "CWE-400",  # Uncontrolled Resource Consumption
    "CWE-489",  # Active Debug Code
    "CWE-494",  # Download of Code Without Integrity Check
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-532",  # Insertion of Sensitive Information into Log File
    "CWE-732",  # Incorrect Permission Assignment for Critical Resource
    "CWE-778",  # Insufficient Logging
    "CWE-798",  # Use of Hard-coded Credentials
    "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
    "CWE-918",  # SSRF (agent-side: LLM-derived URL into unrestricted egress)
]


FRAMEWORK_UNIVERSES: dict[str, list[str]] = {
    "owasp_llm": OWASP_LLM_UNIVERSE,
    "owasp_agentic": OWASP_AGENTIC_UNIVERSE,
    "mitre_atlas": MITRE_ATLAS_UNIVERSE,
    "cwe": CWE_UNIVERSE,
    "ast": OWASP_AST_UNIVERSE,
}


# ---------- gap reasons ----------
#
# Hover-tooltip text shown for "not scanned" chips in the Coverage Matrix.
# Each entry is keyed by (framework_key, item_id). Items absent from this
# dict fall back to a generic message. Reasons are written to be honest
# — they distinguish:
#
#   (a) "permanent out-of-scope"  — threat lives outside static code analysis
#                                   (runtime / human / multi-agent orchestration)
#   (b) "plausible to add"        — a Tier 1 / Tier 2 rule could plausibly cover
#                                   this; tracked as a coverage backlog item
#   (c) "covered elsewhere"       — overlaps an item the scanner DOES cover
#                                   under a different framework axis
#
# The matrix is meant to be diagnostic, not aspirational — never claim
# coverage we don't have.
COVERAGE_GAP_REASONS: dict[tuple[str, str], str] = {
    # OWASP Agentic AI Top 10 — the tail (T12–T15) shifts from code-level
    # patterns into multi-agent orchestration and operator-layer threats.
    # T12 and T13 now covered by rules D-LLM01-005 / D-LLM01-006 plus
    # the Path B runtime probes (orchestrator → downstream-agent fixture
    # in testbed/mock-agent). Left here as reference for the journey.
    ("owasp_agentic", "T14"): (
        "Human Attacks on Multi-Agent Systems (social engineering of "
        "human-in-the-loop). Operator-layer threat with no code-level "
        "signature. Path B's LLM-judge could flag deceptive response "
        "patterns as a partial signal, but real coverage is operator "
        "training + UX guardrails, not a scanner."
    ),
    ("owasp_agentic", "T15"): (
        "Human Manipulation. Operator-layer threat — addressed via "
        "operator training and UX guardrails, not scanners or probes. "
        "Remains out of scope by design."
    ),

    # MITRE ATLAS — most gaps are runtime / pipeline concerns rather than
    # app-code patterns.
    ("mitre_atlas", "AML.T0018"): (
        "Model-supply-chain attack; detection lives in the model training / "
        "serving pipeline, not in app code."
    ),
    ("mitre_atlas", "AML.T0029"): (
        "Partial overlap with LLM10 / CWE-400 (timeouts, covered); DoS-"
        "specific patterns (e.g. adversarial loops) need traffic-level "
        "instrumentation."
    ),
    ("mitre_atlas", "AML.T0052"): (
        "LLM-aided phishing is delivered to end-users — defenses belong to "
        "output handling / human review, not the LLM call site."
    ),
    # AML.T0054 now mapped onto D-LLM01-001 (prompt injection) — the
    # static rule finds the path, the Path B runtime probe confirms the
    # jailbreak actually lands at the LLM.
    ("mitre_atlas", "AML.T0055"): (
        "Overlaps CWE-798 hardcoded credentials (covered); ATLAS framing "
        "focuses on broker / vault misconfig outside the app."
    ),
    # AML.T0056 now covered by rule D013 + Path B probe — static rule
    # finds the error-path leak surface, runtime probe extracts the
    # prompt + embedded escalation key to confirm the leakage.
    ("mitre_atlas", "AML.T0057"): (
        "Partial coverage via LLM02 (sensitive data in prompt / I/O); ATLAS "
        "framing focuses on exfiltration via inference, which needs runtime "
        "monitoring."
    ),

    # CWE — generic AppSec items (CWE-22 path traversal, CWE-295 cert
    # validation, CWE-522 credential transit) are no longer in the
    # CWE_UNIVERSE list above — they're out of scope by design.
    # Anything still listed below is genuinely gapped within
    # AgentShield's domain and explains why.
    # CWE-918 now mapped onto AST03 (manifest unrestricted network) +
    # D-LLM01-005 (agent comm poisoning). LLM-derived URLs reaching an
    # unrestricted egress channel is the agent-side SSRF surface;
    # runtime probe validates the request actually leaves the network.

    # OWASP Agentic Skills Top 10 — only AST10 remains out of scope.
    # AST02 / AST06 / AST08 / AST09 all now have rules + (where
    # applicable) Path B probes attached.
    ("ast", "AST10"): (
        "Behaviour drift needs persistent baselines and version-to-"
        "version comparison. A single scan / probe run can't observe "
        "drift by definition. Genuinely out of scope for AgentShield's "
        "one-shot model — handled by continuous-monitoring tools."
    ),
}


def gap_reason(framework_key: str, item_id: str) -> str:
    """Tooltip text for a 'not scanned' chip in the Coverage Matrix.

    Returns a specific reason when one is curated, or a generic fallback
    otherwise. Always returns a non-empty string so the UI can drop it
    straight into a title attribute.
    """
    specific = COVERAGE_GAP_REASONS.get((framework_key, item_id))
    if specific:
        return specific
    return (
        f"{item_id} is in the curated framework universe but no rule in the "
        "bundled pack covers it yet."
    )


# ---------- scanner-coverage computation ----------

def compute_scanner_coverage(refs: Iterable) -> dict[str, set[str]]:
    """Return the set of framework IDs each rule in the bundled pack
    *can* fire on, keyed by framework. Used to distinguish "scanned but
    clean" from "not scanned at all" in the Coverage Matrix.

    Iterates `RuleReference` objects from
    `agentshield.merger.reference.build_all_references(...)` — typed
    loosely here as `Iterable` to avoid a circular import.
    """
    coverage: dict[str, set[str]] = {k: set() for k in FRAMEWORK_UNIVERSES}
    for ref in refs:
        for key in coverage:
            for item in ref.frameworks.get(key, []) or []:
                coverage[key].add(str(item))
    return coverage
