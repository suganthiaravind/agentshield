"""Build the data behind the "Reference" tab — F.26.

Aggregates every check the scanner can produce, from three sources:

  1. Tier 1 Semgrep rules     — read from `agentshield/rules/**/*.yaml`
  2. Tier 2 Copilot checklist — parsed from the bundled
                                `tier2_checklist.md.tmpl`
  3. AST10 manifest scanner   — registered in
                                `agentshield/manifest_scanner/rules.py`

Output is a flat `list[RuleReference]` the HTML renderer turns into
cards. No I/O outside the package; no network. Designed so that the
reference panel is always in sync with the actual rule pack — adding
or removing a rule automatically updates the documentation surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RuleReference:
    """One row in the Reference tab. Source-agnostic shape so the renderer
    can group/filter without caring about provenance."""

    source: str  # "Semgrep" | "Copilot" | "Markdown"
    rule_id: str  # short id: file slug or AS-C-* identifier
    agentshield_id: str  # current canonical id, AS-<source>-<DDR>-<anchor>-<seq>
    title: str
    category: str  # detect / defend / respond
    severity: str  # critical / high / medium / low / info
    languages: str  # "python", "java", "any", or a join
    description: str  # one-paragraph "what it flags"
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    skip_if: str | None = None  # what makes the rule NOT fire (Tier 2 only)
    remediation: str | None = None
    section: str | None = None  # Tier 2 sub-section ("§1 OWASP LLM Top 10")
    legacy_ids: list[str] = field(default_factory=list)  # F.27 — pre-rename IDs


# ---------- Tier 1 (Semgrep) ----------


def _shorten_tier1_id(canonical: str) -> str:
    """`agentshield.detect.unsanitized-user-input-to-llm` → `unsanitized-user-input-to-llm`."""
    return canonical.rsplit(".", 1)[-1]


def load_tier1_references(rules_path: Path) -> list[RuleReference]:
    """Read every YAML under `rules_path` and emit one RuleReference per
    rule. Java + Python siblings get one entry each — they share an
    AgentShield ID (e.g. AS-D-001) but their language fields differ.
    """
    refs: list[RuleReference] = []
    for yaml_path in sorted(rules_path.rglob("*.yaml")):
        try:
            data = yaml.safe_load(yaml_path.read_text()) or {}
        except yaml.YAMLError:
            continue
        for rule in data.get("rules") or []:
            metadata = rule.get("metadata") or {}
            category = metadata.get("category")
            if category not in {"detect", "defend", "respond"}:
                continue
            canonical = rule.get("id") or ""
            short = _shorten_tier1_id(canonical)
            languages = rule.get("languages") or []
            lang_str = ", ".join(languages) if languages else "any"
            title = _humanize_rule_id(short)
            # Path B+: keep titles symmetric across language variants.
            # Java rules already inherit a "Java" suffix from their
            # rule_id (e.g. `hardcoded-llm-credentials-java`); Python
            # rules don't, which made the Reference tab read
            # asymmetrically. Append the language suffix when missing
            # so siblings line up: "Hardcoded LLM Credentials Python"
            # next to "Hardcoded LLM Credentials Java".
            if (
                languages
                and len(languages) == 1
                and not title.endswith(("Python", "Java"))
            ):
                lang_suffix = languages[0].title()  # python → Python
                title = f"{title} {lang_suffix}"
            refs.append(
                RuleReference(
                    source="Semgrep",
                    rule_id=short,
                    agentshield_id=metadata.get("agentshield_id") or short,
                    title=title,
                    category=category,
                    severity=metadata.get("severity_normalized") or "medium",
                    languages=lang_str,
                    description=_squash_whitespace(rule.get("message") or ""),
                    frameworks=_normalize_framework_mappings(
                        metadata.get("framework_mappings") or {}
                    ),
                    remediation=_squash_whitespace(metadata.get("remediation") or "")
                    or None,
                    legacy_ids=list(metadata.get("legacy_ids") or []),
                )
            )
    refs.sort(key=lambda r: (r.agentshield_id, r.languages))
    return refs


def _humanize_rule_id(short_id: str) -> str:
    """`unsanitized-user-input-to-llm` → `Unsanitized user input to LLM`."""
    parts = short_id.split("-")
    capitalised = " ".join(p[:1].upper() + p[1:] for p in parts if p)
    # restore a few common acronyms
    for term, fix in (
        (" Llm", " LLM"),
        (" Https", " HTTPS"),
        (" Http", " HTTP"),
        (" Cwe", " CWE"),
        (" Sqli", " SQLi"),
    ):
        capitalised = capitalised.replace(term, fix)
    return capitalised


def _normalize_framework_mappings(fm: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for key in ("owasp_llm", "owasp_agentic", "mitre_atlas", "cwe", "ast"):
        vals = fm.get(key) or []
        if vals:
            out[key] = [str(v) for v in vals]
    return out


def _squash_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


# ---------- Tier 2 (Copilot checklist) ----------

# Parse `### TIER2-X-Y — Title` headers and the structured bullet list
# below them. The checklist is hand-edited markdown; keep the parser
# tolerant — skip any chunk that doesn't have at least a Severity bullet.

_T2_HEADER = re.compile(r"^### (AS-C-[A-Z0-9_-]+|TIER2-[A-Z0-9-]+)\s+[—-]\s+(.+)$", re.MULTILINE)
_T2_BULLET = re.compile(
    r"^-\s+\*\*(?P<key>[^*]+):\*\*\s+(?P<value>.+(?:\n[^-#].+)*)",
    re.MULTILINE,
)
_T2_SECTION = re.compile(r"^# §\d+\.\s+(.+)$", re.MULTILINE)


def parse_tier2_checklist(checklist_text: str) -> list[RuleReference]:
    """Parse TIER2-X-Y entries out of the bundled checklist template."""
    refs: list[RuleReference] = []

    # Build a cursor → section title map so each entry knows which §
    # it lives under (purely cosmetic, used for grouping).
    section_starts: list[tuple[int, str]] = [
        (m.start(), m.group(1)) for m in _T2_SECTION.finditer(checklist_text)
    ]

    def section_for(pos: int) -> str | None:
        out: str | None = None
        for start, title in section_starts:
            if start <= pos:
                out = title
            else:
                break
        return out

    headers = list(_T2_HEADER.finditer(checklist_text))
    for i, m in enumerate(headers):
        rule_id = m.group(1)
        title = m.group(2).strip()
        body_start = m.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(checklist_text)
        body = checklist_text[body_start:body_end]

        bullets = _parse_t2_bullets(body)
        severity = (bullets.get("Severity") or "medium").strip().lower()
        languages = (bullets.get("Languages") or "any").strip()
        frameworks = _parse_t2_frameworks(bullets.get("Frameworks") or "")
        look_for = _squash_whitespace(bullets.get("Look for") or "")
        skip_if = _squash_whitespace(bullets.get("Skip if") or "") or None
        remediation = _squash_whitespace(bullets.get("Remediation") or "") or None
        # F.27: prefer the explicit Category bullet (added during the
        # rename); fall back to the rule-id heuristic for legacy headers.
        explicit_category = (bullets.get("Category") or "").strip().lower()
        if explicit_category in {"detect", "defend", "respond"}:
            category = explicit_category
        else:
            category = _category_from_tier2_id(rule_id)
        # F.27: pull out the explicit Legacy ID bullet so the Reference
        # tab can show it as a faint caption.
        legacy = (bullets.get("Legacy ID") or "").strip()
        legacy_ids = [legacy] if legacy else []

        if not look_for:
            continue  # malformed entry — skip rather than emit a blank card

        refs.append(
            RuleReference(
                source="Copilot",
                rule_id=rule_id,
                agentshield_id=rule_id,
                title=title,
                category=category,
                severity=severity,
                languages=languages,
                description=look_for,
                frameworks=frameworks,
                skip_if=skip_if,
                remediation=remediation,
                section=section_for(m.start()),
                legacy_ids=legacy_ids,
            )
        )
    return refs


def _parse_t2_bullets(body: str) -> dict[str, str]:
    """Pull the labelled bullets (`- **Key:** value`) out of a Tier 2 entry."""
    out: dict[str, str] = {}
    for m in _T2_BULLET.finditer(body):
        key = m.group("key").strip()
        # multi-line values: collapse continuations, strip indented junk
        raw = m.group("value")
        cleaned = " ".join(line.strip() for line in raw.splitlines())
        out[key] = cleaned.strip()
    return out


def _parse_t2_frameworks(s: str) -> dict[str, list[str]]:
    """`owasp_llm=[LLM01], owasp_agentic=[T6], cwe=[CWE-94]` → dict."""
    out: dict[str, list[str]] = {}
    if not s:
        return out
    for m in re.finditer(r"(\w+)\s*=\s*\[([^\]]*)\]", s):
        key = m.group(1)
        items = [v.strip() for v in m.group(2).split(",") if v.strip()]
        if items:
            out[key] = items
    return out


def _category_from_tier2_id(rule_id: str) -> str:
    """Map TIER2-LLM01-* / TIER2-AGENTIC-T1-* / TIER2-LLM06-* → D/D/R buckets.

    Heuristic: LLM01/04/05/07/08/09 + Agentic T1/T5/T6/T11 are detect-class
    surfaces; LLM06 is defend-class (controls); LLM02/10 + Agentic T8/T10
    are respond-class (egress / observability). The exact assignment lives
    on each entry's `category` line in the checklist, but we don't have
    that bullet here — fall back to a deterministic mapping by rule-id
    prefix that mirrors the existing taxonomy.
    """
    rid = rule_id.upper()
    if "LLM06" in rid or "AGENTIC-T2" in rid or "AGENTIC-T9" in rid or "AGENTIC-T4" in rid:
        return "defend"
    if "LLM02" in rid or "LLM10" in rid or "AGENTIC-T8" in rid or "AGENTIC-T10" in rid or "GAP" in rid:
        return "respond"
    return "detect"


# ---------- AST10 (manifest scanner) ----------


def load_manifest_scanner_references() -> list[RuleReference]:
    """Pull in the AST10 rule descriptions registered in the manifest
    scanner module. The registry lives next to the rule code so adding a
    rule there automatically registers it here."""
    # Imported lazily so the merger doesn't require manifest_scanner at
    # module-load time (keeps the test surface small).
    from agentshield.manifest_scanner.rules import RULE_DESCRIPTIONS

    refs: list[RuleReference] = []
    for entry in RULE_DESCRIPTIONS:
        refs.append(
            RuleReference(
                source="Markdown",
                rule_id=entry["rule_id"],
                agentshield_id=entry["agentshield_id"],
                title=entry["title"],
                category=entry.get("category", "detect"),
                severity=entry["severity"],
                languages="markdown",
                description=entry["description"],
                frameworks=entry.get("frameworks", {}),
                remediation=entry.get("remediation"),
                legacy_ids=list(entry.get("legacy_ids") or []),
            )
        )
    return refs


# ---------- public entry point ----------


def build_all_references(
    *,
    tier1_rules_path: Path,
    tier2_checklist_path: Path,
) -> list[RuleReference]:
    """Aggregate Tier 1 + Tier 2 + Manifest references in one list."""
    refs: list[RuleReference] = []
    refs.extend(load_tier1_references(tier1_rules_path))
    if tier2_checklist_path.exists():
        refs.extend(parse_tier2_checklist(tier2_checklist_path.read_text(encoding="utf-8")))
    refs.extend(load_manifest_scanner_references())
    return refs


# ---------- Fix-skill renderer (F.34) ----------
#
# Emits one OWASP-Universal-Skill-Format SKILL.md per source so that an
# LLM coding assistant (Claude Code / Copilot Chat) loaded with the skill
# can interpret and remediate AgentShield findings of that source. The
# body content is generated directly from the same RuleReference data
# that powers the Reference tab — so the skills stay in sync with the
# rule pack as long as the build script is re-run after rule changes
# (test_skills.py asserts no drift).

# Per-source frontmatter metadata. The `description` is the LLM-discovery
# hint — it must enumerate the trigger phrases / patterns that should
# load the skill. Vague descriptions never trigger.
_FIX_SKILL_META = {
    "Semgrep": {
        "name": "agentshield-semgrep-fixes",
        "title": "AgentShield Semgrep (Tier 1) Remediation Skill",
        "id_prefix": "AS-S-",
        "blurb": (
            "Help developers fix AgentShield Tier 1 (Semgrep) findings — "
            "high-precision Python/Java AST + taint matches with rule IDs "
            "starting `AS-S-`."
        ),
        "triggers": [
            "the user pastes a finding ID starting with `AS-S-` "
            "(e.g. `AS-S-D-LLM01-001`) into chat",
            "the user asks how to fix an AgentShield Semgrep finding",
            "the user pastes a SARIF result with `ruleId` starting "
            "`agentshield.detect.*` / `agentshield.defend.*`",
            "the user references a legacy AgentShield Tier 1 ID like "
            "`AS-D-001` / `AS-DF-003` (those are aliased to current IDs)",
        ],
    },
    "Copilot": {
        "name": "agentshield-copilot-fixes",
        "title": "AgentShield Copilot (Tier 2) Remediation Skill",
        "id_prefix": "AS-C-",
        "blurb": (
            "Help developers fix AgentShield Tier 2 (Copilot LLM-as-"
            "scanner) findings — semantic / cross-function checks with "
            "rule IDs starting `AS-C-`."
        ),
        "triggers": [
            "the user pastes a finding ID starting with `AS-C-` "
            "(e.g. `AS-C-DF-LLM06-004`) into chat",
            "the user asks how to fix an AgentShield Copilot finding",
            "the user references a legacy `TIER2-LLM..-..` / "
            "`TIER2-AGENTIC-T..-..` / `TIER2-CWE-..-..` ID — they alias "
            "to current `AS-C-*` IDs",
            "the user has just run `agentshield merge` and asks about "
            "Tier 2 entries in the report",
        ],
    },
    "Markdown": {
        "name": "agentshield-manifest-fixes",
        "title": "AgentShield AST10 Agent-Markdown Remediation Skill",
        "id_prefix": "AS-M-",
        "blurb": (
            "Help developers fix AgentShield AST10 findings on agent-"
            "loaded markdown files (SKILL.md, AGENT.md, AGENTS.md, "
            "INSTRUCTION(S).md, PROMPT(S).md, CLAUDE.md) — rule IDs "
            "start with `AS-M-`. Maps to OWASP Agentic Skills Top 10 "
            "(AST10)."
        ),
        "triggers": [
            "the user pastes a finding ID starting with `AS-M-` "
            "(e.g. `AS-M-D-AST03-001`) into chat",
            "the user asks how to fix an AgentShield finding on a "
            "SKILL.md / AGENT.md / CLAUDE.md / instructions file",
            "the user references an AST10 risk (`AST01` … `AST07`) on a "
            "skill / agent / prompt markdown they're building or auditing",
            "the user references a legacy `AS-AST-NNN` ID — those alias "
            "to current `AS-M-*` IDs",
        ],
    },
}


def render_fix_skill(source: str, refs: list[RuleReference]) -> str:
    """Render the SKILL.md content for one source's fix skill.

    Pulls every rule for `source` from `refs`, sorts by category +
    agentshield_id for stability, and emits OWASP-UF YAML frontmatter +
    a per-rule remediation body.
    """
    if source not in _FIX_SKILL_META:
        raise ValueError(f"unknown source: {source!r}")
    meta = _FIX_SKILL_META[source]

    src_refs = [r for r in refs if r.source == source]
    src_refs.sort(key=lambda r: (r.category, r.agentshield_id))

    cat_order = ("detect", "defend", "respond")

    lines: list[str] = []

    # ----- frontmatter -----
    lines.append("---")
    lines.append(f"name: {meta['name']}")
    lines.append("description: |")
    # The description is critical for LLM discovery. List trigger
    # patterns explicitly — vague descriptions never trigger.
    lines.append(f"  {meta['blurb']}")
    lines.append("")
    lines.append("  Use this skill when:")
    for t in meta["triggers"]:
        lines.append(f"    - {t}")
    lines.append("author:")
    lines.append("  name: AgentShield")
    lines.append("  identity: did:web:github.com/suganthiaravind/agentshield")
    # OWASP-UF permission shape (from research/owasp-ast10/README.md).
    # Read-only skill: no network, no shell, no file writes.
    lines.append("permissions:")
    lines.append('  network:')
    lines.append('    allow: []')
    lines.append("  shell: false")
    lines.append("  files:")
    lines.append("    read: []")
    lines.append("    write: []")
    lines.append("    deny_write:")
    lines.append("      - SOUL.md")
    lines.append("      - MEMORY.md")
    lines.append("      - AGENTS.md")
    lines.append("risk_tier: L0")
    lines.append("---")
    lines.append("")

    # ----- body -----
    lines.append(f"# {meta['title']}")
    lines.append("")
    lines.append(meta["blurb"])
    lines.append("")
    lines.append(
        f"When a user pastes an `{meta['id_prefix']}…` finding ID or "
        "asks about one of the rules below, walk them through the "
        "remediation. Cite the canonical rule ID and the framework "
        "mappings; if the user pasted a legacy ID, mention it once and "
        "carry on with the current ID."
    )
    lines.append("")
    lines.append(f"Total rules in this skill: **{len(src_refs)}**")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not src_refs:
        lines.append(f"_No rules currently registered for source `{source}`._")
        return "\n".join(lines) + "\n"

    # Group by D/D/R for readability.
    for cat in cat_order:
        bucket = [r for r in src_refs if r.category == cat]
        if not bucket:
            continue
        emoji_label, _sub, _desc, _q = {
            "detect": ("🔴 Detect", "", "", ""),
            "defend": ("🟡 Defend", "", "", ""),
            "respond": ("🔵 Respond", "", "", ""),
        }[cat]
        lines.append(f"## {emoji_label} ({len(bucket)})")
        lines.append("")
        for ref in bucket:
            lines.extend(_render_fix_skill_rule(ref))
            lines.append("")
        lines.append("---")
        lines.append("")

    # Footer pointing back at AgentShield itself.
    lines.append("## Related")
    lines.append("")
    lines.append(
        "- AgentShield repo: https://github.com/suganthiaravind/agentshield"
    )
    lines.append(
        "- For the live, full rule list across all three sources, run "
        "`agentshield merge --output-html report.html` and open the "
        "**Reference tab** of the generated report."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def _render_fix_skill_rule(ref: RuleReference) -> list[str]:
    """One block per rule. Severity, lang, framework chips, what it
    flags, and the remediation guidance (the user's actionable bit)."""
    chips = []
    for k, items in ref.frameworks.items():
        label = {
            "owasp_llm": "OWASP LLM",
            "owasp_agentic": "OWASP Agentic",
            "mitre_atlas": "MITRE ATLAS",
            "cwe": "CWE",
            "ast": "AST10",
        }.get(k, k)
        for v in items:
            chips.append(f"`{label} {v}`")

    out: list[str] = []
    out.append(f"### `{ref.agentshield_id}` — {ref.title}")
    out.append("")
    meta_bits = [f"**Severity:** {ref.severity}"]
    if ref.languages:
        meta_bits.append(f"**Languages:** {ref.languages}")
    if ref.legacy_ids:
        meta_bits.append(f"**Legacy ID:** `{', '.join(ref.legacy_ids)}`")
    out.append(" · ".join(meta_bits))
    if chips:
        out.append("")
        out.append("**Frameworks:** " + " ".join(chips))
    out.append("")
    out.append(f"**What it flags:** {ref.description}")
    if ref.skip_if:
        out.append("")
        out.append(f"**Skip if:** {ref.skip_if}")
    if ref.remediation:
        out.append("")
        out.append(f"**Remediation:** {ref.remediation}")
    return out
