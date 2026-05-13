"""The 5 AST10 manifest-scanner rules — F.24.

Each rule is a pure function from a ParsedManifest → list[Finding]. The
scanner module composes them in a fixed order and returns the union.

| Rule ID prefix | AST | What it checks                                  |
|----------------|------|------------------------------------------------|
| AS-M-D-AST01-* | AST01 | Concealment / jailbreak markers in body prose  |
| AS-M-D-AST03-* | AST03 | Over-broad permissions in frontmatter          |
| AS-M-D-AST04-* | AST04 | Insecure metadata (missing description / DID)  |
| AS-M-D-AST05-* | AST05 | Unsafe deserialization in body code blocks     |
| AS-M-D-AST07-* | AST07 | Update-drift: missing signature / content_hash |

(Legacy `AS-AST-NNN` IDs are preserved on each Finding's `legacy_ids`
so customer suppress-comments / SARIF integrations from the v1 scheme
continue to work.)

Severity levels follow AgentShield's existing ladder. AST04 / AST07 are
flagged at low/info because they describe hygiene gaps that may not be
actively exploitable, while AST01 / AST05 default to high.
"""

from __future__ import annotations

import re
from typing import Any

from agentshield.manifest_scanner.parser import ParsedManifest
from agentshield.normalize.schema import (
    CodeLocation,
    Finding,
    FrameworkMappings,
)

# F.27 single source of truth for AST10 rule IDs.
# Each `rule_short` (the slug emitted as `rule_id_short` on findings) maps
# to (current_agentshield_id, [legacy_ids]). The new IDs follow the
# uniform `AS-<source>-<DDR>-<anchor>-<seq>` convention; legacy IDs are
# preserved so customer suppress-comments and dashboards from the v1
# AST scheme keep working.
_RULE_IDS: dict[str, tuple[str, list[str]]] = {
    "ast01-malicious-skill-marker":  ("AS-M-D-AST01-001", ["AS-AST-001"]),
    "ast03-network-unrestricted":    ("AS-M-D-AST03-001", ["AS-AST-003"]),
    "ast03-network-wildcard-allow":  ("AS-M-D-AST03-002", ["AS-AST-003"]),
    "ast03-shell-access":            ("AS-M-D-AST03-003", ["AS-AST-003"]),
    "ast03-wildcard-file-read":      ("AS-M-D-AST03-004", ["AS-AST-003"]),
    "ast03-wildcard-file-write":     ("AS-M-D-AST03-005", ["AS-AST-003"]),
    "ast03-identity-file-write":     ("AS-M-D-AST03-006", ["AS-AST-003"]),
    "ast04-missing-description":     ("AS-M-D-AST04-001", ["AS-AST-004"]),
    "ast04-missing-author-identity": ("AS-M-D-AST04-002", ["AS-AST-004"]),
    "ast05-unsafe-deserialization":  ("AS-M-D-AST05-001", ["AS-AST-005"]),
    "ast07-missing-signature":       ("AS-M-D-AST07-001", ["AS-AST-007"]),
    "ast07-missing-content-hash":    ("AS-M-D-AST07-002", ["AS-AST-007"]),
}

# --- AST01 markers (re-uses D009 / D010 vocabulary applied to .md body) ---

_AST01_PATTERNS = [
    # Concealment (D009 family).
    re.compile(
        r"(?i)\bdo\s+not\s+(tell|inform|mention|notify)\s+(the\s+)?user"
    ),
    re.compile(r"(?i)\bdon[’']t\s+(tell|inform|mention)\s+(the\s+)?user"),
    re.compile(r"(?i)\bhide\s+(this|that|the)\s+(action|operation|step|fact)"),
    re.compile(r"(?i)\bkeep\s+(this|that|it)\s+(secret|hidden)"),
    re.compile(
        r"(?i)\bdon[’']t\s+mention\s+you\s+(used|called)\s+"
        r"(this\s+)?(tool|skill|function)"
    ),
    # Jailbreak / mode-switch (D010 family).
    re.compile(
        r"(?i)\byou\s+are\s+now\s+in\s+"
        r"(unrestricted|debug|developer|admin|god|jailbreak|dan)\s+mode"
    ),
    re.compile(
        r"(?i)\bdisable\s+(all\s+)?(safety|security|content|ethical)\s+"
        r"(filters|checks|guidelines|guardrails)"
    ),
    re.compile(
        r"(?i)\bignore\s+(all\s+)?(previous|prior|earlier)\s+"
        r"(instructions|rules|prompts|guidelines)"
    ),
    re.compile(r"(?i)\bbypass\s+(content|usage|safety)\s+polic(y|ies)"),
]


def check_ast01_body_markers(manifest: ParsedManifest) -> list[Finding]:
    """AST01 — malicious-skill markers in the SKILL.md prose body.

    Skills are distributed as text; a malicious skill's primary attack
    surface is concealment / jailbreak / exfil instructions in its prose
    that the LLM treats as authoritative. Flag any line in the body that
    matches the same vocabulary D009/D010 catch in source code.
    """
    findings: list[Finding] = []
    for body_lineno, line in enumerate(manifest.body.splitlines(), start=1):
        for pat in _AST01_PATTERNS:
            if pat.search(line):
                abs_line = manifest.body_offset + body_lineno - 1
                findings.append(
                    _build_finding(
                        rule_short="ast01-malicious-skill-marker",
                        path=manifest.path,
                        line=abs_line,
                        snippet=line.strip()[:200],
                        message=(
                            "SKILL.md body contains a concealment / jailbreak / "
                            "exfil marker that the host LLM may treat as "
                            "authoritative instruction. AST01 (Malicious Skills) "
                            "— this is the same prose-injection surface "
                            "documented in the ClawHavoc / ToxicSkills 2026 "
                            "campaigns."
                        ),
                        severity="high",
                        ast_id="AST01",
                        owasp_llm=["LLM01", "LLM03"],
                    )
                )
                break  # one finding per line; don't double-fire on multi-marker lines
    return findings


# --- AST03 — over-broad permissions in frontmatter ---

# Identity files that AST03 says require explicit deny_write — skills
# that try to write to these are persistence vectors (SOUL.md is an
# identity file; MEMORY.md and AGENTS.md are referenced in the AST10 spec).
_PROTECTED_IDENTITY_FILES = {"SOUL.md", "MEMORY.md", "AGENTS.md"}

# Wildcard read paths that grant the skill broad filesystem access. The
# AST10 Universal Skill Format requires explicit paths, no wildcards.
_WILDCARD_PATTERN = re.compile(r"(?:^|[/\\])(?:\*\*|\*)")


def check_ast03_overprivileged(manifest: ParsedManifest) -> list[Finding]:
    """AST03 — over-broad permissions declared in YAML frontmatter."""
    findings: list[Finding] = []
    perms = manifest.frontmatter.get("permissions")
    if not isinstance(perms, dict):
        return findings

    fm_line = 1  # all frontmatter findings point at the file head; refining
    # to per-key line numbers would require a YAML round-trip parser.

    # network: true (no allowlist).
    network = perms.get("network")
    if network is True:
        findings.append(
            _build_finding(
                rule_short="ast03-network-unrestricted",
                path=manifest.path,
                line=fm_line,
                snippet="permissions.network: true",
                message=(
                    "Skill declares unrestricted network egress "
                    "(`network: true`). AST03 — should be a domain "
                    "allowlist (`network.allow: [api.example.com]`) with "
                    "default-deny."
                ),
                severity="high",
                ast_id="AST03",
                owasp_llm=["LLM03", "LLM06"],
                owasp_agentic=["T2", "T3"],
                cwe=["CWE-732"],
            )
        )
    elif isinstance(network, dict):
        # network.allow: ["*"] is just network: true with extra steps.
        allow = network.get("allow")
        if isinstance(allow, list) and any(a == "*" for a in allow):
            findings.append(
                _build_finding(
                    rule_short="ast03-network-wildcard-allow",
                    path=manifest.path,
                    line=fm_line,
                    snippet='permissions.network.allow: ["*"]',
                    message=(
                        "Skill's network allowlist contains `*` — equivalent "
                        "to unrestricted egress. AST03 — list explicit hosts."
                    ),
                    severity="high",
                    ast_id="AST03",
                    owasp_llm=["LLM03", "LLM06"],
                    owasp_agentic=["T2", "T3"],
                    cwe=["CWE-732"],
                )
            )

    # shell: true.
    if perms.get("shell") is True:
        findings.append(
            _build_finding(
                rule_short="ast03-shell-access",
                path=manifest.path,
                line=fm_line,
                snippet="permissions.shell: true",
                message=(
                    "Skill declares shell access (`shell: true`). AST03 — "
                    "should only be granted when the skill's core function "
                    "requires it; document why in the description."
                ),
                severity="medium",
                ast_id="AST03",
                owasp_llm=["LLM06"],
                owasp_agentic=["T2"],
                cwe=["CWE-78"],
            )
        )

    # files.read with wildcards.
    files = perms.get("files")
    if isinstance(files, dict):
        for key in ("read", "write"):
            paths = files.get(key)
            if isinstance(paths, list):
                for p in paths:
                    if isinstance(p, str) and _WILDCARD_PATTERN.search(p):
                        findings.append(
                            _build_finding(
                                rule_short=f"ast03-wildcard-file-{key}",
                                path=manifest.path,
                                line=fm_line,
                                snippet=f"permissions.files.{key}: {p}",
                                message=(
                                    f"Wildcard {key} permission on `{p}`. "
                                    f"AST03 — skill manifests must declare "
                                    f"explicit paths; wildcards defeat "
                                    f"least-privilege review."
                                ),
                                severity="medium",
                                ast_id="AST03",
                                cwe=["CWE-732"],
                            )
                        )

        # files.write to identity files without explicit deny_write.
        write_paths = files.get("write") or []
        deny_write = files.get("deny_write") or []
        if isinstance(write_paths, list) and isinstance(deny_write, list):
            denied = {str(p).strip() for p in deny_write}
            for p in write_paths:
                if not isinstance(p, str):
                    continue
                base = p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
                if base in _PROTECTED_IDENTITY_FILES and base not in denied:
                    findings.append(
                        _build_finding(
                            rule_short="ast03-identity-file-write",
                            path=manifest.path,
                            line=fm_line,
                            snippet=f"permissions.files.write: {p}",
                            message=(
                                f"Skill requests write access to identity "
                                f"file `{base}` without an explicit "
                                f"`deny_write`. AST03 — `SOUL.md`, "
                                f"`MEMORY.md`, and `AGENTS.md` survive "
                                f"skill uninstall and persist attacker "
                                f"instructions across sessions."
                            ),
                            severity="critical",
                            ast_id="AST03",
                            owasp_llm=["LLM04"],
                            owasp_agentic=["T1"],
                            cwe=["CWE-732"],
                        )
                    )
    return findings


# --- AST04 — insecure / missing metadata ---


def check_ast04_metadata(manifest: ParsedManifest) -> list[Finding]:
    """AST04 — missing or empty metadata that hampers auditability."""
    findings: list[Finding] = []
    fm = manifest.frontmatter

    # Empty / missing description (skill becomes hard to audit).
    desc = fm.get("description")
    if not (isinstance(desc, str) and desc.strip()):
        findings.append(
            _build_finding(
                rule_short="ast04-missing-description",
                path=manifest.path,
                line=1,
                snippet="description: <missing or empty>",
                message=(
                    "SKILL.md is missing a non-empty `description` field. "
                    "AST04 — without a description the host LLM cannot "
                    "decide when to trigger the skill; reviewers cannot "
                    "verify intent. Honest-metadata is a precondition for "
                    "least-privilege review."
                ),
                severity="low",
                ast_id="AST04",
            )
        )

    # Missing author identity (DID / signing key).
    author = fm.get("author")
    has_identity = (
        isinstance(author, dict) and bool(str(author.get("identity") or "").strip())
    )
    if not has_identity and (fm.get("name") or fm.get("description")):
        findings.append(
            _build_finding(
                rule_short="ast04-missing-author-identity",
                path=manifest.path,
                line=1,
                snippet="author.identity: <missing>",
                message=(
                    "Skill manifest has no `author.identity` (DID / signing-"
                    "key anchor). AST04 — without a verifiable identity "
                    "anchor, registry consumers cannot detect impersonation "
                    "or typosquats; this is the foothold the ClawHub fake-"
                    "Google skill exploited."
                ),
                severity="info",
                ast_id="AST04",
            )
        )
    return findings


# --- AST05 — unsafe deserialization in body code blocks ---

# Match `yaml.load(`, `pickle.loads(`, `eval(`, `exec(` inside fenced
# code blocks. Single-line scan is sufficient for the common case;
# multi-line eval / exec args will still match the function-call line.
_AST05_PATTERNS = [
    (
        re.compile(r"\byaml\.load\s*\(\s*(?!.*Loader\s*=\s*yaml\.SafeLoader)"),
        "yaml.load() without SafeLoader — arbitrary tag deserialization",
    ),
    (
        re.compile(r"\bpickle\.loads?\s*\("),
        "pickle.load(s)() — arbitrary code execution on attacker-controlled bytes",
    ),
    (
        re.compile(r"(?<![\w.])eval\s*\("),
        "eval() in a skill script — arbitrary code execution primitive",
    ),
    (
        re.compile(r"(?<![\w.])exec\s*\("),
        "exec() in a skill script — arbitrary code execution primitive",
    ),
]


def check_ast05_unsafe_deserialization(manifest: ParsedManifest) -> list[Finding]:
    """AST05 — unsafe deserialization patterns inside the body's code blocks.

    Only fires inside fenced code blocks (``` ... ```) — prose that
    *describes* `eval` for educational purposes shouldn't trip the rule.
    """
    findings: list[Finding] = []
    in_code_block = False
    for body_lineno, line in enumerate(manifest.body.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if not in_code_block:
            continue
        for pat, why in _AST05_PATTERNS:
            if pat.search(line):
                abs_line = manifest.body_offset + body_lineno - 1
                findings.append(
                    _build_finding(
                        rule_short="ast05-unsafe-deserialization",
                        path=manifest.path,
                        line=abs_line,
                        snippet=stripped[:200],
                        message=(
                            f"AST05 — {why}. SKILL.md scripts run with the "
                            f"agent's full host permissions; an unsafe "
                            f"deserializer turns any attacker-controlled "
                            f"input (including LLM output) into an RCE "
                            f"primitive."
                        ),
                        severity="high",
                        ast_id="AST05",
                        owasp_llm=["LLM05"],
                        owasp_agentic=["T11"],
                        cwe=["CWE-94", "CWE-502"],
                    )
                )
                break  # one finding per line
    return findings


# --- AST07 — update drift: missing signature / content_hash ---


def check_ast07_update_drift(manifest: ParsedManifest) -> list[Finding]:
    """AST07 — manifest lacks the integrity fields required for safe update.

    Surfaces at info severity. The OWASP Universal Skill Format proposes
    `signature:` and `content_hash:` fields to enable Merkle-root
    verification at install/update time. Many real SKILL.md files in the
    wild don't yet implement that format — flagging these as info (not
    high) treats them as a hygiene gap, not a vulnerability.
    """
    findings: list[Finding] = []
    fm = manifest.frontmatter
    if not fm:
        # Body-only file — no frontmatter at all means there's nothing to
        # verify. Skip; AST04 already flagged the missing-metadata case.
        return findings

    sig = str(fm.get("signature") or "").strip()
    content_hash = str(fm.get("content_hash") or "").strip()

    if not sig:
        findings.append(
            _build_finding(
                rule_short="ast07-missing-signature",
                path=manifest.path,
                line=1,
                snippet="signature: <missing>",
                message=(
                    "SKILL.md frontmatter has no `signature` field. AST07 — "
                    "without an ed25519 signature the registry cannot verify "
                    "the skill on update; ClawJacked-style update-drift "
                    "attacks become viable."
                ),
                severity="info",
                ast_id="AST07",
                owasp_llm=["LLM03"],
                cwe=["CWE-345"],
            )
        )
    if not content_hash:
        findings.append(
            _build_finding(
                rule_short="ast07-missing-content-hash",
                path=manifest.path,
                line=1,
                snippet="content_hash: <missing>",
                message=(
                    "SKILL.md frontmatter has no `content_hash` field. "
                    "AST07 — Merkle-root verification at install time "
                    "requires a SHA-256 over the canonical skill payload."
                ),
                severity="info",
                ast_id="AST07",
                cwe=["CWE-345"],
            )
        )
    return findings


# --- helper -------------------------------------------------------------


def _remediation_for(rule_short: str) -> str | None:
    """Look up the curated fix guidance for `rule_short` in
    `RULE_DESCRIPTIONS` — the same table the Reference tab renders from.
    Single source of truth for fix text; returns None if the rule isn't
    in the table or has no remediation field. Linear scan is fine — the
    table is ~10 entries and only walked on a finding."""
    for entry in RULE_DESCRIPTIONS:
        if entry.get("rule_id") == rule_short:
            text = entry.get("remediation")
            if isinstance(text, str) and text.strip():
                return text.strip()
            return None
    return None


def _build_finding(
    *,
    rule_short: str,
    path: Any,
    line: int,
    snippet: str,
    message: str,
    severity: str,
    ast_id: str,
    owasp_llm: list[str] | None = None,
    owasp_agentic: list[str] | None = None,
    cwe: list[str] | None = None,
) -> Finding:
    """Build a Finding in the canonical shape the rest of the pipeline
    expects, with the AST mapping populated. The current/legacy IDs come
    from the central `_RULE_IDS` table — keep that table the single source
    of truth for rule identity."""
    agentshield_id, legacy_ids = _RULE_IDS.get(rule_short, (rule_short, []))
    return Finding(
        rule_id=f"agentshield.detect.{rule_short}",
        rule_id_short=rule_short,
        agentshield_id=agentshield_id,
        legacy_ids=list(legacy_ids),
        category="detect",
        tier="framework",
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        location=CodeLocation(
            file_path=str(path),
            start_line=line,
            snippet=snippet,
        ),
        message=message,
        language="markdown",
        framework_mappings=FrameworkMappings(
            owasp_llm=list(owasp_llm or []),
            owasp_agentic=list(owasp_agentic or []),
            cwe=list(cwe or []),
            ast=[ast_id],
        ),
        remediation=_remediation_for(rule_short),
    )


# --- public rule list ---

ALL_RULES = [
    check_ast01_body_markers,
    check_ast03_overprivileged,
    check_ast04_metadata,
    check_ast05_unsafe_deserialization,
    check_ast07_update_drift,
]


# --- public reference data (used by the Reference tab in HTML reports) ---
#
# One entry per *user-visible rule* — multiple sub-rules under a single
# AST risk are listed individually so the Reference tab shows the
# distinct severities. Frameworks/remediation kept short here; the
# scanner runtime emits the full message on each finding.
RULE_DESCRIPTIONS = [
    {
        "rule_id": "ast01-malicious-skill-marker",
        "agentshield_id": "AS-M-D-AST01-001",
        "legacy_ids": ['AS-AST-001'],
        "title": "AST01 — concealment / jailbreak markers in body",
        "category": "detect",
        "severity": "high",
        "description": (
            "SKILL.md body prose contains concealment, jailbreak, or "
            "exfil instructions the host LLM may treat as authoritative "
            "— the same prose-injection surface documented in the "
            "ClawHavoc / ToxicSkills 2026 campaigns."
        ),
        "frameworks": {"ast": ["AST01"], "owasp_llm": ["LLM01", "LLM03"]},
        "remediation": (
            "Remove concealment / jailbreak strings from the skill body. "
            "If they're red-team fixtures, move them to a dedicated test "
            "corpus outside the published manifest."
        ),
    },
    {
        "rule_id": "ast03-network-unrestricted",
        "agentshield_id": "AS-M-D-AST03-001",
        "legacy_ids": ['AS-AST-003'],
        "title": "AST03 — unrestricted network egress",
        "category": "detect",
        "severity": "high",
        "description": (
            "`permissions.network: true` (or `network.allow: ['*']`) in "
            "the manifest. Skills with default-allow network can exfil "
            "credentials or pull C2 instructions silently."
        ),
        "frameworks": {
            "ast": ["AST03"],
            "owasp_llm": ["LLM03", "LLM06"],
            "owasp_agentic": ["T2", "T3"],
            "cwe": ["CWE-732"],
        },
        "remediation": (
            "Use a domain allowlist with default-deny: "
            "`network.allow: [api.example.com]`."
        ),
    },
    {
        "rule_id": "ast03-shell-access",
        "agentshield_id": "AS-M-D-AST03-003",
        "legacy_ids": ['AS-AST-003'],
        "title": "AST03 — shell access granted",
        "category": "detect",
        "severity": "medium",
        "description": (
            "`permissions.shell: true` declared. Skill scripts that can "
            "shell out have full host privileges — credential stealers "
            "and reverse shells become trivial."
        ),
        "frameworks": {"ast": ["AST03"], "owasp_llm": ["LLM06"], "cwe": ["CWE-78"]},
        "remediation": (
            "Grant shell access only when the skill's core function "
            "requires it; document why in the description."
        ),
    },
    {
        "rule_id": "ast03-wildcard-file-read",
        "agentshield_id": "AS-M-D-AST03-004",
        "legacy_ids": ['AS-AST-003'],
        "title": "AST03 — wildcard file read/write paths",
        "category": "detect",
        "severity": "medium",
        "description": (
            "`permissions.files.read` (or `.write`) contains a wildcard "
            "(e.g. `~/.aws/**`). Wildcards defeat least-privilege review "
            "— the registry can't tell what the skill will actually "
            "touch."
        ),
        "frameworks": {"ast": ["AST03"], "cwe": ["CWE-732"]},
        "remediation": "Declare explicit paths; no wildcards.",
    },
    {
        "rule_id": "ast03-identity-file-write",
        "agentshield_id": "AS-M-D-AST03-006",
        "legacy_ids": ['AS-AST-003'],
        "title": "AST03 — write access to identity file",
        "category": "detect",
        "severity": "critical",
        "description": (
            "Skill requests write access to `SOUL.md`, `MEMORY.md`, or "
            "`AGENTS.md` without an explicit `deny_write` override. "
            "These files persist instructions across sessions — writes "
            "to them are persistence vectors."
        ),
        "frameworks": {
            "ast": ["AST03"],
            "owasp_llm": ["LLM04"],
            "owasp_agentic": ["T1"],
            "cwe": ["CWE-732"],
        },
        "remediation": (
            "Add the file to `permissions.files.deny_write`. If write "
            "access is genuinely required, document why and require "
            "operator approval."
        ),
    },
    {
        "rule_id": "ast04-missing-description",
        "agentshield_id": "AS-M-D-AST04-001",
        "legacy_ids": ['AS-AST-004'],
        "title": "AST04 — missing description",
        "category": "detect",
        "severity": "low",
        "description": (
            "Frontmatter has no `description` field, or it is empty. "
            "Without a description the host LLM can't decide when to "
            "trigger the skill, and reviewers can't verify intent."
        ),
        "frameworks": {"ast": ["AST04"]},
        "remediation": "Add a one-paragraph honest description.",
    },
    {
        "rule_id": "ast04-missing-author-identity",
        "agentshield_id": "AS-M-D-AST04-002",
        "legacy_ids": ['AS-AST-004'],
        "title": "AST04 — missing author identity",
        "category": "detect",
        "severity": "info",
        "description": (
            "No `author.identity` (DID / signing-key anchor). Without "
            "a verifiable identity, registry consumers can't detect "
            "impersonation — the foothold the ClawHub fake-Google skill "
            "exploited."
        ),
        "frameworks": {"ast": ["AST04"]},
        "remediation": (
            "Add `author.identity: did:web:<your-domain>` and a "
            "`signing_key:` field."
        ),
    },
    {
        "rule_id": "ast05-unsafe-deserialization",
        "agentshield_id": "AS-M-D-AST05-001",
        "legacy_ids": ['AS-AST-005'],
        "title": "AST05 — unsafe deserialization in scripts",
        "category": "detect",
        "severity": "high",
        "description": (
            "`yaml.load` (without SafeLoader), `pickle.loads`, `eval`, "
            "or `exec` inside a fenced code block. Skill scripts run "
            "with the agent's full host permissions — an unsafe "
            "deserializer is a direct RCE primitive."
        ),
        "frameworks": {
            "ast": ["AST05"],
            "owasp_llm": ["LLM05"],
            "owasp_agentic": ["T11"],
            "cwe": ["CWE-94", "CWE-502"],
        },
        "remediation": (
            "Use `yaml.safe_load`, JSON + schema validation, or "
            "`ast.literal_eval`. Never `eval`/`exec` on untrusted bytes."
        ),
    },
    {
        "rule_id": "ast07-missing-signature",
        "agentshield_id": "AS-M-D-AST07-001",
        "legacy_ids": ['AS-AST-007'],
        "title": "AST07 — missing manifest signature",
        "category": "detect",
        "severity": "info",
        "description": (
            "Frontmatter has no `signature` field. Without an ed25519 "
            "signature the registry can't verify the skill on update; "
            "ClawJacked-style update-drift attacks become viable."
        ),
        "frameworks": {"ast": ["AST07"], "owasp_llm": ["LLM03"], "cwe": ["CWE-345"]},
        "remediation": (
            "Sign the canonical skill payload with an ed25519 key and "
            "publish the signature in the manifest."
        ),
    },
    {
        "rule_id": "ast07-missing-content-hash",
        "agentshield_id": "AS-M-D-AST07-002",
        "legacy_ids": ['AS-AST-007'],
        "title": "AST07 — missing content hash",
        "category": "detect",
        "severity": "info",
        "description": (
            "Frontmatter has no `content_hash` field. Merkle-root "
            "verification at install time requires a SHA-256 over the "
            "canonical skill payload."
        ),
        "frameworks": {"ast": ["AST07"], "cwe": ["CWE-345"]},
        "remediation": (
            "Add `content_hash: sha256:<digest>` over the canonical "
            "skill payload."
        ),
    },
]
