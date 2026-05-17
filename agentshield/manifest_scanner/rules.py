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
    "ast06-credential-in-bundle":    ("AS-M-D-AST06-001", ["AS-AST-006"]),
    "ast08-permission-combo-across-skills": ("AS-M-D-AST08-001", ["AS-AST-008"]),
}


# AST06 — non-code companion files that ship with a skill bundle can
# carry credentials Semgrep won't see (Semgrep targets .py / .java).
# Credential regex set tuned to the common provider shapes plus generic
# `KEY=VALUE` patterns. Tight enough that random YAML config doesn't
# false-positive, broad enough to catch the obvious cases.
_AST06_FILE_EXTS = frozenset({
    ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".config",
    ".properties", ".env", ".cfg", ".txt",
})

_AST06_CRED_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Provider-prefixed keys — high confidence.
    (re.compile(r"sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{32,}"), "Anthropic API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_\-]{32,}"), "OpenAI project key"),
    (re.compile(r"(?<![A-Za-z0-9_])sk-[A-Za-z0-9]{20,}"), "OpenAI-style API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access-key ID"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"xox[abp]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(r"gh[pous]_[0-9A-Za-z]{30,}"), "GitHub token"),
    # KEY=VALUE with strong key names. Length floor on the value keeps
    # placeholder strings like `password=changeme` quiet but catches
    # real-looking secrets.
    (
        re.compile(
            r"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?key|"
            r"secret[_-]?key|password|passwd|auth[_-]?token|"
            r"bearer[_-]?token)\s*[=:]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}['\"]?"
        ),
        "Generic credential assignment",
    ),
]

# Skip binary / huge files outright — manifest bundles shouldn't carry
# anything close to this size.
_AST06_MAX_FILE_BYTES = 1_000_000


def check_ast06_credentials_in_bundle(manifest: ParsedManifest) -> list[Finding]:
    """AST06 — credentials hard-coded in non-code files shipped with the skill.

    Walks the manifest's directory and scans every non-markdown text file
    for credential patterns. Catches the credential class that Semgrep
    misses (the code scanner only sees `.py` / `.java`); a skill bundle
    routinely ships YAML / .env / JSON config alongside its prose, and
    secrets pasted into those files ship to every consumer of the bundle
    in the clear.
    """
    findings: list[Finding] = []
    manifest_path = getattr(manifest, "path", None)
    if manifest_path is None:
        return findings
    bundle_dir = manifest_path.parent
    if not bundle_dir.is_dir():
        return findings

    for entry in sorted(bundle_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _AST06_FILE_EXTS:
            continue
        if entry.name.lower() in RECOGNIZED_SKILL_MD_NAMES:
            # The MD body is AST01's domain.
            continue
        try:
            if entry.stat().st_size > _AST06_MAX_FILE_BYTES:
                continue
            text = entry.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_num, line in enumerate(text.splitlines(), start=1):
            for pattern, kind in _AST06_CRED_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        _build_finding(
                            rule_short="ast06-credential-in-bundle",
                            path=entry,
                            line=line_num,
                            snippet=line.strip()[:200],
                            message=(
                                f"{kind} hard-coded in skill-bundle file "
                                f"`{entry.name}`. Skill bundles ship "
                                f"verbatim to every consumer — anyone who "
                                f"can read the bundle (registry, cache, "
                                f"developer clone) reads the secret. "
                                f"AST06 — Secrets in Skill Bundles. Move "
                                f"to a secrets manager or runtime-injected "
                                f"env var; never ship secrets inside the "
                                f"bundle itself."
                            ),
                            severity="high",
                            ast_id="AST06",
                            owasp_llm=["LLM06"],
                            owasp_agentic=["T2"],
                            cwe=["CWE-798"],  # Use of hard-coded credentials
                        )
                    )
                    break  # one finding per line — don't double-fire
    return findings


# Convenience — used inside check_ast06 to skip the manifest's own MD
# files (which AST01 already inspects).
RECOGNIZED_SKILL_MD_NAMES = frozenset({
    "skill.md", "agent.md", "agents.md",
    "instruction.md", "instructions.md",
    "prompt.md", "prompts.md", "claude.md",
})

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
                        owasp_llm=["LLM01"],
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
                owasp_llm=["LLM06"],
                owasp_agentic=["T2", "T3"],
                # Path B: CWE-918 (SSRF) added — when an LLM-derived URL
                # can be passed to the skill's network egress, this is
                # the textbook agent-side SSRF surface. Runtime probe
                # validates it by triggering an outbound fetch.
                cwe=["CWE-732", "CWE-918"],
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
                    owasp_llm=["LLM06"],
                    owasp_agentic=["T2", "T3"],
                    cwe=["CWE-732", "CWE-918"],  # Path B: SSRF surface
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
                            owasp_llm=[],
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
                owasp_llm=[],
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
    check_ast06_credentials_in_bundle,
    check_ast07_update_drift,
]


# Dangerous permission pairs — when both appear (in one skill OR split
# across two skills loaded together), the combo creates an attack class
# that neither half exhibits alone. Names are the canonical
# permission tokens read off the manifest frontmatter.
_AST08_DANGEROUS_COMBOS: list[tuple[frozenset[str], str]] = [
    (
        frozenset({"network_egress", "files_write"}),
        "Network egress paired with arbitrary file write is the textbook "
        "exfiltration chain — read sensitive files, POST them anywhere.",
    ),
    (
        frozenset({"network_egress", "shell"}),
        "Shell access paired with network egress turns the agent into a "
        "general-purpose attack tool — exec anything, send results out.",
    ),
    (
        frozenset({"files_write", "shell"}),
        "Shell access paired with file write means the agent can drop "
        "arbitrary scripts onto the host and run them.",
    ),
    (
        frozenset({"network_egress", "files_read_wildcard"}),
        "Wildcard file read + network egress allows broad credential / "
        "secret harvesting and exfiltration.",
    ),
]


def _summarise_permissions(manifest: ParsedManifest) -> set[str]:
    """Reduce a manifest's frontmatter permissions to canonical tokens.

    Tokens align with the dangerous-combo set above. Intentionally
    over-approximate — if a manifest grants something that maps to one
    of these tokens, count it. False positives are fine here; the
    finding is informational ("audit this combo"), not a hard block.
    """
    fm = manifest.frontmatter or {}
    perms = fm.get("permissions") or {}
    tokens: set[str] = set()
    if not isinstance(perms, dict):
        return tokens

    # network
    net = perms.get("network")
    if net is True:
        tokens.add("network_egress")
    elif isinstance(net, dict):
        allow = net.get("allow") or []
        if isinstance(allow, list) and any(a == "*" for a in allow):
            tokens.add("network_egress")
        elif isinstance(allow, list) and allow:
            tokens.add("network_egress")  # any explicit allow still counts

    # shell
    if perms.get("shell") is True:
        tokens.add("shell")

    # files
    files = perms.get("files") or {}
    if isinstance(files, dict):
        for action in ("write", "read"):
            v = files.get(action)
            if isinstance(v, list) and v:
                # wildcards specifically
                if any(isinstance(p, str) and ("*" in p or "**" in p) for p in v):
                    tokens.add(f"files_{action}_wildcard")
                tokens.add(f"files_{action}")
            elif v is True:
                tokens.add(f"files_{action}_wildcard")
                tokens.add(f"files_{action}")

    return tokens


def check_ast08_cross_skill(
    manifests: list[ParsedManifest],
) -> list[Finding]:
    """AST08 — Permission Bleed across multi-skill manifests.

    Runs once per scan, not once per manifest, so it sees every skill
    in the target. When two or more skills are loaded together and
    their combined permissions hit a known-dangerous combo, emit one
    finding per (combo, skill pair).

    Single-skill targets short-circuit out — AST08 is by definition a
    multi-skill concern. The single-manifest AST03 rule already covers
    the "one skill grants too much" case.
    """
    if len(manifests) < 2:
        return []

    findings: list[Finding] = []
    summarised = [(m, _summarise_permissions(m)) for m in manifests]

    for i, (mi, ti) in enumerate(summarised):
        for j in range(i + 1, len(summarised)):
            mj, tj = summarised[j]
            combined = ti | tj
            for combo, reason in _AST08_DANGEROUS_COMBOS:
                if combo.issubset(combined) and not combo.issubset(ti) and not combo.issubset(tj):
                    # Combo emerges only when both skills are loaded —
                    # neither skill exhibits it alone. That's the AST08
                    # bleed signature.
                    pi = mi.path.as_posix()
                    pj = mj.path.as_posix()
                    findings.append(
                        _build_finding(
                            rule_short="ast08-permission-combo-across-skills",
                            path=mi.path,
                            line=1,
                            snippet=(
                                f"Cross-skill combo: {sorted(combo)} "
                                f"across {pi} + {pj}"
                            ),
                            message=(
                                f"Two skills loaded together grant a "
                                f"dangerous permission combination that "
                                f"neither holds alone. {pi} contributes "
                                f"{sorted(ti & combo)}, {pj} contributes "
                                f"{sorted(tj & combo)}. {reason} "
                                f"AST08 — Permission Bleed."
                            ),
                            severity="high",
                            ast_id="AST08",
                            owasp_llm=["LLM06"],
                            owasp_agentic=["T2", "T6"],
                            cwe=["CWE-269"],  # Improper privilege management
                        )
                    )
    return findings


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
        "frameworks": {"ast": ["AST01"], "owasp_llm": ["LLM01"]},
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
            "owasp_llm": ["LLM06"],
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
            "owasp_llm": [],
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
        "frameworks": {"ast": ["AST07"], "owasp_llm": [], "cwe": ["CWE-345"]},
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
    {
        "rule_id": "ast08-permission-combo-across-skills",
        "agentshield_id": "AS-M-D-AST08-001",
        "legacy_ids": ['AS-AST-008'],
        "title": "AST08 — dangerous permission combo across skills",
        "category": "detect",
        "severity": "high",
        "description": (
            "Two or more skill manifests in the target grant a "
            "permission combination that is dangerous in aggregate, "
            "even though no single skill exhibits the combo alone. "
            "Example: skill A grants network egress, skill B grants "
            "filesystem write — together they form an exfiltration "
            "chain. A compromise of any one skill leaks the combined "
            "blast radius across all of them. AST08 — Permission Bleed."
        ),
        "frameworks": {
            "ast": ["AST08"],
            "owasp_llm": ["LLM06"],
            "owasp_agentic": ["T2", "T6"],
            "cwe": ["CWE-269"],
        },
        "remediation": (
            "Audit the cross-skill permission set. Either tighten each "
            "skill's grant so the dangerous combo no longer materialises "
            "(e.g. remove network from the skill that doesn't need it), "
            "or isolate the skills into separate runtime contexts so a "
            "compromise of one can't leverage the other's privileges. "
            "Document the intentional combo in the manifest if it's "
            "load-bearing — silent privilege bleed is the failure mode."
        ),
    },
    {
        "rule_id": "ast06-credential-in-bundle",
        "agentshield_id": "AS-M-D-AST06-001",
        "legacy_ids": ['AS-AST-006'],
        "title": "AST06 — credential in skill bundle",
        "category": "detect",
        "severity": "high",
        "description": (
            "A non-code file in the skill bundle (YAML / JSON / .env / "
            "config) contains a credential pattern. Bundle files ship "
            "verbatim to every consumer — anyone with read access to "
            "the registry, the cache, or a developer's clone reads the "
            "secret. Semgrep's code-pattern rules miss this because "
            "they target `.py` / `.java`, not bundled config."
        ),
        "frameworks": {
            "ast": ["AST06"],
            "owasp_llm": ["LLM06"],
            "owasp_agentic": ["T2"],
            "cwe": ["CWE-798"],
        },
        "remediation": (
            "Move secrets to a secrets manager (AWS Secrets Manager, "
            "HashiCorp Vault, Azure Key Vault) and reference them by "
            "name from the manifest. If runtime injection isn't an "
            "option, at minimum keep credentials in a separate file "
            "outside the bundle and load them via environment variable."
        ),
    },
]
