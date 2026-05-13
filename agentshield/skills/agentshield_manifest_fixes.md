---
name: agentshield-manifest-fixes
description: |
  Help developers fix AgentShield AST10 manifest-scanner findings — checks on `SKILL.md` packages with rule IDs starting `AS-M-`. Maps to OWASP Agentic Skills Top 10 (AST10).

  Use this skill when:
    - the user pastes a finding ID starting with `AS-M-` (e.g. `AS-M-D-AST03-001`) into chat
    - the user asks how to fix an AgentShield manifest / SKILL.md finding
    - the user references an AST10 risk (`AST01` … `AST07`) on a skill package they're building or auditing
    - the user references a legacy `AS-AST-NNN` ID — those alias to current `AS-M-*` IDs
author:
  name: AgentShield
  identity: did:web:github.com/suganthiaravind/agentshield
permissions:
  network:
    allow: []
  shell: false
  files:
    read: []
    write: []
    deny_write:
      - SOUL.md
      - MEMORY.md
      - AGENTS.md
risk_tier: L0
---

# AgentShield AST10 Manifest Remediation Skill

Help developers fix AgentShield AST10 manifest-scanner findings — checks on `SKILL.md` packages with rule IDs starting `AS-M-`. Maps to OWASP Agentic Skills Top 10 (AST10).

When a user pastes an `AS-M-…` finding ID or asks about one of the rules below, walk them through the remediation. Cite the canonical rule ID and the framework mappings; if the user pasted a legacy ID, mention it once and carry on with the current ID.

Total rules in this skill: **10**

---

## 🔴 Detect (10)

### `AS-M-D-AST01-001` — AST01 — concealment / jailbreak markers in body

**Severity:** high · **Languages:** markdown · **Legacy ID:** `AS-AST-001`

**Frameworks:** `AST10 AST01` `OWASP LLM LLM01`

**What it flags:** SKILL.md body prose contains concealment, jailbreak, or exfil instructions the host LLM may treat as authoritative — the same prose-injection surface documented in the ClawHavoc / ToxicSkills 2026 campaigns.

**Remediation:** Remove concealment / jailbreak strings from the skill body. If they're red-team fixtures, move them to a dedicated test corpus outside the published manifest.

### `AS-M-D-AST03-001` — AST03 — unrestricted network egress

**Severity:** high · **Languages:** markdown · **Legacy ID:** `AS-AST-003`

**Frameworks:** `AST10 AST03` `OWASP LLM LLM06` `OWASP Agentic T2` `OWASP Agentic T3` `CWE CWE-732`

**What it flags:** `permissions.network: true` (or `network.allow: ['*']`) in the manifest. Skills with default-allow network can exfil credentials or pull C2 instructions silently.

**Remediation:** Use a domain allowlist with default-deny: `network.allow: [api.example.com]`.

### `AS-M-D-AST03-003` — AST03 — shell access granted

**Severity:** medium · **Languages:** markdown · **Legacy ID:** `AS-AST-003`

**Frameworks:** `AST10 AST03` `OWASP LLM LLM06` `CWE CWE-78`

**What it flags:** `permissions.shell: true` declared. Skill scripts that can shell out have full host privileges — credential stealers and reverse shells become trivial.

**Remediation:** Grant shell access only when the skill's core function requires it; document why in the description.

### `AS-M-D-AST03-004` — AST03 — wildcard file read/write paths

**Severity:** medium · **Languages:** markdown · **Legacy ID:** `AS-AST-003`

**Frameworks:** `AST10 AST03` `CWE CWE-732`

**What it flags:** `permissions.files.read` (or `.write`) contains a wildcard (e.g. `~/.aws/**`). Wildcards defeat least-privilege review — the registry can't tell what the skill will actually touch.

**Remediation:** Declare explicit paths; no wildcards.

### `AS-M-D-AST03-006` — AST03 — write access to identity file

**Severity:** critical · **Languages:** markdown · **Legacy ID:** `AS-AST-003`

**Frameworks:** `AST10 AST03` `OWASP Agentic T1` `CWE CWE-732`

**What it flags:** Skill requests write access to `SOUL.md`, `MEMORY.md`, or `AGENTS.md` without an explicit `deny_write` override. These files persist instructions across sessions — writes to them are persistence vectors.

**Remediation:** Add the file to `permissions.files.deny_write`. If write access is genuinely required, document why and require operator approval.

### `AS-M-D-AST04-001` — AST04 — missing description

**Severity:** low · **Languages:** markdown · **Legacy ID:** `AS-AST-004`

**Frameworks:** `AST10 AST04`

**What it flags:** Frontmatter has no `description` field, or it is empty. Without a description the host LLM can't decide when to trigger the skill, and reviewers can't verify intent.

**Remediation:** Add a one-paragraph honest description.

### `AS-M-D-AST04-002` — AST04 — missing author identity

**Severity:** info · **Languages:** markdown · **Legacy ID:** `AS-AST-004`

**Frameworks:** `AST10 AST04`

**What it flags:** No `author.identity` (DID / signing-key anchor). Without a verifiable identity, registry consumers can't detect impersonation — the foothold the ClawHub fake-Google skill exploited.

**Remediation:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.

### `AS-M-D-AST05-001` — AST05 — unsafe deserialization in scripts

**Severity:** high · **Languages:** markdown · **Legacy ID:** `AS-AST-005`

**Frameworks:** `AST10 AST05` `OWASP LLM LLM05` `OWASP Agentic T11` `CWE CWE-94` `CWE CWE-502`

**What it flags:** `yaml.load` (without SafeLoader), `pickle.loads`, `eval`, or `exec` inside a fenced code block. Skill scripts run with the agent's full host permissions — an unsafe deserializer is a direct RCE primitive.

**Remediation:** Use `yaml.safe_load`, JSON + schema validation, or `ast.literal_eval`. Never `eval`/`exec` on untrusted bytes.

### `AS-M-D-AST07-001` — AST07 — missing manifest signature

**Severity:** info · **Languages:** markdown · **Legacy ID:** `AS-AST-007`

**Frameworks:** `AST10 AST07` `CWE CWE-345`

**What it flags:** Frontmatter has no `signature` field. Without an ed25519 signature the registry can't verify the skill on update; ClawJacked-style update-drift attacks become viable.

**Remediation:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.

### `AS-M-D-AST07-002` — AST07 — missing content hash

**Severity:** info · **Languages:** markdown · **Legacy ID:** `AS-AST-007`

**Frameworks:** `AST10 AST07` `CWE CWE-345`

**What it flags:** Frontmatter has no `content_hash` field. Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.

**Remediation:** Add `content_hash: sha256:<digest>` over the canonical skill payload.

---

## Related

- AgentShield repo: https://github.com/suganthiaravind/agentshield
- For the live, full rule list across all three sources, run `agentshield merge --output-html report.html` and open the **Reference tab** of the generated report.

