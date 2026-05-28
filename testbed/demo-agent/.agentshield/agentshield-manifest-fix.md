# AgentShield — Manifest Findings Fix Guide

_Per-scan fix guide for **Manifest Scanner** findings — insecure permissions, dangerous tool combinations, and jailbreak markers found in your SKILL.md / AGENT.md / CLAUDE.md files. Paste into Claude Code or Copilot Chat and say:_

> **"Fix all the findings listed in this guide. For each one, read the Location, Flagged code, and Fix sections, then apply the change. After all fixes, confirm what you changed."**

---

**11 findings to fix** — 🟧 3 high · 🟨 2 medium · 🟦 6 info

Work through them **top to bottom** (critical first).

---

### [1/11] 🟧 HIGH · `ast03-network-unrestricted` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Skill declares unrestricted network egress (`network: true`). AST03 — should be a domain allowlist (`network.allow: [api.example.com]`) with default-deny.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares permissions.network: true with no network.allow allowlist — unrestricted outbound network access.

**Fix:** Use a domain allowlist with default-deny: `network.allow: [api.example.com]`.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-network-unrestricted` no longer fires for `SKILL.md`._
---

### [2/11] 🟧 HIGH · `ast08-permission-combo-across-skills` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['network_egress'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with network egress turns the agent into a general-purpose attack tool — exec anything, send results out. AST08 — Permission Bleed.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Combined permissions across the two manifests: demo-agent-helper grants network: true + filesystem read/write; billing grants shell: true. The compound (network egress + shell exec + filesystem write) is the RCE-to-exfil pair AST08 watches for — neither skill on its own grants the dangerous combo, but together they do.

**Fix:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast08-permission-combo-across-skills` no longer fires for `SKILL.md`._
---

### [3/11] 🟧 HIGH · `ast08-permission-combo-across-skills` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Two skills loaded together grant a dangerous permission combination that neither holds alone. /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/SKILL.md contributes ['files_write'], /Users/suganthichandrasekaran/AgentShield/testbed/demo-agent/skills/billing/SKILL.md contributes ['shell']. Shell access paired with file write means the agent can drop arbitrary scripts onto the host and run them. AST08 — Permission Bleed.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Second emission of the same cross-skill compound permission reported from the billing-side perspective. Either fix (drop network from the helper OR drop shell from billing OR split the skills across separate agents) resolves both.

**Fix:** Audit the cross-skill permission set. Either tighten each skill's grant so the dangerous combo no longer materialises (e.g. remove network from the skill that doesn't need it), or isolate the skills into separate runtime contexts so a compromise of one can't leverage the other's privileges. Document the intentional combo in the manifest if it's load-bearing — silent privilege bleed is the failure mode.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast08-permission-combo-across-skills` no longer fires for `SKILL.md`._
---

### [4/11] 🟨 MEDIUM · `ast03-wildcard-file-read` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Wildcard read permission on `~/.config/demo-agent/**`. AST03 — skill manifests must declare explicit paths; wildcards defeat least-privilege review.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** permissions.files.read pattern `~/.config/demo-agent/**` uses the recursive ** glob — wildcard file-read access covering every file under the config directory.

**Fix:** Declare explicit paths; no wildcards.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-wildcard-file-read` no longer fires for `SKILL.md`._
---

### [5/11] 🟨 MEDIUM · `ast03-shell-access` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** Skill declares shell access (`shell: true`). AST03 — should only be granted when the skill's core function requires it; document why in the description.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter declares permissions.shell: true. The static permission grant is what AST03 catches — granting shell access is a coarse capability; even narrowed scripts can be attacked via argument injection.

**Fix:** Grant shell access only when the skill's core function requires it; document why in the description.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast03-shell-access` no longer fires for `skills/billing/SKILL.md`._
---

### [6/11] 🟦 INFO · `ast04-missing-author-identity` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Author block has only `name: Demo Co` — no DID, no signed handle, no public-key reference. Provenance is unverifiable; an attacker republishing the bundle as 'Demo Co' is indistinguishable from the legitimate publisher.

**Fix:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast04-missing-author-identity` no longer fires for `SKILL.md`._
---

### [7/11] 🟦 INFO · `ast07-missing-content-hash` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares no content_hash / checksum / integrity field — the loader has no way to verify the bundle payload matches what the manifest describes.

**Fix:** Add `content_hash: sha256:<digest>` over the canonical skill payload.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-content-hash` no longer fires for `SKILL.md`._
---

### [8/11] 🟦 INFO · `ast07-missing-signature` · [Semgrep]

**Location:** `SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** Frontmatter declares no signature field — bundle authenticity is unverifiable independent of integrity. Companion to the missing content_hash finding.

**Fix:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-signature` no longer fires for `SKILL.md`._
---

### [9/11] 🟦 INFO · `ast04-missing-author-identity` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** Skill manifest has no `author.identity` (DID / signing-key anchor). AST04 — without a verifiable identity anchor, registry consumers cannot detect impersonation or typosquats; this is the foothold the ClawHub fake-Google skill exploited.
**Copilot verdict:** ⚠ Context-dependent
**Copilot reasoning:** Author block has `did: did:example:demo-team` — the did:example: method is documented as a non-production placeholder (RFC), not a real verifiable identity. The presence of a DID field is a step toward compliance, but the placeholder method leaves provenance unverifiable. Mitigatable by switching to a real DID method (did:web, did:key) — hence CD rather than TP.

**Fix:** Add `author.identity: did:web:<your-domain>` and a `signing_key:` field.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast04-missing-author-identity` no longer fires for `skills/billing/SKILL.md`._
---

### [10/11] 🟦 INFO · `ast07-missing-content-hash` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `content_hash` field. AST07 — Merkle-root verification at install time requires a SHA-256 over the canonical skill payload.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter has no content_hash / checksum / integrity field — identical defect to the demo-agent-helper SKILL.md case.

**Fix:** Add `content_hash: sha256:<digest>` over the canonical skill payload.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-content-hash` no longer fires for `skills/billing/SKILL.md`._
---

### [11/11] 🟦 INFO · `ast07-missing-signature` · [Semgrep]

**Location:** `skills/billing/SKILL.md` · line 1
**Finding:** SKILL.md frontmatter has no `signature` field. AST07 — without an ed25519 signature the registry cannot verify the skill on update; ClawJacked-style update-drift attacks become viable.
**Copilot verdict:** ✅ Confirmed real
**Copilot reasoning:** billing skill frontmatter has no signature field — identical defect to the demo-agent-helper SKILL.md case.

**Fix:** Sign the canonical skill payload with an ed25519 key and publish the signature in the manifest.

_After fixing: re-run `agentshield scan <path>` + `agentshield merge <path>` and confirm `ast07-missing-signature` no longer fires for `skills/billing/SKILL.md`._

---

_Generated by AgentShield · Re-run `agentshield merge <path>` after fixes to get a fresh copy of this guide with only remaining findings._
