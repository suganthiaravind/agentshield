# AgentShield — Architecture Rationale

Status: Draft 2026-05-03
Companion to: [ARCHITECTURE.md](./ARCHITECTURE.md)

This document explains *why* the architecture in [ARCHITECTURE.md](./ARCHITECTURE.md) looks the way it does. For each major decision: what was considered, what was rejected, and what the rejected option's failure mode would have been.

---

## 1. Why semgrep as the primary detection engine

**Decision:** Semgrep YAML rules are the core detection mechanism, not custom AST walkers and not LLM-first scanning.

**Alternatives considered:**
- *Custom AST walker* (tree-sitter / Python's `ast` / JavaParser). Maximum precision, but every rule is bespoke code. Rule reviewability collapses; non-engineers can't audit a Python AST visitor.
- *LLM-first scanning* (LLM reads every file). Best framework knowledge, but: cost scales with codebase size (millions of files for a JPMC monorepo), non-deterministic across runs, slow, and code has to leave the repo.
- *Off-the-shelf SAST tools* (CodeQL, Snyk, SonarQube). Strong for traditional vulns but blind to LLM/agent-specific risks; can't easily extend with custom rules in the same format.

**Why semgrep wins (ranked, killer reasons first):**

Cost is real but not the primary reason. For a compliance-heavy enterprise like JPMC, the killer pair is **determinism + auditability** — there is no amount of money that buys reproducibility from a non-deterministic system.

| # | Reason | Why it outweighs LLM-as-judge for primary detection |
|---|---|---|
| 1 | **Determinism** | Same commit → same findings, every run. Audit/compliance teams must reproduce verdicts; PR-blocking checks need stability. LLM verdicts drift run-to-run even at `temp=0`. |
| 2 | **Auditability** | When a finding fires, you point at the exact YAML pattern — a definitive answer to "why did this trigger?" LLM reasoning text drifts, can hallucinate about itself, and cannot anchor compliance documentation. |
| 3 | **Coverage guarantees** | If a rule matches `X`, *every* `X` in the codebase is matched — provable. LLMs silently miss findings (false negatives), which is the worst failure mode for security tools. |
| 4 | **Speed** | Pre-commit hooks need <1s, PR checks <30s. LLM-per-file scanning would take minutes-to-hours on real repos. Semgrep scans a service repo in seconds. |
| 5 | **Trust boundary** | Semgrep runs entirely locally; no code leaves the machine. LLM judging = code snippets leave the machine, even to corporate Bedrock. More compliance surface to defend. |
| 6 | **Hallucination risk** | LLMs invent vulnerabilities or miss real ones. Catastrophic for security tools where false negatives are silent. |
| 7 | **Industry precedent** | Every mature security scanner is rule-based — CodeQL, Snyk, Semgrep, SonarQube. The reasons above are why. |
| 8 | **Reviewability for non-engineers** | YAML rules can be audited by security/compliance staff. AST walkers and LLM prompts cannot. |
| 9 | **Cross-language coverage** | Same YAML format covers Python AND Java with `taint` mode. No per-language tooling investment. |
| 10 | **Cost** | Real, but probably the smallest factor at JPMC scale — the org can afford the tokens. The other factors above do not have a budget workaround. |

**Where LLM-as-judge does earn its keep:** disambiguating Tier 2 fallback findings (where SNR is worst), generating natural-language remediation, and discovering things rules missed (Tier 4). These are fundamentally different roles from primary detection and are explicitly part of the architecture — see §2.

**Failure mode if rejected (i.e. if we went LLM-first instead):** findings become non-reproducible across runs, breaking audit and PR-gating. False negatives go undetected because there's no provable coverage. Compliance documentation cannot be anchored to stable rule definitions. With ~30 rules across 3 categories, custom AST walkers (the other rejected alternative) become 30 mini-engineering projects with the same audit problems.

---

## 2. Why a three-tier (semgrep + fallback + LLM judge) architecture

**Decision:** High-precision framework-specific rules → broader fallback rules → LLM judge to triage the noisy tier.

**Alternatives considered:**
- *Pure framework enumeration (no fallback, no LLM)*. Cheap and simple but blind to internal wrappers and new SDKs. The ecosystem evolves faster than rule maintenance.
- *Pure LLM judging (no semgrep)*. Adapts automatically but costs scale with codebase size, not finding volume. Untenable on enterprise monorepos.
- *Two tiers (framework rules + LLM judge on everything)*. Better coverage than pure enumeration, but LLM cost not bounded.

**Why three tiers win:**
- Tier 1 catches the 80% case for free with high precision.
- Tier 2 (fallback) catches the 15% (unknown wrappers) for free but with high noise.
- Tier 3 (LLM) only fires on Tier 2 findings — cost is bounded by finding count, not codebase size. The LLM is used exactly where SNR is worst.
- Each tier has a clear precision/cost profile, making it auditable.

**Failure mode if collapsed to one tier:** either coverage suffers (pure framework rules) or cost explodes (pure LLM).

---

## 3. Why pluggable LLM backend (boto3-Bedrock | SMARTSDK | Copilot)

**Decision:** Judge tier talks to a `JudgeBackend` protocol; concrete drivers are interchangeable via config flag.

**Alternatives considered:**
- *Hard-code SMARTSDK*. Was the original design (PHASE_I_PLAN VDI constraint). Brittle: locks the tool to one organization's sanctioned path.
- *Hard-code boto3-Bedrock*. Excludes deployment contexts where Bedrock isn't reachable but Copilot is.
- *No LLM tier at all*. Drops triage value; engineers manually disambiguate every fallback finding.

**Why pluggable wins:**
- Same product works across deployment contexts (CLI in VDI, IDE-time via Copilot, batch in CI).
- Future-proof: when a new sanctioned route appears, add a driver, no architectural change.
- Honors the scanner-vs-scanned split — scanner-side LLM choice is independent of what the scanned code does.

**Failure mode if rejected:** the product becomes context-specific and can't ship across multiple environments.

**Default = `boto3-bedrock`:** target apps usually run on AWS, so the scanner co-locates well; same trust boundary as the typical workload.

---

## 4. Why Detect / Defend / Respond taxonomy

**Decision:** Every finding maps to exactly one of three buckets (already locked in PHASE_I_PLAN §3).

**Alternatives considered:**
- *OWASP-only categorization*. Maps cleanly to LLM01–LLM10 but doesn't capture defensive controls or response readiness — only vulnerabilities.
- *NIST AI RMF only*. Comprehensive but academic; engineers don't think in MAP/MEASURE/MANAGE/GOVERN.
- *Flat severity-only* (high/med/low). No structural meaning; can't answer "how is this agent defended?"

**Why D/D/R wins:**
- Maps to security-ops mental model: vulnerabilities, defenses, recovery.
- Each bucket answers a distinct question.
- Findings still carry full framework mappings (OWASP/NIST/MITRE/AS-v1) for downstream consumers — D/D/R is the *organizing* spine, not the *only* taxonomy.

---

## 5. Why SARIF as primary output format

**Decision:** SARIF v2.1.0 is the canonical output; JSON and Markdown are derived views.

**Alternatives considered:**
- *Custom JSON schema*. Maximum control but every consumer needs a custom parser. Loses GitHub code-scanning, SonarQube, IDE plugin integrations for free.
- *Markdown-first*. Human-friendly but unparseable; no CI integration story.

**Why SARIF wins:**
- Industry standard; GitHub, GitLab, Azure DevOps, SonarQube, IntelliJ, VS Code all consume it natively.
- One output → many consumers.
- Schema is well-defined; extensions allow custom fields (framework mappings, judge verdicts) without breaking standard consumers.

**Failure mode if rejected:** every integration becomes a custom parser project.

---

## 6. Why bundled rule pack (YAMLs inside the wheel)

**Decision:** Rules ship inside the Python package, versioned with the tool.

**Alternatives considered:**
- *External rule path required*. Users must clone or download rules separately. Versioning becomes a manual problem.
- *Remote rule fetching*. Tool downloads rules at runtime from a registry. Breaks in offline VDIs.

**Why bundled wins:**
- A given AgentShield version is reproducible — rules are pinned to the wheel.
- Audit trail: scan metadata records the package version, which uniquely identifies the rule set.
- Works offline.

---

## 7. Why golden-file tests against testbed

**Decision:** Each rule has expected-findings snapshots against the framework directories in `testbed/`. CI runs semgrep + diffs against snapshots.

**Alternatives considered:**
- *Unit tests on rule logic only*. Tests against synthetic code snippets. Misses real-world edge cases.
- *No tests*. Standard for many semgrep rule packs. Refactoring a rule then becomes terrifying.

**Why golden-file wins:**
- The testbed already exists and is curated to look like real agent code.
- Rule changes produce visible diffs in expected findings — easy to review.
- Catches regressions when adding patterns to existing rules (which we just did extensively for SMARTSDK).

---

## 8. Why offline mode (graceful degradation when LLM unreachable)

**Decision:** If no LLM backend is reachable, run Tiers 1+2 only and emit a banner. Don't hard-fail.

**Alternatives considered:**
- *Hard-fail on LLM unreachable*. Strict but blocks scans during Bedrock outages or VDI network blips.
- *Silent degradation*. User has no idea the judge tier was skipped.

**Why offline mode wins:**
- Tiers 1+2 are still useful without judge — they catch the high-confidence cases.
- Banner makes the degradation visible in the report.
- Robust to transient infrastructure issues.

---

## 9. Why parallel development tracks

**Decision:** Architecture is split into 4 tracks (A: core, B: judge, C: tests, D: discovery) with explicit dependency edges, so multiple work streams can progress in parallel.

**Alternatives considered:**
- *Strict sequential build*. Simpler to reason about but slow; only one piece advances at a time.
- *Big-bang*. Build everything at once, integrate at the end. High risk of integration disasters.

**Why parallel tracks win:**
- Different tracks have different complexity profiles — judge is research-heavy, normalizer is mechanical.
- Independent modules let multiple developers (or multiple terminals/branches) progress simultaneously.
- Dependency edges are explicit, so the ordering is enforced where it matters but freed where it doesn't.

---

## 10. Why config file (`agentshield.yaml`) instead of CLI flags

**Decision:** Per-repo / per-org `agentshield.yaml` config file, with CLI flags as overrides.

**Alternatives considered:**
- *CLI flags only*. Simple for one-off scans but doesn't scale to dozens of options or shared team configs.
- *Env vars only*. Hard to version-control; team members forget which vars matter.

**Why config file wins:**
- Repo-level config can be committed and shared. New developer clones the repo and `agentshield scan` Just Works.
- Org-level defaults (e.g., always use SMARTSDK in this org) are encoded once.
- CLI flags still available for ad-hoc overrides.

---

## 11. Why scanner-vs-scanned constraint split

**Decision:** AgentShield's own LLM access (scanner side) is independent of what the scanned code does (scanned side).

**Why this needs to be explicit:** an earlier design conflated the two — assumed AgentShield must use SMARTSDK because PHASE_I_PLAN said "no outbound internet from the VDI." But that constraint applied to *production target agents*, not to the scanner running in a dev VDI. Conflating them led to a hard-coded SMARTSDK assumption.

**Failure mode if not split:** the product becomes deployment-shape-locked, can't run in environments where SMARTSDK isn't installed, and can't take advantage of multiple sanctioned LLM routes.

---

## 12. Static vs dynamic security boundary

**Decision:** Phase I draws a hard line at *static* analysis — pattern detection on source code. Active red-team probing (sending adversarial prompts to a running agent and observing behavior) is deferred to Phase II.

**Why the line is drawn here:**
- Static analysis is reproducible, fast, and runs on every commit. Dynamic probing is slow, requires a running agent in a known state, and is non-deterministic by nature.
- These are fundamentally different tools — collapsing them into one product confuses the value proposition. Static = "is the code defensible?" Dynamic = "does the running agent actually defend?"
- Most zero-trust failures *do* leave static signatures (missing auth check, broad credentials in code, no integrity verification on memory load). Catching the signature is cheap and high-value before the system ever runs.

**What's covered statically (Phase I):**
- Vulnerability surfaces (Detect): user input → LLM without sanitizer, untrusted RAG loaders, code-execution tools, indirect prompt injection signatures, system-prompt exposure.
- Control presence (Defend): guardrails imports, tool args schemas, authorization checks, credential scopes, memory integrity, inter-agent auth, side-effect validation.
- Observability presence (Respond): audit logging, tracing, structured error handling.

The full mapping is in [ARCHITECTURE.md §11 Zero-Trust Coverage Matrix](./ARCHITECTURE.md#11-zero-trust-coverage-matrix).

**What requires dynamic probing (Phase II):**
- Confirming a prompt injection actually succeeds (jailbreak verification).
- Measuring guardrail efficacy under adversarial input.
- Memory poisoning attacks against a running agent.
- Multi-turn attack chains (escalation, social engineering).
- Tool-output-driven attacks where the attack payload is generated at runtime by another tool.

These require feeding payloads to a live agent — Promptfoo, Garak, AgentDojo, and PyRIT (already in `testbed/`) are the right tools. Phase II will wire AgentShield's static report into these as a *prioritization signal*: "static analysis flagged these surfaces; dynamic probes should target them first."

**Failure mode if conflated:** a tool that tries to do both ends up doing neither well. Static-only tools that try to "simulate" attacks produce theatrical findings with no real coverage; dynamic-only tools waste cycles probing surfaces that static analysis would have caught for free.

**Phase I → Phase II handoff contract:**
- AgentShield emits SARIF with stable rule IDs and severity.
- Phase II consumes the SARIF, extracts flagged surfaces, and uses them as seeds for adversarial probing.
- Findings round-trip back into the report: static finding + dynamic exploit confirmation = highest-priority surface.

---

## 13. Open architectural questions (revisit later)

- **Does the judge tier also re-rank Tier 1 findings?** Currently no, to keep the trust boundary clean. Revisit if Tier 1 false-positive rate proves higher than expected.
- **Backend fallback** (e.g., try Copilot, fall back to boto3 on failure)? Currently single-backend-per-scan. Revisit if real-world reliability of any single backend is poor.
- **Should DF001 / R001 absence-detection rules get a fallback tier too?** Likely yes. Deferred until Tier 2 D001 behavior is validated against testbed.
- **Cross-language taint** (Python service calling Java microservice)? Out of scope for Phase I; revisit in Phase II.
- **Rule severity calibration per-repo**? Currently rule severity is fixed in YAML. Some repos may want to tune (e.g., DF001 from WARNING to ERROR). Likely solved via `agentshield.yaml` overrides — not a core architectural change.
