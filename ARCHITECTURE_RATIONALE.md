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

**Common pushback: "if the LLM is so good, why not skip Tier 1 and just use Tier 3 alone?"**

Tier 1 isn't kept *despite* having Tier 3 — it's kept *because* Tier 3 cannot replace it. Going LLM-only would lose every property that makes the tool usable in a compliance workflow:

| What we'd lose by dropping Tier 1 | Why it matters |
|---|---|
| **Determinism** | Same commit → same findings, every run. LLM verdicts drift even at `temp=0`. PR-blocking checks become impossible if "flagged today, not yesterday" |
| **Auditability** | "Why did this fire?" has a definitive answer with a YAML pattern. LLM reasoning text drifts and cannot anchor compliance documentation |
| **Coverage guarantees** | Tier 1 says: "every X in the codebase is matched, provably." LLMs silently miss findings — false negatives are the worst failure mode for security tools |
| **Speed** | Tier 1 scans an enterprise repo in seconds. LLM-per-file would take minutes-to-hours on a JPMC monorepo. Pre-commit hooks need <1s; PR checks <30s |
| **Trust boundary** | Tier 1 runs entirely locally; no code leaves the machine. Tier 3 sends snippets to Bedrock — even within corporate AWS, more compliance surface |
| **Hallucination risk** | LLMs invent vulnerabilities or miss real ones. Catastrophic for security tools |
| **Cost** | Real, but probably the smallest factor at JPMC scale — the org can afford the tokens. The other six don't have a budget workaround |

The right framing: **Tier 1 because LLMs cannot deliver determinism + auditability + provable coverage. Tier 3 because LLMs CAN deliver semantic reasoning that Tier 1 cannot.** Each tier does what the others can't.

**What Tier 3 actually compensates for** (specific gaps Tier 1 has, by design):

| Tier 1 limitation | Tier 3 compensation |
|---|---|
| Cannot reason about unknown wrappers (someone's bespoke `acme_llm.Client().complete()`) | LLM has framework knowledge from training; identifies "this looks like an LLM call" without a hard-coded rule |
| Cannot disambiguate ambiguous calls (`service.call(x)` is RPC vs LLM?) | LLM reads surrounding context and decides |
| Cannot generate per-finding remediation prose | LLM produces context-aware reasoning text |
| Cannot tell if an absent control is really missing or just renamed | LLM sees the whole file and can spot a renamed equivalent |

Tier 3 is **applied surgically** — only on Tier 2 fallback findings (where SNR is worst). Not on Tier 1's high-precision findings, because those don't need triaging. Token spend stays bounded by finding count, not codebase size.

**Failure mode if collapsed to one tier:** either coverage suffers (pure framework rules) or cost / determinism / auditability all explode at once (pure LLM). The three-tier architecture isn't a compromise — it's the only configuration where each property survives.

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

## 4. Why Detect / Defend / Respond taxonomy (with dual mapping to security frameworks)

**Decision:** Every finding carries **two coexisting mappings**:
1. Exactly one D/D/R `category` — AgentShield's own organizing spine (locked in PHASE_I_PLAN §3).
2. Many `framework_mappings` — pointers into external standards (OWASP LLM, OWASP Agentic, NIST AI RMF, MITRE ATLAS, AgentShield Framework v1).

These are complementary, not redundant. Concrete shape from rule [`D001`](./agentshield/rules/detect/D001-unsanitized-user-input-to-llm.yaml):
```yaml
metadata:
  category: detect                          # ← D/D/R bucket: exactly one of detect/defend/respond
  agentshield_id: AS-D-001
  severity_normalized: high
  framework_mappings:                       # ← security framework mappings: many, across multiple standards
    owasp_llm: ["LLM01"]
    owasp_agentic: ["T6"]
    nist_ai_rmf: ["MAP-2.3", "MEASURE-2.7"]
    mitre_atlas: ["AML.T0051"]
    agentshield_v1: []
```

| Mapping | Cardinality | Purpose | Consumer |
|---|---|---|---|
| `category` (D/D/R) | Exactly 1 of 3 | Organizing spine — answers "vulnerability, missing defense, or missing recovery control?" | AgentShield's own report layout (groups findings by D/D/R) |
| `framework_mappings` | Many, multi-standard | Anchors finding to recognized external taxonomies | OWASP scorecards, NIST audit packs, MITRE attack mapping, compliance dashboards |

A finding in the rendered report reads as both at once:
> **AS-D-001** [**Detect**] User input flows into LLM without sanitizer
> Maps to: OWASP LLM01, OWASP Agentic T6, NIST MAP-2.3 + MEASURE-2.7, MITRE ATLAS AML.T0051

**Alternatives considered:**
- *OWASP-only categorization*. Maps cleanly to LLM01–LLM10 but doesn't capture defensive controls or response readiness — only vulnerabilities. Loses the "how is this agent defended?" lens entirely.
- *NIST AI RMF only*. Comprehensive but academic; engineers don't think in MAP / MEASURE / MANAGE / GOVERN day-to-day. Hard to triage findings against.
- *Flat severity-only* (high / med / low). No structural meaning; loses both the operational lens (D/D/R) and the standards-mapping lens.
- *Single mapping (D/D/R only, no frameworks)*. Wins for AgentShield's internal narrative but breaks every external integration — compliance teams need OWASP/NIST mappings to satisfy audit, security ops want MITRE for attack-tree work.
- *Single mapping (frameworks only, no D/D/R)*. Wins for external standards but the report has no organizing spine — engineers see a flat list of OWASP IDs with no narrative for "what's missing in defense vs recovery."

**Why dual mapping wins:**
- D/D/R is the security-ops mental model — vulnerabilities, defenses, recovery. Each bucket answers a distinct operational question. Reports group by this.
- Framework mappings let one finding satisfy multiple compliance/audit frameworks without duplication. Adding a new framework = adding a new key to `framework_mappings`, no rule rewrite.
- Decoupling means changes to AgentShield's own taxonomy (D/D/R) don't churn external mappings, and vice versa. Stable contracts in both directions.

**Failure mode if rejected (single mapping only):**
- D/D/R-only: every external integration becomes a custom translation layer. Compliance teams hand-map findings to their frameworks; brittle and lossy.
- Framework-only: the report has no AgentShield-native narrative — readers can't answer "is this agent defended?" without manually grouping by control type.

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

## 13. Peer SAST tools — where AgentShield sits in the ecosystem

**Decision context:** AgentShield is one of several rule-based static analyzers in the SAST market. This section maps the technology choices against peer tools so the rationale of "why semgrep" extends naturally to "why not SonarQube / CodeQL / Snyk Code."

**The peer set:**

| Tool | Engine | Per-language strategy |
|---|---|---|
| **AgentShield** (this product) | Semgrep — single engine + tree-sitter / pfff parsers | One YAML rule DSL across all languages |
| **SonarQube** | Custom proprietary **SonarSource analyzers** (one per language) | SonarJava, SonarPython, SonarJS/TS, SonarCSharp, SonarKotlin — each is an internal analyzer with its own AST traversal + dataflow |
| **CodeQL** (GitHub) | Datalog over a database of program facts | One pipeline; deeper inter-procedural analysis than the others |
| **Snyk Code** | Custom proprietary engine (formerly DeepCode) | Symbolic-AI hybrid; not semgrep |
| **Semgrep alone** | Same engine AgentShield uses, but with the public/community rule registry | Generic security rules, not agent-specific |

**What AgentShield and SonarQube share** (the closest peer):
- Both are AST-based static analyzers
- Both do AST-pattern matching + intra-procedural dataflow
- Both emit findings with severity, type, location
- Both produce SARIF output (so they target the same downstream integrations: GitHub code-scanning, IDE plugins, etc.)
- Both compete in the SAST market alongside Snyk Code, Veracode, Checkmarx

**Where they differ technically:**
- Sonar's per-language analyzers run **deeper analysis in some areas** — symbolic execution for null-pointer / divide-by-zero detection in Java, type inference, more sophisticated control-flow tracking. Semgrep's intra-procedural taint is competitive; **inter-procedural is weaker** than Sonar's deep Java/C# analysis.
- Semgrep is **rule-portable** — the same YAML works across languages. Sonar's rules are hard-coded into the per-language analyzer (you can't write one rule that targets both Java and Python with the same pattern).
- Sonar has commercial product layers (Quality Gate, Sonar AI Code Assurance for LLM-assisted review, added 2024–2025); semgrep has Semgrep Pro for similar enterprise features.

**Where neither helps directly with agentic AI security:**

This is the key point — **AgentShield's value isn't the choice of engine.** SonarQube, CodeQL, and Snyk Code don't ship agent-specific rules; their rule libraries are general-purpose vulnerabilities (SQL injection, XSS, hard-coded credentials, etc.). Semgrep's open registry has some LLM-related rules but nothing close to a structured D/D/R framework with OWASP LLM / Agentic Top 10 / NIST AI RMF / MITRE ATLAS mapping.

The differentiated value AgentShield delivers, layered on top of any sufficiently capable AST engine:

1. **Agent-specific rule pack** — D001/D002/D003/DF001/DF002/R001 + Java mirrors + fallback rules with import-gate + verb-regex
2. **Dual-mapping schema** — every finding carries D/D/R category AND framework_mappings (OWASP/NIST/MITRE)
3. **Tier 3 LLM judge** — semantic triage of low-confidence findings via pluggable backend
4. **Phase II handoff contract** — SARIF feeding dynamic red-team tools (Promptfoo, Garak, AgentDojo, PyRIT)

The same rule set could in theory be ported to SonarQube's rule format or CodeQL — at the cost of giving up cross-language uniformity (each language would need its own rule reimplementation in Sonar's format) and losing the rapid iteration semgrep's YAML enables.

**Why we picked semgrep specifically over SonarQube / CodeQL:**
- **Cross-language rule reuse**: one YAML pattern covers Python AND Java with `taint` mode. Sonar would require reimplementing each rule per language.
- **Rule iteration speed**: edit a YAML, run, see the result. Sonar custom rules require Java plugin development; CodeQL requires datalog query authoring.
- **License**: semgrep is LGPL-2.1; can ship inside an internal product. SonarQube Community Edition is LGPL but the analyzers are not all OSS.
- **VDI compatibility**: semgrep is a single binary that runs offline. SonarQube needs a server.

**Failure mode if rejected (i.e. if we picked SonarQube instead):**
- Per-language rule reimplementation doubles the rule maintenance cost.
- Rule iteration slows from minutes to days (Java plugin dev cycle).
- Operational overhead of running a Sonar server inside the VDI.
- The dual-mapping schema, three-tier architecture, and LLM-judge contract are tool-agnostic — but the engine choice still affects feasibility.

---

## 14. Open architectural questions (revisit later)

- **Does the judge tier also re-rank Tier 1 findings?** Currently no, to keep the trust boundary clean. Revisit if Tier 1 false-positive rate proves higher than expected.
- **Backend fallback** (e.g., try Copilot, fall back to boto3 on failure)? Currently single-backend-per-scan. Revisit if real-world reliability of any single backend is poor.
- **Should DF001 / R001 absence-detection rules get a fallback tier too?** Likely yes. Deferred until Tier 2 D001 behavior is validated against testbed.
- **Cross-language taint** (Python service calling Java microservice)? Out of scope for Phase I; revisit in Phase II.
- **Rule severity calibration per-repo**? Currently rule severity is fixed in YAML. Some repos may want to tune (e.g., DF001 from WARNING to ERROR). Likely solved via `agentshield.yaml` overrides — not a core architectural change.
