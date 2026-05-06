# AgentShield — Phase I Plan

Status: Approved 2026-05-02
Source brief: [project.md](./project.md)

> **⚠ Historical (2026-05-06).** This is the v0.1 plan from project inception. **Phase F (architecture v2) supersedes Tracks B (LLM judge backends) and D (Tier 4 discovery)** — the judge tier code was deleted in F.6 and discovery was folded into Tier 2's whole-repo Copilot scan. See [`ROADMAP.md` §3.9](./ROADMAP.md#39-phase-f--architecture-v2-2-tiers-copilot-as-scanner) for the v2 phased delivery and [`ARCHITECTURE_V2.md`](./ARCHITECTURE_V2.md) for the current design. The strategic context below (§1-§3 — why the project exists, what it does, the D/D/R taxonomy) remains valid; the Track B/D implementation specifics are obsolete.

---

## 1. Vision

AgentShield is a pre-production security evaluator for AI agents. Input is a source repository (code + infra). Output is a normalized report of security violations, mapped to standard frameworks (OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS, Galileo) and to a custom **AgentShield Framework v1** for findings that don't fit elsewhere.

The product ships as:
- **Phase I** — CLI + Python library, static analysis only.
- **Phase II** — runtime red-teaming (Promptfoo / Garak / AgentDojo / PyRIT), plus a UI for the report.

---

## 2. Hard constraints

These shape every architectural decision below.

- **Runs in a corporate VDI with no outbound internet.** No SaaS calls, no telemetry, no live credential verification.
- **OSS adapters only.** No proprietary tools, no paid platforms.
- **License-clean.** Apache-2.0 / MIT / LGPL only. No AGPL in the dependency graph.
- **Languages for v0.1: Python and Java only.** TypeScript / Rust / Go / others can come later.
- **Static analysis only in Phase I.** No runtime probes against a live agent.
- **Must understand the organization's wrapper SDKs.** Target codebases use **SMARTSDK** (internal wrapper around Google ADK) for agents and **RAG SDK** (internal wrapper around LlamaIndex) for retrieval. Off-the-shelf scanners are blind to these wrappers — AgentShield must not be. See [Section 5a: Wrapper SDKs](#5a-wrapper-sdks-smartsdk--rag-sdk).

---

## 3. The Detect / Defend / Respond taxonomy

Every finding maps to **exactly one** of three buckets:

| Bucket | What it answers | Static evidence |
|--------|-----------------|-----------------|
| **Detect** | Where is the agent flawed / exploitable? | User input flows into prompt without sanitization, system prompts leaked in source, tool functions accept unvalidated args, RAG retrievers pull from untrusted sources. |
| **Defend** | What active defenses are present in the code? | Presence/absence of guardrails libraries (NeMo Guardrails, Llama Guard, Lakera, Rebuff), input/output filters, tool allowlists, sandboxed execution, prompt-injection detectors. |
| **Respond** | What recovery and observability is in place? | Refusal templates, audit logging on every LLM call, rate limits, kill switches, structured error handling around tool failures, alerting/monitoring hooks. |

A finding then maps to an external framework (OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS, Galileo) **or** to **AgentShield Framework v1** when no external mapping exists. AgentShield v1 is where novel, agent-specific checks live that the public frameworks don't yet cover.

---

## 4. Tool set (four tools, all OSS, all offline-capable)

| Tool | License | Role | Offline configuration |
|------|---------|------|------------------------|
| **Semgrep** | LGPL-2.1 | Engine for the AgentShield Pattern DB (Python + Java) | `--config ./local/rules/ --metrics=off` |
| **Trivy** | Apache-2.0 | CVEs in pip + Maven/Gradle dependencies | `--offline-scan --skip-db-update --cache-dir <pre-loaded DB>` |
| **Agentic Radar** | MIT | Python-only agent-framework awareness (LangChain, LlamaIndex, CrewAI, Google ADK) — see caveat below re: SMARTSDK/RAG SDK | No LLM-enrichment flags enabled |
| **Checkov** | Apache-2.0 | IaC (Dockerfiles, Kubernetes, Terraform, GitHub Actions) | `--no-stats`, no `BC_API_KEY` set |

### Tools deliberately not in v0.1

- **Gitleaks / TruffleHog** — secret detection. Deferred to v0.2 because secrets scanning is a well-trodden, non-agent-specific problem likely already covered by the user's enterprise SDLC. v0.1 should focus on what's *unique* to AgentShield.
- **Grype + Syft** — dropped in favor of Trivy alone (one fewer DB to maintain).
- **Promptfoo / Garak / AgentDojo / PyRIT / MCP Scan** — runtime tools, deferred to Phase II.

### Operational note: Trivy DB freshness

Trivy is the only tool with a "stay current" cost. Its vuln DB needs a periodic refresh:

1. On an internet-connected machine, weekly: `trivy fs --download-db-only --cache-dir ./trivy-cache`
2. Tarball the cache directory, transfer through normal VDI file-ingress.
3. Point Trivy at it via `TRIVY_CACHE_DIR`.

A 1-week-old DB is fine for most CVEs; a 3-month-old DB silently misses recent ones. Document this in the README.

---

## 5a. Wrapper SDKs (SMARTSDK + RAG SDK)

The target organization uses two internal wrapper SDKs over public frameworks:

| Wrapper SDK | Wraps | Used for |
|-------------|-------|----------|
| **SMARTSDK** | Google ADK (Agent Development Kit) | Building agents |
| **RAG SDK** | LlamaIndex | Retrieval-augmented generation |

### Why this matters

Off-the-shelf scanners — including Agentic Radar — recognize the upstream frameworks (LangChain, LlamaIndex, Google ADK) but have **zero visibility into private wrappers**. A developer who writes `from smartsdk import Agent; agent.run(user_input)` will produce code that every external tool considers opaque, and every prompt-injection / tool-misuse / RAG-poisoning surface inside that wrapper goes undetected.

This is precisely where AgentShield earns its keep inside the organization. It is the one scanner that can be made wrapper-aware.

### Two-layer detection strategy

Every AgentShield Pattern DB rule targets **both** layers via Semgrep pattern alternatives:

1. **Upstream layer** — the public framework call (Google ADK, LlamaIndex). Catches code that bypasses the wrapper and calls the underlying SDK directly. Mined from Agentic Radar source.
2. **Wrapper layer** — the SMARTSDK / RAG SDK call equivalent. Catches the common case where teams use the corporate wrapper. Authored from internal SDK API surface.

A single rule fires whether the code looks like:
```python
# Upstream: Google ADK
from google.adk import Agent
agent = Agent(...)
agent.run(user_input)                        # AS-D-002 fires

# Wrapper: SMARTSDK
from smartsdk import Agent
agent = Agent(...)
agent.run(user_input)                        # AS-D-002 also fires
```

### What's needed from the organization to author wrapper-aware rules

Authoring requires knowledge of the wrapper API surface. To be collected before / alongside Pattern DB authoring:

1. **Public API surface** — list of imports, top-level classes, common methods for SMARTSDK and RAG SDK. A redacted cheat-sheet or `.pyi` stub file is enough.
2. **Canonical "hello world" examples** — one annotated SMARTSDK agent, one RAG SDK pipeline. The shape of the API is more useful than prose docs.
3. **Variants** — Python only, or Java bindings too? Sync + async? Single-agent / ReAct / multi-agent flavors?
4. **VDI installability** — can `pip install smartsdk` run in our dev environment? If yes, we can introspect for more accurate rules.
5. **Org-published examples or templates** — starter repos, internal cookbooks. These encode the "right way" to call the SDK and give us both positive (defend) and negative (detect) patterns.

### Mining strategy — tiered, deliberately selective

"Best of every tool" produces a Frankenstein with conflicting ontologies. We mine *aggressively* from a few high-yield sources, *lightly* from a couple more for inspiration, and defer the rest. Each source we mine is a source we have to refresh on cadence — keep the list small enough to actually maintain.

#### Internal sources (mandatory — load-bearing for org value)

| Source | License | What we extract |
|--------|---------|-----------------|
| **SMARTSDK API surface + examples** | Internal | Wrapper-layer pattern alternatives for every Pattern DB rule. Without this, AgentShield is blind to the org's most important code paths. |
| **RAG SDK API surface + examples** | Internal | Wrapper-layer pattern alternatives for retrieval-related rules. |

#### Tier 1 — mine directly into Pattern DB (do this first)

| Source | License | What we extract | Why now |
|--------|---------|-----------------|---------|
| **Agentic Radar** | MIT | Static detection rules → re-author as Semgrep for Python+Java, both upstream (Google ADK / LlamaIndex) and SMARTSDK / RAG SDK layers | Same modality (static), same target (agent code). Highest signal-per-hour of any source. |
| **Promptfoo plugins** | MIT | Attack taxonomy — each plugin category becomes a static detector for code that looks vulnerable to that class | Best curated catalog of "what attack classes matter." We translate runtime knowledge into static patterns. |
| **DeepTeam** | Apache-2.0 | Their OWASP / NIST framework mapping work | They've already done the compliance-mapping labor. Direct save on our framework YAML tables. |

#### Tier 2 — read once for taxonomy, do not vendor

| Source | License | What we extract | Caveat |
|--------|---------|-----------------|--------|
| **AgentDojo** | **AGPL-3.0** | Attack-scenario taxonomy in tool-calling environments | Read-only. Do NOT vendor or link. Reading for inspiration is fine; distributing derived code is not. |
| **Giskard** | Apache-2.0 | RAG-specific checks (retriever bias, document trust) | Worth mining now precisely because the org uses RAG SDK. |
| **MCP Scan** | varies | MCP server static patterns | Only useful if SMARTSDK / org agents use MCP. Skip until confirmed. |

#### Tier 3 — defer to Phase II (runtime)

| Source | Why defer |
|--------|-----------|
| **Garak** | Foundation-model probes, not agent-level. Most probes have no meaningful static analog. Reactivate when we add runtime in Phase II. |
| **PyRIT** | Research-grade scriptable framework. Useful for bespoke multi-turn attacks at runtime; little to mine for static. |

#### Tier 4 — discovery channel, not a source

| Source | Use |
|--------|-----|
| **TalEliyahu/Awesome-AI-Security** | The index flagged in `project.md`. Don't mine — *use*. Quarterly: re-scan the list for new tools that might join Tier 1 or 2. |

#### Public spec sources (always)

| Source | What we extract |
|--------|-----------------|
| OWASP LLM Top 10, NIST AI RMF, MITRE ATLAS, Galileo | Framework mapping IDs and rule scope. |
| Public incident reports | Real-world failures we want to catch. |

### Mining cadence

One-time extraction now, **quarterly refresh** thereafter. We do not depend on any of these projects' code; we read, extract patterns, and re-author as Semgrep rules with our own metadata schema. The output ontology is single and consistent: Detect/Defend/Respond + framework mappings. The inputs may be diverse; the output never is.

### Diminishing returns

Tier 1 alone (Agentic Radar + Promptfoo + DeepTeam) likely covers ~80% of useful agent-security patterns. Tier 2 adds marginal coverage but multiplies maintenance. Resist adding more sources without a concrete gap they uniquely fill.

---

## 5. The AgentShield Pattern DB (the product's IP)

This is the artifact that makes AgentShield different from a generic SAST wrapper. It is a curated set of **Semgrep rules** tagged with our Detect/Defend/Respond category and framework mappings.

### Two distinct meanings of "vulnerability database"

| Concept | Source | Approach |
|---------|--------|----------|
| **CVE data for dependencies** (Log4Shell, etc.) | NVD / OSV / GHSA | **Do NOT reinvent.** Use Trivy's curated DB, ship it offline. |
| **Agent-specific anti-pattern catalog** | Mined from OSS projects | **This IS our IP.** Author original Semgrep rules informed by Agentic Radar + Promptfoo. |

### Sourcing

The full mining strategy lives in [Section 5a](#5a-wrapper-sdks-smartsdk--rag-sdk). We do **not** vendor any external project's code — we read, learn, and author original Semgrep rules with our own schema and metadata.

### Rule organization

```
agentshield/rules/
├── detect/
│   ├── unsanitized-prompt-input.yaml         (py + java)
│   ├── system-prompt-leaked-in-source.yaml   (py + java)
│   ├── tool-without-input-schema.yaml        (py + java)
│   └── rag-from-untrusted-source.yaml        (py + java)
├── defend/
│   ├── no-input-guardrail.yaml
│   ├── no-output-filter.yaml
│   ├── tool-execution-not-sandboxed.yaml
│   └── no-allowlist-on-tools.yaml
└── respond/
    ├── no-audit-logging-around-llm-call.yaml
    ├── no-rate-limit-on-agent-endpoint.yaml
    ├── no-refusal-template.yaml
    └── no-error-handling-around-tool.yaml
```

Each rule's metadata block carries:
```yaml
metadata:
  category: detect | defend | respond
  agentshield_id: AS-D-002
  framework_mappings:
    owasp_llm: [LLM01]
    nist_ai_rmf: [MAP-2.3]
    mitre_atlas: [AML.T0051]
    galileo: []
    agentshield_v1: []      # populated only when no external mapping exists
  languages: [python, java]
```

---

## 6. Findings schema

Every adapter normalizes to this canonical record:

```yaml
id: AS-D-002
title: "Unsanitized user input flows directly into LLM call"
category: detect              # detect | defend | respond
severity: high                # critical | high | medium | low | info
source_tool: semgrep
source_rule_id: agentshield.detect.unsanitized-prompt-input
framework_mappings:
  owasp_llm: ["LLM01"]
  nist_ai_rmf: ["MAP-2.3"]
  mitre_atlas: ["AML.T0051"]
  galileo: []
  agentshield_v1: []
evidence:
  file: src/agent/handler.py
  line: 47
  snippet: "..."
remediation: "..."
references: ["https://..."]
```

This schema is the single source of truth — every adapter must produce records that conform to it before they reach the framework-mapping engine.

---

## 7. Architecture

```
                       AgentShield (Phase I)

  ┌────────────────────────────────────────────────────────────────┐
  │                        INPUT                                   │
  │   Local repo path  OR  pre-cloned source  (Python and/or Java) │
  └─────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                  REPO INSPECTION                               │
  │  • Language detection (.py / .java, requirements.txt, pom.xml, │
  │    build.gradle)                                               │
  │  • Agent framework detection:                                  │
  │      - Wrappers:  SMARTSDK, RAG SDK   (org-internal, priority) │
  │      - Upstream:  Google ADK, LlamaIndex, LangChain,           │
  │                   LangChain4j, Spring AI, CrewAI,              │
  │                   OpenAI / Anthropic SDK                       │
  │  • Decide which adapters to enable                             │
  └─────────────────────────────┬──────────────────────────────────┘
                                │
       ┌────────────────────────┼─────────────────────┬──────────────────┐
       ▼                        ▼                     ▼                  ▼
 ┌──────────────────┐  ┌────────────────┐  ┌──────────────────┐  ┌──────────────┐
 │ Semgrep adapter  │  │ Trivy adapter  │  │ Agentic Radar    │  │ Checkov      │
 │                  │  │                │  │ (Python only)    │  │ adapter      │
 │ runs:            │  │ runs:          │  │                  │  │              │
 │  AgentShield     │  │ trivy fs       │  │ static scan of   │  │ IaC scan     │
 │  Pattern DB      │  │ --offline-scan │  │ LangChain /      │  │ (Docker,     │
 │  (py + java)     │  │ --skip-db-     │  │ LlamaIndex /     │  │ K8s, TF,     │
 │                  │  │ update         │  │ CrewAI graphs    │  │ GH Actions)  │
 │  Local-only,     │  │                │  │                  │  │              │
 │  no metrics      │  │ Pre-loaded     │  │ No LLM-enrich    │  │ --no-stats   │
 │                  │  │ vuln DB        │  │ flag             │  │              │
 └────────┬─────────┘  └───────┬────────┘  └──────┬───────────┘  └──────┬───────┘
          │                    │                  │                     │
          └────────────────────┴────────┬─────────┴─────────────────────┘
                                        │
                                        ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                    NORMALIZATION                               │
  │   Each adapter's raw output  →  canonical Finding records      │
  │   (id, category, severity, source_tool, evidence, ...)         │
  └─────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────────┐
  │             FRAMEWORK MAPPING ENGINE                           │
  │   Each finding → Detect | Defend | Respond  (mandatory)        │
  │   Each finding → external frameworks via YAML mapping tables:  │
  │     OWASP LLM Top 10 · NIST AI RMF · MITRE ATLAS · Galileo     │
  │   Findings with no external mapping → AgentShield Framework v1 │
  └─────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
  ┌────────────────────────────────────────────────────────────────┐
  │                      REPORTERS                                 │
  │   JSON     (canonical, for CI)                                 │
  │   Markdown (for PR comments / human review)                    │
  │   SARIF    (optional, for IDE / GitHub code-scanning)          │
  └────────────────────────────────────────────────────────────────┘

                           CLI surface
                  agentshield scan ./repo \
                      --format md,json \
                      --output ./report/

                           Library surface
                  from agentshield import scan
                  report = scan("./repo")
```

---

## 8. Repository layout

```
agentshield/
├── pyproject.toml
├── README.md
├── PHASE_I_PLAN.md                  (this file)
├── project.md                       (original brief)
└── agentshield/
    ├── cli.py                       # agentshield scan <repo>
    ├── core/
    │   ├── findings.py              # pydantic Finding schema
    │   ├── pipeline.py              # repo inspect → adapters → normalize → report
    │   └── repo.py                  # language + agent-framework detection
    ├── adapters/                    # one file per scanner; same interface
    │   ├── base.py                  # Adapter ABC
    │   ├── semgrep.py
    │   ├── trivy.py
    │   ├── agentic_radar.py
    │   └── checkov.py
    ├── frameworks/                  # rule_id → framework entry mapping tables
    │   ├── owasp_llm.yaml
    │   ├── nist_ai_rmf.yaml
    │   ├── mitre_atlas.yaml
    │   ├── galileo.yaml
    │   └── agentshield_v1.yaml
    ├── rules/                       # AgentShield Pattern DB (Semgrep)
    │   ├── detect/
    │   ├── defend/
    │   └── respond/
    └── reporters/
        ├── json.py
        ├── markdown.py
        └── sarif.py
```

---

## 9. Sequenced work plan — compressed to one week (decided 2026-05-02)

v0.1 ships in 5 working days as a deliberately narrow thin slice. Everything outside the scope below moves to v0.2. VDI testing happens **in parallel, same-day**, not at the end.

### v0.1 scope (in)
- Python only (Java deferred to v0.2)
- ~6 Semgrep rules across Detect / Defend / Respond
- Two adapters: Semgrep + Trivy
- Agentic Radar adapter if time permits Day 4
- Wrapper-layer rules (SMARTSDK / RAG SDK) added Day 4 **if SDK API surface arrives by end of Day 2**
- JSON + Markdown reporters
- CLI on local paths
- VDI bundle (single tarball)
- Framework mappings: OWASP LLM Top 10 only

### v0.1 scope (out — defer to v0.2)
Java support · Checkov / IaC · DeepTeam mining · SARIF reporter · GitHub URL cloning · NIST AI RMF / MITRE ATLAS / Galileo mapping coverage · Gitleaks · 12+ rules

### Day-by-day

| Day | Build (dev) | VDI test (parallel, same-day) |
|-----|-------------|--------------------------------|
| **Mon (Day 1)** | Findings schema (pydantic) · framework mapping loader (YAML) · pipeline (local path, lang detect) · Semgrep adapter · 2 starter rules (1 Detect + 1 Defend, Python upstream) · CLI scaffold (`agentshield scan <path> --format json`) | Stand up VDI environment · ingest first bundle · scan a throwaway Python repo · confirm `agentshield scan` works fully offline |
| **Tue (Day 2)** | 4 more rules (mix of Detect/Defend/Respond, Python upstream) · Markdown reporter · VDI bundle v0 packaging script | Install bundle end-to-end · scan a real SMARTSDK repo · report what fires correctly vs. noisily |
| **Wed (Day 3)** | Trivy adapter · Trivy DB snapshot ingestion · OWASP LLM Top 10 framework mapping seeded · severity calibration based on Tue VDI feedback | Validate offline Trivy DB · scan SMARTSDK repo for CVEs in pip deps · validate report renders cleanly |
| **Thu (Day 4)** | Agentic Radar adapter · **wrapper-layer rules added** (SMARTSDK / RAG SDK alternatives — assumes API surface arrived by end of Day 2) · re-tune rules from VDI feedback | Validate SMARTSDK detection on real repo · check false positive rate · report blockers |
| **Fri (Day 5)** | Final severity tuning · README + install guide · ship final v0.1 VDI bundle | Run scan on 2–3 real SMARTSDK repos · capture demo report |

### Hard dependencies (must land or scope shrinks further)

1. **SMARTSDK + RAG SDK API surface** received by end of Day 2. If slips → v0.1 ships upstream-only (~30% useful coverage on org repos).
2. **Real SMARTSDK repo available in VDI** by Tuesday morning. A toy test repo is not enough — rule calibration needs realistic code shape.
3. **Same-day VDI testing**, not end-of-week batches. Each day's build needs feedback by next morning.

### Two risks to watch

- **Rule quality > rule count.** 6 well-tuned rules beat 20 noisy ones; the latter destroys adoption. If a rule is too noisy in VDI on Tue, kill it that day rather than ship it.
- **Defend / Respond rules are absence-detection** — higher false-positive risk by nature. Start them at `severity: medium` (not `high`) and let VDI feedback promote them.

---

## 10. Distribution: VDI bundle

To make ingress into the VDI clean, ship AgentShield as a single tarball:

```
agentshield-vdi-bundle.tar.gz
├── wheels/                       # Python wheels for offline pip install
│   └── ...
├── binaries/                     # Static Go binaries
│   ├── trivy
│   └── (gitleaks deferred to v0.2)
├── rules/                        # Semgrep rule packs (AgentShield Pattern DB)
├── frameworks/                   # Framework mapping YAMLs
├── trivy-db/                     # Pre-downloaded Trivy vuln DB snapshot
└── install.sh                    # pip install --no-index --find-links wheels/ agentshield
```

One `tar -xf` plus one `./install.sh` and AgentShield runs. No internet required at any step.

Docker image is a secondary distribution option for VDIs that permit container runtimes.

---

## 11. Risks to watch

- **Cross-language rule coverage will be uneven.** Python is rich (LangChain, OpenAI SDK, Anthropic SDK, LlamaIndex); Java is thinner (LangChain4j, Spring AI). Honest expectation: Python repos get full coverage; Java repos get baseline-only (deps, IaC, generic LLM-call patterns) plus whatever Java-specific rules we author. Set this expectation in the README.
- **Wrapper SDK drift.** SMARTSDK and RAG SDK will evolve. Wrapper-layer rules need a refresh process (re-read API surface each minor SDK release, regenerate alternatives). Treat the wrapper rule pack like a living document, not a one-time port.
- **Wrapper visibility gap before authoring.** Until SMARTSDK/RAG SDK rules exist, scans of org repos will under-report findings on the most important code paths — the ones using the corporate wrapper. Be loud about this in the report header until coverage exists.
- **Defend and Respond are absence-detection.** Flagging "you don't have X" generates more noise than flagging "you have a bug." Calibrate severity carefully so an agent that legitimately doesn't need rate-limiting isn't drowned in low-confidence warnings.
- **Static can't confirm exploitability.** Every Detect finding is "pattern suggests vulnerability." Phase II runtime probes are what convert these into proven exploits. Be honest about this in the report.
- **Trivy DB staleness.** The only ongoing operational cost. Document the refresh process clearly; consider an "DB age" warning in the report header.

---

## 12. Out of scope for Phase I (so we don't drift)

- Runtime red-teaming (Phase II — Promptfoo / Garak / AgentDojo / PyRIT / MCP Scan)
- UI for the report (Phase II)
- TypeScript / Rust / Go support
- Gitleaks / secret detection (v0.2)
- GitHub Copilot extension wrapper (Phase II — same library, thin shim)
- Cloning from GitHub URLs in v0.1 (operate on already-cloned local paths first; URL fetch is trivial to add later but VDI ingress means most users will pre-clone anyway)
- **Agent-based scanner core** (rejected — see §13)

---

## 13. Agent-based augmentation (Phase II backlog, not Phase I)

### Decision: deterministic core, optional agent layer

The scanner itself stays deterministic (Semgrep + Trivy + Agentic Radar + Checkov producing canonical JSON findings). An agent-based scanner — i.e. instructing GitHub Copilot / Claude Code / Cursor via a `skill.md` or `agent.md` to "read this repo and report agent-security violations" — was considered and **rejected for the core** because:

| Constraint | Failure mode of agent-based core |
|------------|----------------------------------|
| **VDI with no outbound internet** | Hard blocker. All AI coding assistants need to call their model backends. The scanner literally cannot execute in its target environment. |
| **Auditability for compliance** | "Why did the AI flag this and not that?" has no defensible answer. A Semgrep rule has an explicit pattern; AI reasoning is opaque. |
| **Determinism** | Same code, different scans → different findings. Breaks CI/CD integration and compliance reporting. |
| **Speed and cost** | Seconds vs. minutes-to-hours; zero marginal cost vs. thousands of API calls per scan. |
| **Hallucination** | Agents invent findings or miss real ones. False confidence is worse than no scanner. |

### Where agent augmentation *does* fit (Phase II addition)

Once the deterministic v0.1 scanner exists, ship a thin `skill.md` (one for GitHub Copilot, equivalents for Claude Code / Cursor) that takes the AgentShield JSON report and provides AI-powered:

- **Plain-English explanation** of each finding ("here's why AS-D-002 fired on `handler.py:47`")
- **Codebase-aware fix suggestions** — the agent reads the repo for context, then proposes a concrete patch
- **Triage / prioritization** — "of these 12 findings, fix these 3 first because…"
- **Drafting a remediation PR** — turn findings into a branch + PR description automatically

This runs **outside** the VDI (developer laptop, GitHub Actions, Phase II UI) where internet is available. It is pure additive value: no constraints break, the deterministic scan remains the source of truth, and the agent only operates on already-produced findings.

Estimated effort: 1–2 days once v0.1 exists. Add to v0.2 backlog.

### Same pattern as the broader industry

Snyk, Veracode, GitHub Advanced Security all ship "deterministic scan + AI explainer" — none put the scanner itself behind an LLM. Following that split is well-trodden, not contrarian.
