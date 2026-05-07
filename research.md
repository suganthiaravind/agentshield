# AgentShield — Research & References

Status: 2026-05-06
Companion to: [README.md](./README.md), [ROADMAP.md](./ROADMAP.md), [ARCHITECTURE_V2.md](./ARCHITECTURE_V2.md), [GLOSSARY.md](./GLOSSARY.md). Per-rule detail lives in the **Reference tab** of any generated HTML report.

This document is the **forward-looking reference** for AgentShield: the security frameworks AgentShield maps findings to, the Detect / Defend / Respond taxonomy that organises every finding, and the open-source AI agent security tools that complement (or compete with) AgentShield.

For per-rule detail (what each Semgrep rule, Copilot check, and AST10 manifest rule looks for, with suppressors and framework mappings), open the **Reference tab** in any generated HTML report — `agentshield merge --output-html report.html` produces it. The print-friendly stacked variant is `report-print.html`. The raw Tier 2 checklist source is at [`agentshield/skills/tier2_checklist.md.tmpl`](./agentshield/skills/tier2_checklist.md.tmpl).

## Contents

- [1. Why AgentShield exists — the gap](#1-why-agentshield-exists--the-gap)
- [2. Security frameworks AgentShield maps findings to](#2-security-frameworks-agentshield-maps-findings-to)
  - [2.1 OWASP LLM Top 10 v2 (2025)](#21-owasp-llm-top-10-v2-2025)
  - [2.2 OWASP Agentic AI Top 10](#22-owasp-agentic-ai-top-10)
  - [2.3 MITRE ATLAS](#23-mitre-atlas)
  - [2.4 CWE first-class concerns](#24-cwe-first-class-concerns)
  - [2.5 NIST AI RMF](#25-nist-ai-rmf)
- [3. The Detect / Defend / Respond taxonomy](#3-the-detect--defend--respond-taxonomy)
- [4. Open-source AI-agent security tools](#4-open-source-ai-agent-security-tools)
  - [4.1 Static / pre-runtime](#41-static--pre-runtime)
  - [4.2 Runtime red-teaming](#42-runtime-red-teaming)
  - [4.3 How they fit together — the suggested stack](#43-how-they-fit-together--the-suggested-stack)
- [5. JPMC SAIGE Agent Tier classification](#5-jpmc-saige-agent-tier-classification)
- [6. Further reading & awesome lists](#6-further-reading--awesome-lists)

---

## 1. Why AgentShield exists — the gap

The AI agent security tooling landscape splits into two camps:

- **Traditional SAST** (CodeQL, Snyk, SonarQube) — strong for OWASP-Top-10 web vulnerabilities and supply-chain CVEs, but blind to LLM/agent-specific risks (prompt injection, tool misuse, missing guardrails, agent-orchestration anti-patterns). Their pattern languages aren't extended for "user input flows into `chain.invoke`."
- **Runtime red-teaming** (Promptfoo, Garak, PyRIT, AgentDojo) — strong for probing live agents with adversarial prompts, but require a deployed agent to attack. They can't tell you what's wrong with agent code *before* you ship it; they can't catch hardcoded credentials or untrusted document loaders.

**AgentShield fills the pre-deployment gap.** It is a **pre-production** evaluator: scan the GitHub repo of your agent code + infra, get a unified report mapping findings to OWASP / Agentic / MITRE / CWE before you deploy. v2 (2026-05-06) does this in two tiers:

- **Tier 1 — semgrep** with a 6-family high-precision rule pack (D001-fw, D003, D004, D005, D008, DF003). Narrow taint or narrow regex by construction, deterministic, sub-second on typical scans, no network egress.
- **Tier 2 — LLM-as-scanner via Copilot** in the user's IDE. A comprehensive 56-check skill file (covering OWASP LLM Top 10 v2 + Agentic AI Top 10 + MITRE ATLAS + 10 first-class CWEs + 5 codebase-validated gaps) gets emitted into `<repo>/.agentshield/`; Copilot reads it, walks every source file, writes findings to `tier2-findings.json`. No AWS dep.

The unified `agentshield merge` report combines both tiers + a Tier-2-cross-checked verdict on each Tier 1 finding (TP / CD / FP).

**Where AgentShield deliberately does not compete:** runtime probing of live agents (use Promptfoo / Garak / AgentDojo), supply-chain CVE scanning of dependencies (use Trivy or similar — a future integration documented in [ROADMAP.md §5.5](./ROADMAP.md)), or general-purpose web/infrastructure SAST (use CodeQL / Snyk).

---

## 2. Security frameworks AgentShield maps findings to

Every AgentShield finding carries pointers into multiple external taxonomies via its `framework_mappings` block. The dual-mapping pattern: a finding has **exactly one** D/D/R category (AgentShield's organising spine — see §3) plus **many** external mappings (OWASP / Agentic / NIST / MITRE / CWE). This lets a single finding tell different consumers different things — a compliance team sees "this satisfies OWASP LLM01 + NIST MAP-2.3," a security engineer sees "this is a Detect rule firing on a missing input filter."

For per-rule detail of which framework items each rule maps to, open the **Reference tab** of any generated HTML report — every card lists its full framework chip set inline. Or browse to **Frameworks tab → click any framework item** to drill down to the rules that touch it.

### 2.1 OWASP LLM Top 10 v2 (2025)

The current OWASP Top 10 for LLM Applications. AgentShield aims for full coverage across the two tiers — Tier 1 hits the testable subset; Tier 2 (Copilot) covers the contextual / reasoning items that static rules can't reach (LLM09 in particular).

| OWASP item | What it is | AgentShield coverage |
|---|---|---|
| **LLM01 — Prompt Injection** | Attacker hides instructions inside user input that the LLM treats as commands | Tier 1: D001-fw (taint analysis: HTTP/Lambda input → LLM call without sanitiser). Tier 2: TIER2-LLM01-01/02/03 (direct, indirect via document loader, system-prompt override) |
| **LLM02 — Sensitive Information Disclosure** | Sensitive data in prompts, logs, or LLM output | Tier 1: D005 (hardcoded credentials). Tier 2: TIER2-LLM02-01/02/03/04 (creds, PII in prompt, raw I/O in logs, output to SNS/email/HTTP sinks without scrubbing) |
| **LLM03 — Supply Chain** | Compromised models, plugins, datasets | Tier 2: TIER2-LLM03-01 (unpinned model loading), TIER2-LLM03-02 (untrusted plugin/tool registration) |
| **LLM04 — Data and Model Poisoning** | Training-data / fine-tuning input poisoning | Tier 2: TIER2-LLM04-01 (RAG corpus / fine-tune ingest from untrusted sources) |
| **LLM05 — Improper Output Handling** | LLM output flows into a code-execution sink without validation | Tier 1: D004 (taint: LLM output → eval/exec/Runtime.exec/SQL). Tier 2: TIER2-LLM05-01/02 (code-exec sink, HTML/Markdown render without escaping) |
| **LLM06 — Excessive Agency** | Agent has broader tool permissions than necessary | Tier 1: D003 (code-execution tools). Tier 2: TIER2-LLM06-01/02/03 (destructive verb naming, broad permissions, missing args schema) |
| **LLM07 — System Prompt Leakage** | System prompt exposed via logs / responses / errors | Tier 2: TIER2-LLM07-01 (system prompt logged or returned in response) |
| **LLM08 — Vector and Embedding Weaknesses** | Embedding model issues, RAG cross-tenant leaks | Tier 2: TIER2-LLM08-01/02 (unpinned embeddings, vector store query without auth boundary) |
| **LLM09 — Misinformation** | Model emits unverified info to downstream consumer | Tier 2: TIER2-LLM09-01 (no confidence signal surfaced — info severity, reviewer judgment) |
| **LLM10 — Unbounded Consumption** | No timeout / token cap; cost / DoS risk | Tier 1: DF003 (timeout=None, max_tokens=None, Duration.ZERO). Tier 2: TIER2-LLM10-01/02/03 (no timeout, no audit logging, no guardrails) |

Reference: https://genai.owasp.org/

### 2.2 OWASP Agentic AI Top 10

OWASP's threat catalogue specifically for **multi-step agent codebases** (planners, tool callers, memory). T1–T11. AgentShield's Tier 2 covers all 11 (some are out of static-rule scope by design — alignment / identity threats).

| Item | Threat | AgentShield coverage |
|---|---|---|
| **T1** | Memory Poisoning | Tier 2: TIER2-AGENTIC-T1-01 (long-term memory write of unvalidated user input or LLM output) |
| **T2** | Tool Misuse | Tier 1: D003. Tier 2: TIER2-AGENTIC-T2-01/02 (code-exec tool, tool argument injection) |
| **T3** | Privilege Compromise | Tier 2: TIER2-AGENTIC-T3-01 (agent runs with broader perms than user) |
| **T4** | Resource Overload | Tier 1: DF003. Tier 2: TIER2-AGENTIC-T4-01/02 (unbounded recursion, no tool timeout) |
| **T5** | Cascading Hallucinations | Tier 2: TIER2-AGENTIC-T5-01 (multi-step pipeline, LLM-A → LLM-B without verification — surfaced as a TP on the `moip-cost-anomaly-probe-lambda` 12-step pipeline) |
| **T6** | Intent Breaking & Goal Manipulation | Tier 1: D001-fw. Tier 2: TIER2-AGENTIC-T6-01 (goal manipulation via tool description) |
| **T7** | Misaligned & Deceptive Behaviours | Tier 2: TIER2-AGENTIC-T7-01 (no alignment-evaluation hook — info severity, reviewer judgment) |
| **T8** | Repudiation & Untraceability | Tier 2: TIER2-AGENTIC-T8-01 (no audit trail of agent decisions / tool calls / planner outputs) |
| **T9** | Identity Spoofing & Impersonation | Tier 2: TIER2-AGENTIC-T9-01 (agent-to-system auth uses static token, not short-lived credentials) |
| **T10** | Overwhelming HITL | Tier 2: TIER2-AGENTIC-T10-01 (HITL approval fatigue from over-gating routine actions) |
| **T11** | Unexpected RCE / Code Attacks | Tier 1: D003, D004. Tier 2: TIER2-AGENTIC-T11-01 (deserialisation of untrusted data) |

Reference: https://genai.owasp.org/llm-top-10-for-agentic-ai/

### 2.3 MITRE ATLAS

ML-attack-specific techniques. AgentShield's Tier 2 references 6 ATLAS techniques most relevant to LLM applications.

| Technique | Description | AgentShield coverage |
|---|---|---|
| **AML.T0010** | ML Supply Chain Compromise | Tier 2: TIER2-ATLAS-T0010-01 (cross-references LLM03-01) |
| **AML.T0011** | User Execution (LLM Plugin) | Tier 2: TIER2-ATLAS-T0011-01 (cross-references LLM06-01) |
| **AML.T0019** | Publish Poisoned Datasets | Tier 2: TIER2-ATLAS-T0019-01 (CI publishing fine-tune corpora without signing) |
| **AML.T0024** | Exfiltration via ML Inference API | Tier 2: TIER2-ATLAS-T0024-01 (raw model internals returned to untrusted callers) |
| **AML.T0050** | Command and Scripting Interpreter | Tier 1: D004. Tier 2: TIER2-ATLAS-T0050-01 (cross-references LLM05-01 / AGENTIC-T2-01) |
| **AML.T0053** | LLM Plugin Compromise | Tier 2: TIER2-ATLAS-T0053-01 (plugin loading without signature verification) |

Reference: https://atlas.mitre.org/

### 2.4 CWE first-class concerns

Generic Common Weakness Enumeration items that apply directly to LLM/agent code. AgentShield surfaces 10 CWEs first-class (carrying them on findings' `framework_mappings.cwe`).

| CWE | Name | Tier 1 / Tier 2 coverage |
|---|---|---|
| **CWE-78** | OS Command Injection | Tier 1: D003, D004. Tier 2: TIER2-CWE-78-01 |
| **CWE-89** | SQL Injection | Tier 1: D004. Tier 2: TIER2-CWE-89-01 |
| **CWE-94** | Code Injection | Tier 1: D003, D004. Tier 2: TIER2-CWE-94-01 |
| **CWE-200** | Information Exposure | Tier 2: TIER2-CWE-200-01 (verbose error responses, internal IDs in logs) |
| **CWE-400** | Resource Consumption (DoS) | Tier 1: DF003. Tier 2: TIER2-CWE-400-01 |
| **CWE-494** | Download of Code Without Integrity Check | Tier 2: TIER2-CWE-494-01 (cross-references LLM03-01) |
| **CWE-532** | Log Information Exposure | Tier 2: TIER2-CWE-532-01 (cross-references LLM02-03) |
| **CWE-732** | Incorrect Permission Assignment | Tier 2: TIER2-CWE-732-01 (cross-references LLM06-02) |
| **CWE-798** | Hardcoded Credentials | Tier 1: D005. Tier 2: TIER2-CWE-798-01 |
| **CWE-829** | Inclusion of Functionality from Untrusted Source | Tier 2: TIER2-CWE-829-01 (cross-references LLM03 / LLM08) |

Reference: https://cwe.mitre.org/

### 2.5 NIST AI RMF

NIST AI Risk Management Framework subcategories that AgentShield references in rule metadata. Not enforced as a primary mapping (Tier 2 doesn't reference these directly), but Tier 1 rule YAMLs carry NIST AI RMF subcategory IDs in `framework_mappings.nist_ai_rmf` for org-level reporting.

Subcategories AgentShield references (5 total): MAP-2.3 (Categorize AI risks), MEASURE-2.6 (Trustworthy AI characteristics), MEASURE-2.7 (Resilience and security), MANAGE-2.4 (Risk treatment), MANAGE-3.1 (Incident response).

Reference: https://www.nist.gov/itl/ai-risk-management-framework

---

## 3. The Detect / Defend / Respond taxonomy

AgentShield's organising spine — every finding belongs to **exactly one** of these three buckets.

### Detect — vulnerability surfaces

> "Where is the agent exploitable?"

A *Detect* finding is a static signature of something an attacker can reach: user input flowing into an LLM without sanitisation, a tool that accepts unvalidated arguments, a RAG retriever pulling from untrusted sources. The bug exists whether or not the agent is running; the finding says "this is broken."

**In AgentShield:** rule IDs start with `D` (e.g. `AS-D-001`). Active Tier 1 rules: D001-fw (unsanitized user input → LLM), D003 (code-execution tool registered), D004 (LLM output → code-exec sink), D005 (hardcoded credentials), D008 (untrusted system prompt).

### Defend — missing controls

> "What active defenses are present, and what's missing?"

A *Defend* finding doesn't say a vulnerability exists — it says a defensive layer that *should* exist *doesn't*. No timeout on the LLM call. No `args_schema` on a registered tool. No guardrail wrapper. *Defend findings are absence detection.*

**In AgentShield:** rule IDs start with `DF`. Active Tier 1 rules: DF003 (no timeout / max_tokens cap on LLM client). Retired in F.2 because absence-detection is FP-prone in static analysis: DF001 (no guardrails import), DF002 (no `@Tool` args schema), DF004 (destructive verb naming) — those moved to Tier 2 where Copilot can read full file context to judge whether the absence is real.

### Respond — observability gaps

> "If something goes wrong, can you tell, and can you respond?"

A *Respond* finding says the operational layer is missing: no audit logging on LLM invocations, no tracing, no kill switches, no rate limits. These are the controls you need *after* an incident — for forensics, blast-radius containment, and learning.

**In AgentShield:** rule IDs start with `R`. Active Tier 1 rules: none (R001 retired in F.2 because Phase E.2 showed ~50% FP rate even after relaxing for Lombok `@Slf4j` + stdlib `logger = logging.getLogger(...)`). Coverage moved to Tier 2: TIER2-LLM10-02 reads file context to judge whether structured audit logging is present.

### Why D/D/R, not just OWASP categories?

OWASP LLM Top 10 mixes "vulnerability surface" items (LLM01 prompt injection) with "missing-control" items (LLM10 unbounded consumption is half a vulnerability, half an absence). A **single security report** that wants to say "show me everything an attacker could exploit (Detect) vs everything we should add to harden the system (Defend) vs everything we need for incident response (Respond)" needs an organising axis that isn't OWASP itself. D/D/R is that axis.

The dual-mapping pattern (one D/D/R category + many framework mappings per finding) means a single finding tells different consumers different things — see §2 introduction.

---

## 4. Open-source AI-agent security tools

The ecosystem AgentShield is part of. Each tool below has its own niche; AgentShield aims to complement, not replace.

### 4.1 Static / pre-runtime

#### Agentic Radar — pre-runtime scanner for agent code
- **Repo:** https://github.com/agentic-radar/agentic-radar
- **License:** MIT
- **Specialty:** static analysis of agent code/workflows. Per-framework analyzers (LangGraph, CrewAI, AutoGen, OpenAI Agents, n8n) parse with Python AST and detect which **predefined tools** the agent registers; a central `mapper/vulnerabilities.json` catalogues which vulnerabilities each tool category inherits.
- **Detection model:** "import detection + categorical vulnerability inheritance." E.g. import `WebBaseLoader` → inherits SSRF + Indirect-Prompt-Injection; import `PythonREPL` → inherits Arbitrary-Code-Execution.
- **Where it overlaps with AgentShield:** Tool-import-based detection for OWASP LLM01/LLM05/LLM08 categories. Agentic Radar is **structural / import-based**, NOT **code-pattern-based**.
- **Where AgentShield differs:** AgentShield's Tier 1 does dataflow taint analysis (semgrep `mode: taint`), not just import detection. AgentShield's Tier 2 (Copilot LLM-as-scanner) covers the contextual reasoning Agentic Radar's static AST walker can't reach.
- **Best use:** run alongside AgentShield. Agentic Radar's tool inventory complements AgentShield's per-call-site rules; both surface different signals.

#### Trivy — supply-chain scanner
- **Repo:** https://github.com/aquasecurity/trivy
- **License:** Apache 2.0
- **Specialty:** dependency CVEs, SBOM generation, IaC misconfiguration scanning.
- **Where it overlaps with AgentShield:** None directly — AgentShield doesn't scan `requirements.txt` / `pom.xml` for dependency CVEs.
- **Best use:** run before AgentShield to catch known-vulnerable LLM SDK versions (LangChain CVEs, etc.). Documented in [ROADMAP.md §5.5](./ROADMAP.md) as a planned integration (Track F).

### 4.2 Runtime red-teaming

#### Promptfoo — CLI/CI red-team with compliance mapping
- **Repo:** https://github.com/promptfoo/promptfoo
- **License:** MIT
- **Specialty:** all-around red-team via plugins. Each plugin = one attack class (`indirectPromptInjection`, `sqlInjection`, `ssrf`, `dataExfil`, `bola`, `hijacking`, `divergentRepetition`, `pii`, `toxicity`, `hallucination`, etc.). Compliance mapping (OWASP/NIST), GitHub Action support, agent plugins, trace-based testing.
- **Why it's the most polished workflow:** broadest plugin coverage + compliance mappings + CI integration + trace-based testing for agent flows. The *de facto* runtime red-team baseline for production CI/CD.
- **Where AgentShield differs:** Promptfoo runs against a **deployed agent**; AgentShield runs against the **codebase**. They're complementary.
- **Useful insight:** Promptfoo's plugin names map directly to AgentShield's static-rule catalog. Each runtime plugin corresponds to either a Detect rule (look for the surface) or a Defend rule (look for the absence of the filter). The Tier 2 checklist's structure mirrors Promptfoo's taxonomy by design.

#### Garak — broad model-level vulnerability scan
- **Repo:** https://github.com/leondz/garak
- **License:** Apache 2.0
- **Specialty:** static probe library for **foundation-model regression checks**. Probes for prompt injection, data leakage, toxic content, jailbreaks. AVID reporting. Partial agent support (improving in 0.14+).
- **When to use:** before you upgrade your underlying LLM (e.g. switching from Claude 3.5 to Claude 4). Re-run Garak on the new model and compare regressions to baseline.
- **Where AgentShield differs:** Garak probes the **model**; AgentShield probes the **code**. A Garak finding says "this model can be jailbroken with this technique"; an AgentShield finding says "this code has no input filter to defend against jailbreaks."

#### PyRIT — Python Risk Identification Toolkit
- **Repo:** https://github.com/Azure/PyRIT
- **License:** MIT
- **Specialty:** programmatic, multi-turn attack orchestration for research. Scriptable framework (Python API). Microsoft-maintained.
- **Best use:** for researcher-style custom multi-turn attack scripts that don't fit Promptfoo's plugin model. Higher floor than Promptfoo for non-Python operators; higher ceiling for advanced attacks.

#### DeepTeam — Pythonic OWASP/NIST-aligned scans
- **Repo:** https://github.com/confident-ai/deepteam
- **License:** Apache 2.0
- **Specialty:** Pythonic scan API for RAG / agent flows. OWASP and NIST aligned out of the box.
- **Best use:** if your team already uses DeepEval (the parent project) for general LLM evals, DeepTeam slots in cleanly for security probes.

#### Giskard — RAG + bias + security in one scan
- **Repo:** https://github.com/Giskard-AI/giskard
- **License:** Apache 2.0
- **Specialty:** ML-test framework. Biases, robustness, RAG-specific patterns + security in one pass. Partial agent support.
- **Best use:** RAG-heavy applications where bias and security need to be scanned together in a single workflow.

#### AgentDojo — academic-grade agent injection benchmark
- **Repo:** https://github.com/ethz-spylab/agent-dojo
- **License:** AGPL
- **Specialty:** **purpose-built** for agent prompt-injection benchmarking. Tool-calling environment with formal utility checks (a stronger guarantee than judge-LLM grading). Used by UK/US AI Safety Institutes.
- **Best use:** quarterly or before major releases. Being able to say "we benchmarked against the same suite UK/US AISI used" is meaningful.
- **License note:** AGPL — incompatible with some commercial workflows. Verify before adopting.

#### MCP Scan — MCP server security
- **Specialty:** purpose-built scanner for **Model Context Protocol** servers.
- **When to use:** if your agent connects to MCP servers, this is non-optional. AgentShield's Tier 2 has a basic check for MCP server registration (`TIER2-LLM03-02` covers untrusted plugin loading) but doesn't deep-scan MCP servers themselves.

### 4.3 How they fit together — the suggested stack

For a team starting on agent security, the most defensible stack from open-source alone:

1. **AgentShield + Agentic Radar first** — static analysis is cheap and finds problems before you've even run a test. AgentShield's Tier 1 + Tier 2 covers code-pattern-based static issues; Agentic Radar's import-based inheritance catches a different class.
2. **Promptfoo as your primary CI/CD red-team** — broad plugin coverage, compliance mapping, GitHub Action support. The most polished runtime workflow.
3. **AgentDojo for periodic deep evaluation** — quarterly, or before major releases. The formal-utility-check methodology is a stronger guarantee than judge-LLM grading.
4. **MCP Scan if you use MCP servers** — non-optional in that case.
5. **PyRIT if you have a researcher on the team** — for custom multi-turn attack scripts that don't fit Promptfoo's plugin model.
6. **Garak periodically** — for foundation-model regression checks when you upgrade your underlying LLM.

The four tools that are unambiguously worth installing today even before you have a real agent to test: **Promptfoo, Agentic Radar, AgentDojo, and Garak**. Each takes 5–10 minutes to set up, and running them gives you four very different views of your security posture from four different methodologies.

**Where AgentShield slots in:** position 1 in the stack. Run on every commit / PR; scan the whole repo + run Copilot Tier 2; gate CI on the Tier 1 findings; review the unified report before deploy. Promptfoo / AgentDojo / Garak then validate the deployed agent at runtime.

---

## 5. JPMC SAIGE Agent Tier classification

> **Scope note (F.16, 2026-05-06):** AgentShield reports the JPMC Strategic AI Governance and Enablement (SAIGE) agent tier as an **informational classification only** — no findings are filtered, prioritised, or weighted by tier. The tier appears in the unified report header so reviewers know which governance regime the codebase falls under; that's it.

[SAIGE](https://confluence.prod.aws.jpmchase.net/confluence/spaces/ACIC/pages/5109695741/Agent+Tiers+WIP) (Confluence — internal) is JPMC's governance framework for AI agent use cases. It classifies every agentic workload into one of five categories along two axes: **autonomy** (deterministic vs non-deterministic decision-making) and **interaction breadth** (read-only vs write-modify; internal vs external/customer-facing).

### The five categories

| Category | Definition |
|---|---|
| **Non-Agent** | A system where the workflow plan is fixed at runtime and does **not** call any systems, tools, or databases. No autonomy, no agentic characteristics. |
| **Tier 0 — Deterministic Agentic Workflow** | A non-agentic use case where the workflow plan is fixed at runtime. The agent can call pre-defined systems, tools, or databases, but follows a predetermined non-autonomous workflow without dynamic decision-making capabilities. |
| **Tier 1 — Autonomous Workflow with Low Interaction** | An agentic use case with non-deterministic, autonomous workflow where AI uses quantitative methods to determine next steps dynamically, including calls to the next agent. The agent has only **read-only** access with no modification or state-changing capabilities across tools, systems, and databases. |
| **Tier 2 — Autonomous Workflow with Moderate Interaction** | Tier 1 PLUS **write/modify/state-changing access** to tools, systems, and databases. |
| **Tier 3 — Autonomous Workflow with High Interaction** | Tier 2 PLUS state-changing access to **external or customer-facing** tools, systems, and databases. |

### How AgentShield classifies the agent

Tier 2 (Copilot LLM-as-scanner) reads the entire repo and walks a three-question decision tree:

1. **Autonomy.** Is the workflow plan fixed at runtime, or does the agent use non-deterministic autonomous decision-making (LLM-driven control flow)? → distinguishes Non-Agent / Tier 0 from Tier 1+.
2. **State-changing access.** Does the agent perform write/modify/delete operations on tools, systems, or databases (file writes, SQL `INSERT`/`UPDATE`/`DELETE`, HTTP `POST`/`PUT`/`DELETE`/`PATCH`, message queue publishes)? → distinguishes Tier 1 from Tier 2+.
3. **External/customer-facing reach.** Do those state-changing operations touch external systems or customer-facing data? → distinguishes Tier 2 from Tier 3.

The classification + supporting evidence (file:line citations) is emitted as `saige_tier` + `saige_tier_reasoning` in `tier2-findings.json` per the [output schema](./agentshield/skills/tier2_output_schema.md.tmpl). The `agentshield merge` report surfaces it in a header line; nothing else in AgentShield's behaviour is conditional on the tier.

### Why classification is Tier 2's job, not Tier 1's

Semgrep can detect specific code shapes ("this method calls `chain.invoke`") but can't reason about **intent** — whether a workflow is genuinely deterministic, whether write operations target customer-facing or internal systems, whether the agent has discretion or is just dispatching a fixed plan. SAIGE classification fundamentally requires that judgment, so it sits in Tier 2 alongside the other code-comprehension checks.

---

## 6. Further reading & awesome lists

- **TalEliyahu/Awesome-AI-Security** — https://github.com/TalEliyahu/Awesome-AI-Security — the most regularly updated curated index of tools, frameworks, and research across the whole AI security space. Bookmark this.
- **OWASP GenAI Security Project** — https://genai.owasp.org/ — primary source for the LLM Top 10 v2 + the Agentic AI Top 10 + supporting docs (the LLM Security & Governance Checklist is a good companion to AgentShield's Tier 2 checklist).
- **MITRE ATLAS** — https://atlas.mitre.org/ — the full ML-attack technique catalogue. Cross-references CVEs and academic papers per technique.
- **NIST AI RMF** — https://www.nist.gov/itl/ai-risk-management-framework — the framework AgentShield's `framework_mappings.nist_ai_rmf` references.
- **CWE** — https://cwe.mitre.org/data/definitions/ — search the 10 first-class CWEs AgentShield surfaces (78, 89, 94, 200, 400, 494, 532, 732, 798, 829).
- **AVID — AI Vulnerability Database** — https://avidml.org/ — the format Garak's reports target. Useful as a vocabulary for cross-tool comparison.
- **AI Incident Database** — https://incidentdatabase.ai/ — historical real-world AI failures. Useful when arguing for specific control investments.
