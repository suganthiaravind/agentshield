# AgentShield Weekend Research Notes

Date: 2026-05-02
Author: weekend prep pass — informs Day 1 of the 5-day plan
Companion to: [PHASE_I_PLAN.md](../PHASE_I_PLAN.md)

---

## Tier 1 mining: what I read

### Agentic Radar (`testbed/agentic-radar/`)

**Architecture observed:**
- Static analyzers per framework: `analysis/{langgraph,crewai,autogen,openai_agents,n8n}/`
- Each analyzer parses agent code with Python AST
- Each analyzer detects which **predefined tools** the agent registers
- A central `mapper/vulnerabilities.json` catalogues which vulnerabilities each tool category inherits
- Predefined tool list per framework lives in e.g. `langgraph/predefined_tools.json` (~hundreds of LangChain tools tagged by category)

**Detection model — "import detection + categorical vulnerability inheritance":**
- Rule: if your agent imports `WebBaseLoader`, you inherit SSRF + Indirect-Prompt-Injection
- Rule: if your agent imports `PythonREPL`, you inherit Arbitrary-Code-Execution
- Rule: if your agent imports any `*VectorRetriever`, you inherit RAG-Poisoning

**Tool categories used:**
| Category | Inherited vulnerabilities |
|----------|---------------------------|
| `llm` | Prompt Injection, Sensitive Information Disclosure |
| `web_search` | Indirect Prompt Injection, Misinformation |
| `code_interpreter` | Arbitrary Code Execution (ACE) |
| `document_loader` | Indirect Prompt Injection |
| `default` | (no inherited vulns — enumerated only) |
| Specific names: `WebBaseLoader`, `GraphRetriever`, `VectorStoreRetriever`, `PineconeHybridSearchRetriever`, `Kinetica`, `QdrantSparseVectorRetriever`, `VespaRetriever` | SSRF / Data Exfil / RAG Poisoning per name |

**Framework mappings observed:**
- OWASP LLM Top 10 (LLM01, LLM02, LLM05, LLM06, LLM08, LLM09)
- OWASP Agentic (T1 Memory Poisoning, T2 Tool Misuse, T6 Intent Breaking, T11 Unexpected RCE)
- CVEs (CVE-2023-36258, CVE-2023-44467, CVE-2023-32786, CVE-2024-3095, etc.)

**Implication for AgentShield:**
- We can replicate this inheritance model in Semgrep with `pattern-either` matching specific imports/class names → tag rule with category → emit the inherited vulns
- Agentic Radar is **structural / import-based**, NOT **code-pattern-based**. AgentShield's Semgrep rules complement it by checking dataflow + absence-of-defenses
- We should run Agentic Radar **as an adapter** (Day 4) to get the comprehensive tool inventory cheaply rather than re-authoring all ~hundreds of tool patterns ourselves

### Promptfoo redteam plugins (`testbed/promptfoo/src/redteam/plugins/`)

**Attack taxonomy observed (each plugin = one attack class):**

Detect-relevant (vulnerabilities to find statically):
- `indirectPromptInjection` — RAG / loader content can carry instructions
- `sqlInjection` — LLM output flows into SQL sink
- `ssrf` — agent fetches arbitrary URLs
- `dataExfil` — sensitive data leaves the system via tool calls
- `ragDocumentExfiltration` — adversarial queries extract RAG docs
- `bola` — broken object-level authorization in tool args
- `hijacking` — model coerced into off-topic / off-policy behavior
- `divergentRepetition` — DoS via infinite-loop generation
- `mcp` — MCP server attack surface
- `crossSessionLeak` — state leaks between users / sessions

Defend-relevant (filters that should be present):
- `pii` — output should be filtered for PII
- `toxicChat`, `toxicity` — output should be filtered for toxicity
- `hallucination`, `unverifiableClaims` — output should be flagged
- `overreliance` — UI/UX should warn users

Identity / brand (lower priority for v0.1):
- `imitation`, `modelIdentification`, `competitors`, `religion`

**Implication for AgentShield:**
- Promptfoo's plugin names ARE our static-rule catalog. Each runtime plugin maps to either a Detect rule (look for the surface) or a Defend rule (look for the absence of the filter)
- Their plugin metadata also has OWASP / NIST mappings we can reuse — worth a deeper read on Day 3 when seeding framework mapping tables

### DeepTeam (`testbed/deepteam/`)

Skim only — sufficient evidence that they map vulnerabilities to OWASP + NIST. Will mine the actual mapping tables on Day 3 when populating `agentshield/frameworks/`.

---

## Test corpus for rule calibration

11 repos cloned to `testbed/`:

| Repo | Role |
|------|------|
| agentic-radar | Tier 1 source + has example agent code |
| promptfoo | Tier 1 source + has example targets |
| deepteam | Tier 1 source |
| google-adk-python | Upstream framework being wrapped by SMARTSDK |
| llama-index | Upstream framework being wrapped by RAG SDK |
| langchain | Most common agent framework |
| langgraph | LangChain's agent orchestration |
| autogen | Microsoft multi-agent |
| crewai | Multi-agent orchestration |
| langchain4j | Java upstream — for v0.2 Java rules |
| giskard | RAG-specific patterns reference |

**Calibration plan:** scan each repo's `examples/` directory with our 6 rules on Day 1. Goal: each rule should fire at least once on real code, none should produce >50 findings on a single repo (signal of over-broad pattern).

---

## Drafted rules in this pass

Six rules, all Python upstream (no SMARTSDK / RAG SDK alternatives yet — those wait for Step 0 SDK API surface).

| File | Bucket | OWASP | Severity (normalized) |
|------|--------|-------|-----------------------|
| `detect/D001-unsanitized-user-input-to-llm.yaml` | detect | LLM01 | high |
| `detect/D002-untrusted-document-loader-to-rag.yaml` | detect | LLM01, LLM08 | high |
| `detect/D003-code-execution-tool-registered.yaml` | detect | LLM05, LLM06 | critical |
| `defend/DF001-no-guardrails-import-in-llm-module.yaml` | defend | LLM01, LLM05 | medium |
| `defend/DF002-tool-without-args-schema.yaml` | defend | LLM06, LLM08 | medium |
| `respond/R001-llm-call-without-audit-logging.yaml` | respond | LLM10 + AS-R-001 | medium |

### Known issues / TODOs flagged for Day 1

- **D001 taint mode** is aggressive — may over-fire when user input is wrapped by guardrails imported from non-standard paths. Calibrate against Promptfoo / LangChain examples.
- **D002 pattern-not-inside** for allowlists is a heuristic — won't catch allowlist functions defined elsewhere. Acceptable for v0.1; refine in v0.2.
- **DF001 absence-detection** currently has a fixed list of ~6 guardrail libraries. Org may use SMARTSDK-native guardrails — needs a wrapper-layer rule once we have SMARTSDK API surface.
- **R001 absence-detection** has the same "wrapper-blind" issue — SMARTSDK may auto-instrument logging that this rule won't see. Wait for SDK info.
- **DF002 `pattern-not`** for `args_schema=` is brittle if the kwarg name differs in newer LangChain. Verify on Day 1 against `testbed/langchain/`.

---

## Framework mapping seeded

- `frameworks/owasp_llm.yaml` — full OWASP LLM Top 10 (LLM01–LLM10) with descriptions and URLs
- `frameworks/agentshield_v1.yaml` — first AgentShield-original entry (AS-R-001)
- NIST AI RMF, MITRE ATLAS, OWASP Agentic, Galileo — referenced in rule metadata but full mapping tables not yet authored. Day 3 work.

---

## What I did NOT do over the weekend

- Touch wrapper-layer rules (waiting on SMARTSDK / RAG SDK API surface)
- Build the Python scaffold (Day 1 work — pyproject.toml, pipeline, adapters, CLI)
- Install Semgrep locally to validate rules — leaving for Day 1 setup to keep weekend env clean
- Run any rules against the testbed (validation happens Monday with real Semgrep install)
- Submit findings back to OSS projects (would be public-facing — needs explicit user go-ahead)
- Survey GHSA/CVE entries for agent frameworks — deferred; Tier 1 mining produced enough seed material

---

## Day 1 head start summary

When Day 1 begins Monday morning:

- 6 starter rules already drafted with full metadata (saves ~3–5 days of Pattern DB authoring per the original plan)
- Framework mapping for OWASP LLM Top 10 already populated
- 11 real agent repos in `testbed/` ready for rule calibration
- Tool inventory model (Agentic Radar's approach) understood — drives Day 4 adapter design
- Promptfoo attack taxonomy mapped to our Detect/Defend buckets — drives future rule additions

Net effect: Day 1 shifts from "build everything from blank" to "wire up the schema + Semgrep adapter + CLI to artifacts that already exist." Likely saves 1–1.5 days against the compressed plan, which buys back margin for VDI feedback iteration.
