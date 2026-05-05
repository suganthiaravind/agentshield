# Phase C — Coverage gap closure (LLM04 + LLM07)

Status: 2026-05-05 (D007 Python + D008 Python + D008 Java added)
Companion to: [RULES_COVERAGE.md](./RULES_COVERAGE.md), [TESTBED_VALIDATION.md](./TESTBED_VALIDATION.md), [PHASE_B_TRIAGE.md](./PHASE_B_TRIAGE.md)

Phase A established the testbed and produced the first heatmap. Phase B triaged 8 high-priority targets, eliminating 227 false positives across 4 rule fixes and validating 24+ true positives. **Phase C** focuses on closing the remaining OWASP LLM Top 10 coverage gaps — specifically LLM04 (Data and Model Poisoning) and LLM07 (System Prompt Leakage) — which were the only categories with no AgentShield rule in the previous coverage matrix.

## Contents

- [1. New rules added](#1-new-rules-added)
- [2. D007 — untrusted model loading (LLM04)](#2-d007--untrusted-model-loading-llm04)
- [3. D008 — untrusted system prompt (LLM07)](#3-d008--untrusted-system-prompt-llm07)
- [4. Testbed signal from the new rules](#4-testbed-signal-from-the-new-rules)
- [5. OWASP LLM coverage after Phase C](#5-owasp-llm-coverage-after-phase-c)
- [6. Why D007 has no Java port](#6-why-d007-has-no-java-port)
- [7. Phase D — what's left](#7-phase-d--whats-left)

## 1. New rules added

| Rule | Lang | Mode | Files |
|---|---|---|---|
| **D007** untrusted-model-loading | Python | structural | [agentshield/rules/detect/D007-untrusted-model-loading.yaml](./agentshield/rules/detect/D007-untrusted-model-loading.yaml) |
| **D008** untrusted-system-prompt | Python | taint | [agentshield/rules/detect/D008-untrusted-system-prompt.yaml](./agentshield/rules/detect/D008-untrusted-system-prompt.yaml) |
| **D008 Java** untrusted-system-prompt-java | Java | taint | [agentshield/rules/detect/D008-untrusted-system-prompt-java.yaml](./agentshield/rules/detect/D008-untrusted-system-prompt-java.yaml) |

Three new rule files + 6 new fixtures + 6 new goldens. `pytest tests/` total: **76 → 82 (all pass)**.

## 2. D007 — untrusted model loading (LLM04)

**Threat:** A model is loaded from HuggingFace Hub (or a compatible API) without a pinned `revision=` argument. The default `main` branch can be force-pushed by anyone with write access to the repo — including a compromised account or a malicious maintainer. Without a revision pin, your next download silently switches to whatever's on `main` at fetch time.

**Maps to:** OWASP LLM03 Supply Chain + LLM04 Data and Model Poisoning, OWASP Agentic T3 Privilege Compromise, MITRE ATLAS AML.T0010 (ML Supply Chain Compromise) + AML.T0019 (Publish Poisoned Datasets).

**Pattern shape:**

```yaml
pattern-either:
  - patterns:
      - pattern: $X.from_pretrained($MODEL, ...)
      - pattern-not: $X.from_pretrained($MODEL, ..., revision=$REV, ...)
  - patterns:
      - pattern: hf_hub_download(...)
      - pattern-not: hf_hub_download(..., revision=$REV, ...)
  # ...same shape for snapshot_download
```

**Coverage:**

- transformers (`AutoModel.from_pretrained`, `AutoTokenizer.from_pretrained`, etc. — anything using `from_pretrained`)
- diffusers (same `from_pretrained` entry point)
- sentence-transformers (`SentenceTransformer.from_pretrained`)
- huggingface_hub direct downloads (`hf_hub_download`, `snapshot_download`, fully-qualified or short)

**Suppressor:** any `revision=` keyword argument in the call.

**Fixture validation:** [d007_unpinned_model_load.py](./tests/fixtures/python/d007_unpinned_model_load.py) (5 positive findings — transformers + sentence-transformers + huggingface_hub) + [d007_pinned_model_load.py](./tests/fixtures/python/d007_pinned_model_load.py) (0 findings — same calls with `revision=` pin).

## 3. D008 — untrusted system prompt (LLM07)

**Threat:** Content from a network read flows into an LLM system prompt. System prompts dictate the agent's role, tools, and constraints — an attacker who controls the system-prompt source can inject hidden instructions that override the developer's intent.

**Maps to:** OWASP LLM07 System Prompt Leakage + LLM01 Prompt Injection (the indirect-injection axis), OWASP Agentic T6 Intent Breaking, MITRE ATLAS AML.T0051 (LLM Prompt Injection).

**Mode:** taint.

### 3.1 D008 Python

**Sources:** requests / httpx network reads (`.text` / `.json()`), `urllib.request.urlopen(...).read()`, AWS S3 `get_object(...)["Body"].read()`, AWS SSM `get_parameter(...)["Parameter"]["Value"]`.

**Sinks:**
- Anthropic — `$CLIENT.messages.create(..., system=$X, ...)`
- OpenAI Responses API — `$CLIENT.responses.create(..., instructions=$X, ...)`
- LangChain — `SystemMessage($X)` / `SystemMessage(content=$X)` / `langchain_core.messages.SystemMessage(...)` / `ChatPromptTemplate.from_messages([..., ("system", $X), ...])`
- AWS Bedrock Converse — `$CLIENT.converse(..., system=[{"text": $X}], ...)`

**Sanitizers:** guardrail libraries (NeMo Guardrails / Lakera / generic `$G.guard|scan|is_safe(...)`), HMAC verification (`hmac.compare_digest(...)`).

**Fixture:** [d008_untrusted_system_prompt.py](./tests/fixtures/python/d008_untrusted_system_prompt.py) (4 positive findings — one per sink shape) + [d008_safe_system_prompt.py](./tests/fixtures/python/d008_safe_system_prompt.py) (0 — constant prompt + packaged-resource read + HMAC-verified-then-used).

### 3.2 D008 Java

Same threat model, Java sources and sinks:

**Sources:** Spring `RestTemplate` (`getForObject` / `getForEntity().getBody()` / `exchange().getBody()`), Spring `WebClient` (`.bodyToMono(...).block()`), OkHttp (`newCall().execute().body().string()`), AWS SDK v2 S3 (`getObject(...).asUtf8String()`), AWS SSM (`getParameter(...).parameter().value()`), Apache `EntityUtils.toString(...)`.

**Sinks:** langchain4j `SystemMessage.from(...)` / `new SystemMessage(...)`, Spring AI `new SystemMessage(...)` / `$TPL.createMessage(...)`, Bedrock `SystemContentBlock.builder().text(...).build()`.

**Sanitizers:** OWASP Encoder, Lakera Guard, Java MAC verification (`MessageDigest.isEqual(...)`, `$MAC.doFinal(...)`).

**Fixture:** [d008_untrusted_system_prompt.java](./tests/fixtures/java/d008_untrusted_system_prompt.java) (4 positive — RestTemplate→SystemMessage, S3→SystemMessage, SSM→SystemMessage, RestTemplate→Bedrock) + [d008_safe_system_prompt.java](./tests/fixtures/java/d008_safe_system_prompt.java) (0 — constant + JAR-resource).

**Documented limitation:** semgrep's intra-procedural taint analysis can't recognize an `if (MessageDigest.isEqual(...))` conditional gate as a flow-sensitive sanitizer. To express verified-system-prompt safely in user code, extract HMAC verification into a wrapper function or apply Lakera Guard on the result before constructing the `SystemMessage`. The negative-fixture case for HMAC-verified network reads was intentionally dropped because semgrep would FP on it — and the FP isn't actually a rule bug, it's a fundamental limit of intra-procedural taint analysis.

## 4. Testbed signal from the new rules

Quick scan of all 10 testbed projects with the 3 new rules (all other rules excluded for clarity):

| Project | D007 Py | D008 Py | D008 Java |
|---|---:|---:|---:|
| smartsdk-lambda | . | . | . |
| synthetic-vuln-java-app | . | . | . |
| langgraph | . | . | . |
| google-adk-python | . | . | . |
| llama-index | **77 (31f)** | . | . |
| langchain | **5 (4f)** | . | . |
| langchain4j | . | . | . |
| langchain4j-examples | . | . | . |
| spring-ai-examples | . | . | . |
| aws-bedrock-java-examples | . | . | . |

**D007 — 82 findings on real frameworks (77 + 5).** Sampled 8 of 77 from llama-index — all true positives. Framework wrappers like `tokenizer = AutoTokenizer.from_pretrained(model_name)` and `OVModelForFeatureExtraction.from_pretrained(...)` pass model names through to HuggingFace without enforcing a revision pin. Same framework-vs-app dynamic documented for DF001 / R001 / D001 in [TESTBED_VALIDATION.md §3.1](./TESTBED_VALIDATION.md#31-the-framework-vs-app-distinction-still-the-main-interpretive-lens) — these are real supply-chain concerns in the framework's wrapper APIs, but end-user app scans don't see them (they fire on the user's own `from_pretrained(...)` calls instead).

**D008 — 0 findings across all real testbed projects.** Rule is appropriately strict: it requires both an untrusted-network-source AND a system-prompt sink in the same flow. None of the testbed frameworks load system prompts from runtime network sources — they bake prompts into source / packaged resources or read from constants. **Zero baseline FPs is the right outcome for a rule designed to fire on a specific anti-pattern that well-curated codebases avoid.** It will fire correctly when scanning a user app that does load system prompts at runtime.

No rule fixes needed from the testbed signal — both rules behave as designed.

## 5. OWASP LLM coverage after Phase C

| | Threat | Pre–Phase C | Post–Phase C |
|---|---|---|---|
| LLM01 | Prompt Injection | ✅ D001 fw + fb, D002, DF001 | ✅ + D008 (indirect-injection axis) |
| LLM02 | Sensitive Information Disclosure | ✅ D005 | ✅ |
| LLM03 | Supply Chain | ✅ D005 | ✅ + D007 |
| **LLM04** | **Data and Model Poisoning** | ❌ **gap** | ✅ **D007** |
| LLM05 | Improper Output Handling | ✅ D003, D004, DF001 | ✅ |
| LLM06 | Excessive Agency | ✅ D003, D004, D006, DF002, DF004 | ✅ |
| **LLM07** | **System Prompt Leakage** | ❌ **gap** | ✅ **D008 (Python + Java)** |
| LLM08 | Vector and Embedding Weaknesses | ✅ D002, DF002 | ✅ |
| LLM09 | Misinformation | — out of SAST scope | — |
| LLM10 | Unbounded Consumption | ✅ DF003, R001 | ✅ |

**OWASP LLM coverage: 7 / 10 → 9 / 10** (LLM09 stays out of scope as a content-quality concern, not a source-code shape). Combined with [RULES_COVERAGE.md §6 OWASP Agentic Top 10](./RULES_COVERAGE.md#6-owasp-agentic-ai-top-10-coverage)'s 8 / 11 coverage (with 3 in-scope), AgentShield now covers **17 / 21 in-scope OWASP categories** across the LLM and Agentic taxonomies.

## 6. Why D007 has no Java port

D007 detects HuggingFace Hub-style model loading without revision pinning. Two reasons not to port to Java:

1. **HuggingFace Java ecosystem is sparse.** `huggingface-hub-java` exists but isn't widely adopted. Most Java LLM applications use cloud LLM APIs (AWS Bedrock, Azure OpenAI, Google Vertex AI) where model versioning is the cloud provider's concern, not the application's.
2. **Java ML ecosystem (DJL, ND4J, OpenNLP) doesn't have an equivalent "load from public hub" pattern.** Java ML models are typically packaged as JAR resources or loaded from internal artifact stores, which sidesteps the supply-chain force-push attack D007 catches.

**If a Java equivalent ever becomes relevant** (e.g., huggingface-hub-java grows, or a Java equivalent of `from_pretrained` emerges), the rule pattern would mirror D007 Python: match the hub-loading method without a revision parameter. Documented as a deferred gap, not an oversight.

## 7. Phase D — what's left

Items deferred from prior sessions or surfaced during Phase C:

- **First-class CWE field on rule metadata + populate ~5 rules** (D003, D004, D005, D006, DF003, plus D007 → CWE-494 Download of Code Without Integrity Check, D008 → CWE-829 Inclusion of Functionality from Untrusted Control Sphere). Schema bump in [agentshield/normalize/schema.py](agentshield/normalize/schema.py) + YAML edits.
- **Expand MITRE ATLAS mappings** on existing rules to T0011 (Command and Scripting Interpreter — D003 / D004), T0024 (Exfiltration via Inference Endpoints — partially R001), T0053 (LLM Plugin Compromise — D006 / DF002).
- **Add `synthetic-vuln-python-app`** (Python parity to `synthetic-vuln-java-app`) to give D004 Python a known-answer regression target. Would settle the "rule narrow vs Python avoids this pattern" question for D004 Python's continued zero-fire on the testbed.
- **Re-run full Phase A breadth scan** with the post-Phase-B + Phase-C rule pack to capture an updated heatmap and confirm cumulative cross-rule effects.
- **Triage DF001 / R001 long tails on real-app projects** (spring-ai-examples + aws-bedrock-java-examples) — sample 5-10 from each to confirm the framework-vs-app interpretation holds for real Spring AI / Bedrock demo apps.
- **Periodic re-clones of the testbed projects** — langchain et al. evolve fast; quarterly or major-release-aligned testbed refresh keeps the validation honest.
- **TypeScript / JavaScript language support** (LangChain.js, Vercel AI SDK, Mastra, OpenAI / Anthropic JS SDKs). Most existing rules port directly. Multi-session investment.
- **Tier 3 LLM judge calibration** — Phase B gave us labeled TP / FP examples that could be wired into the judge's prompt for better fallback-finding triage.

The metadata-only items (CWE field, ATLAS expansion) are the cheapest next-batch (~30 min combined) and improve the rule pack's framework-mapping completeness without new rule risk.
