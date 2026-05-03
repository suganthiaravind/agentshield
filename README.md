# AgentShield

Pre-production security evaluator for AI agents. Static analysis only (Phase I); runtime red-teaming deferred to Phase II.

**Status:** A1 scaffolding (Phase I, v0.1.0). CLI runs and prints planned pipeline; tier execution lands in Tracks A2/A3/A4/B/C/D/E.

## What it does (when complete)

- Scans Python and Java repos for AI-agent-specific security issues using semgrep rules organized as **Detect / Defend / Respond** controls.
- Maps every finding to OWASP LLM Top 10, OWASP Agentic Top 10, NIST AI RMF, MITRE ATLAS, and the AgentShield Framework v1.
- Recognizes JPMC's wrapper SDKs: **SMARTSDK** (wraps Google ADK) and **RAD SDK** (wraps LlamaIndex), in addition to LangChain, LangGraph, langchain4j, Spring AI, AWS Bedrock direct, and Azure OpenAI.
- Emits findings as SARIF v2.1.0 (primary) plus JSON and Markdown.
- Optional LLM-judge tier (boto3-Bedrock / SMARTSDK / Copilot) triages low-confidence fallback findings.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the system design and [ARCHITECTURE_RATIONALE.md](./ARCHITECTURE_RATIONALE.md) for why-this-not-that for each major decision.

## Install

```bash
# clone
git clone git@github.com:suganthiaravind/agentshield.git
cd agentshield

# create a venv
python3 -m venv .venv
source .venv/bin/activate

# install — three flavors
pip install -e .                    # core only (no semgrep, no judge)
pip install -e ".[semgrep]"         # + semgrep for Tier 1/2 scanning
pip install -e ".[semgrep,judge]"   # + boto3 for Tier 3 judge backend
pip install -e ".[all,dev]"         # everything + dev tools (pytest, ruff, mypy)
```

## Quickstart

```bash
# show version
agentshield --version

# stub scan (A1: prints planned pipeline as TODOs)
agentshield scan ./path/to/target/repo

# scan with LLM judge backend selected
agentshield scan ./path/to/target/repo --llm-backend boto3-bedrock

# offline mode (Tiers 1+2 only, skip judge)
agentshield scan ./path/to/target/repo --no-judge

# enable discovery pass (Tier 4)
agentshield scan ./path/to/target/repo --discovery

# write reports
agentshield scan ./path/to/target/repo \
  --output-sarif report.sarif \
  --output-json report.json \
  --output-markdown report.md
```

## VDI setup notes

AgentShield's *scanner side* (this CLI) runs in your dev VDI. It can reach AWS Bedrock (default judge backend) via `boto3` if your VDI has IAM-role or STS credentials configured. It does not require outbound public internet.

The *scanned side* (production target agents) typically runs in AWS — that constraint is independent. See [ARCHITECTURE_RATIONALE.md §11](./ARCHITECTURE_RATIONALE.md#11-why-scanner-vs-scanned-constraint-split).

```bash
# verify AWS credentials reachable from your VDI
aws sts get-caller-identity

# select a Bedrock model (record the inference-profile ARN)
aws bedrock list-inference-profiles --region us-east-1
```

Set `bedrock_model_id` in your `agentshield.yaml` (or pass via CLI) once known.

## Configuration

`agentshield.yaml` (per-repo or per-org default; CLI flags override):

```yaml
llm_backend: boto3-bedrock     # boto3-bedrock | smartsdk | copilot | none
bedrock_model_id: <arn>        # required when llm_backend = boto3-bedrock
tiers:
  framework_rules: true
  fallback_rules: true
  judge: true
  discovery: false
ignore:
  - "**/test/**"
  - "**/vendor/**"
output:
  sarif: report.sarif
  json: report.json
  markdown: report.md
```

## Project layout

```
agentshield/
├── rules/         # semgrep YAML rule packs (detect / defend / respond)
├── frameworks/    # OWASP / NIST / MITRE / AgentShield-v1 mapping tables
├── runner/        # Track A2: semgrep subprocess wrapper
├── normalize/     # Track A3: SARIF → Finding schema
├── judge/         # Track B: pluggable LLM-judge backends
├── discovery/     # Track D: Tier 4 discovery pass
├── report/        # Track A4: SARIF / JSON / Markdown writers
└── cli.py         # entry point
```

See [ARCHITECTURE.md §5 Parallel development tracks](./ARCHITECTURE.md#5-parallel-development-tracks) for the dev plan and dependency edges.

## Phase I scope

Static analysis only. No runtime probing of live agents. Languages: Python and Java. See [ARCHITECTURE.md §10](./ARCHITECTURE.md#10-whats-not-in-scope-for-phase-i) for the explicit out-of-scope list.

## License

Apache-2.0.
