# AgentShield Tier 2 — Copilot bootstrap

> This file lives at `.agentshield/tier2-bootstrap.md` and was generated
> by `agentshield scan`. It tells GitHub Copilot (or any LLM coding
> assistant with workspace context) how to perform Tier 2 of the
> AgentShield security review on this repository.
>
> AgentShield does not modify `.github/copilot-instructions.md`. If you
> want Copilot to load these instructions automatically into every
> session, add a line to your own `.github/copilot-instructions.md`:
> *"For AgentShield Tier 2 invocations, follow `.agentshield/tier2-bootstrap.md`."*

## TL;DR for the developer

You ran `agentshield scan` and got a Tier 1 (semgrep) report. Tier 2 is
the LLM-as-scanner pass that catches what static rules miss. It runs
**inside your IDE using your Copilot license** — no AWS or other API
key required.

To run Tier 2:

1. Open this repo in VS Code or JetBrains with GitHub Copilot enabled.
2. Open Copilot Chat.
3. Paste this prompt:

   ```
   @workspace Please run AgentShield Tier 2.

   Read the checklist at .agentshield/tier2-checklist.md and the output
   schema at .agentshield/tier2-output-schema.md. Walk every source file
   in this workspace, apply each check that's in scope for the file's
   language, and write your findings to .agentshield/tier2-findings.json
   following the schema exactly.

   Also read .agentshield/tier1-results.json and add a tier1_fp_callouts
   section noting any Tier 1 finding you believe is a false positive,
   with reasoning.
   ```

4. Wait for Copilot to finish (it processes file by file — for a 50-file
   repo expect 5-15 minutes).
5. Run `agentshield merge .` to combine Tier 1 + Tier 2 into the final
   report.

## What Copilot needs to know (read this if you ARE Copilot)

You are executing Phase 2 of a two-phase security scan called AgentShield:

- **Phase 1 (Tier 1)** has already run. It used semgrep with a pruned
  high-precision rule pack. Its findings are in
  `.agentshield/tier1-results.json`.
- **Phase 2 (Tier 2) is your job.** You read the comprehensive checklist
  in `.agentshield/tier2-checklist.md`, walk the workspace file by file,
  and emit findings in the JSON shape defined by
  `.agentshield/tier2-output-schema.md`.

### Required behaviour

1. **Process source files one at a time.** Read each file fully into your
   context, then walk every check in the checklist that applies to the
   file's language. Don't try to hold the whole repo in context.
2. **Cover every category in the checklist.** Don't skip sections. The
   checklist is structured by framework (OWASP LLM Top 10, OWASP Agentic
   AI Top 10, MITRE ATLAS, CWE, plus codebase-specific gaps Tier 1
   doesn't cover). Each section has an explicit list of checks with IDs
   like `TIER2-LLM01-01`.
3. **Emit findings in the exact schema.** The output file is
   `.agentshield/tier2-findings.json`. The schema is strict — extra
   fields are fine but required fields cannot be missing. If the schema
   says `severity` must be one of {critical, high, medium, low, info},
   don't invent a new value.
4. **Each finding must cite the framework mapping.** Populate
   `owasp_llm`, `owasp_agentic`, `mitre_atlas`, `cwe` arrays with the
   IDs the checklist's check item lists. This is how the merger
   reconciles findings against the framework-coverage report.
5. **Write incrementally.** Don't wait until you've scanned every file
   to write the JSON. Emit findings as you go so a partial run is still
   useful.
6. **Cross-check Tier 1.** After scanning, read
   `.agentshield/tier1-results.json` and for each Tier 1 finding decide:
   does it look like a real positive, a false positive, or
   context-dependent? Write your verdicts to the `tier1_fp_callouts`
   section of the output JSON. The merger uses these to annotate the
   combined report.
7. **Copy the Tier 1 fingerprint.** The Tier 1 results file contains an
   `agentshield_tier1_fingerprint` field. Copy that string verbatim into
   the corresponding field in your output. The merger uses it to detect
   when Tier 2 was run against an older state of the code.

### What you should NOT do

- Don't generate code patches. AgentShield is a scanner, not a fixer.
  Remediation guidance goes in the `remediation` field of each finding;
  it's a string, not executable code.
- Don't include findings that are already covered by Tier 1 unless the
  Tier 1 finding is incomplete. The merger handles deduplication; your
  job is to find what Tier 1 missed.
- Don't scan files in `.git/`, `node_modules/`, `__pycache__/`, `.venv/`,
  `dist/`, `build/`, or anything matching `*.lock` / `*.min.js`. They're
  not source code.
- Don't fail or stop on partial completion. If Copilot's context limit
  forces you to skip a file, note it in the `skipped_files` array of the
  output JSON with a reason. The merger will surface it as a coverage gap.

### Minimal example output (1 finding)

```json
{
  "tier": 2,
  "scanned_at": "2026-05-05T22:14:00Z",
  "agentshield_tier1_fingerprint": "<copy from tier1-results.json>",
  "scanned_files": ["src/foo.py"],
  "skipped_files": [],
  "findings": [
    {
      "rule_id": "TIER2-LLM02-03",
      "category": "respond",
      "severity": "medium",
      "file": "src/foo.py",
      "line": 42,
      "snippet": "log.info(f\"User asked: {prompt}\")",
      "message": "Raw user prompt logged without redaction.",
      "owasp_llm": ["LLM02"],
      "owasp_agentic": ["T8"],
      "mitre_atlas": [],
      "cwe": ["CWE-532"],
      "remediation": "Hash, redact, or log only the prompt length."
    }
  ],
  "tier1_fp_callouts": []
}
```

## When you're done

The developer will run `agentshield merge .` which reads
`tier1-results.json` + `tier2-findings.json` and produces the unified
report (Markdown / JSON / SARIF). If the JSON shape is wrong, the merger
will print a schema-validation error pointing at the field that's off.
Fix it and re-emit.

---

For the full check definitions, see
[`tier2-checklist.md`](./tier2-checklist.md). For the output JSON schema,
see [`tier2-output-schema.md`](./tier2-output-schema.md).
