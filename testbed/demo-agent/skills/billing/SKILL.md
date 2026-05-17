---
name: billing-tools
version: 1.0.0
description: Billing-side tool skill — cancel_subscription, list_invoices, exec_billing_script.
author:
  name: Demo Team
  did: did:example:demo-team
permissions:
  # Narrow grant: this skill only needs to run vetted billing scripts.
  # It deliberately does NOT request network or filesystem access — the
  # billing operations are local shell calls.
  shell: true
tools:
  - cancel_subscription
  - list_invoices
  - exec_billing_script
---

# Billing skill

Provides billing operations: cancel subscription, list invoices,
delete customer records.

Activation: invoked by the support orchestrator when a user requests
account changes.

## Implementation note

Uses `subprocess.run(...)` to call vetted billing scripts under
`/usr/local/billing/`. Permission scope is narrow on purpose — this
skill should never need to write files or reach the network on its
own. Side effects flow through the billing-side scripts only.
