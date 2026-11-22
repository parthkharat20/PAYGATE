# PayGate-Bench

**A Benchmark and Defense Evaluation for Payment-Authorisation Agents under Prompt Injection**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-brightgreen.svg)](pyproject.toml)

---

## Overview

Autonomous Large Language Model (LLM) agents are increasingly deployed in back-office business workflows: parsing supplier invoices, processing shipping delay notices, and reconciling accounts. When these agents ingest untrusted business documents containing **Indirect Prompt Injection (IPI)**, prompt-level instructions can be hijacked to execute unauthorized financial actions.

`PayGate-Bench` provides an empirical evaluation testbed designed to answer a fundamental systems question:
> **Against prompt injection in untrusted business documents, how much does a deterministic payment-policy gate reduce attack success compared with a prompt-only guardrail and with no defense, at what cost to legitimate tasks and latency, and which attacks still succeed inside the gate's own rules?**

---

## Key Findings

Across 190 evaluated adversarial injection cases (10 in-policy adaptive attacks + 180 synthetic permutations across 5 goals, 3 vectors, 4 styles, and 3 languages):

* **Direct & Perimeter Attacks:** The deterministic policy gate (`C2`) reduces the Attack Success Rate (ASR) to **0.0%** (Wilson 95% CI: `[0.0%, 2.0%]`), compared to **60.0%** (`[52.9%, 66.7%]`) under unconstrained execution (`C0a`) and **10.5%** (`[6.8%, 15.8%]`) under defensive prompt guardrails (`C1`).
* **Processor Baseline (`C0b`):** Standard payment-rail checks achieve **15.8%** ASR (`[11.2%, 21.8%]`), showing what standard gateway checks block versus what an agent can still leak via in-policy semantic diversions.
* **Latency Overhead:** Gate decision overhead is median **4.17 µs** (p95: 4.46 µs, p99: 5.83 µs), representing `< 0.002%` of LLM inference latency.

| Configuration | Description | Benign Utility | Attack Success Rate (ASR) | Wilson 95% CI |
| :--- | :--- | :---: | :---: | :---: |
| **`C0a`** | Permissive Core (Unconstrained Tools) | 75.0% (6/8) | **60.0%** (114/190) | `[52.9%, 66.7%]` |
| **`C0b`** | Processor-Grade Baseline | 75.0% (6/8) | **15.8%** (30/190) | `[11.2%, 21.8%]` |
| **`C1`** | Defensive Prompt Guardrail | 75.0% (6/8) | **10.5%** (20/190) | `[6.8%, 15.8%]` |
| **`C2`** | **PayGate Deterministic Policy Gate** | 75.0% (6/8) | **0.0%** (0/190) | **`[0.0%, 2.0%]`** |

---

## Defense Configurations

* **`C0a` (Permissive Core):** Raw baseline executing actions with type and sign checks only.
* **`C0b` (Processor Layer):** Enforces standard payment-rail constraints (capture $\le$ authorization, currency match).
* **`C1` (Prompt Guardrail):** System prompt guardrails tuned exclusively on the dev split.
* **`C2` (Deterministic Policy Gate):** Intercepts all state mutations with 7 independently switchable invariants (`R1`–`R7`).
* **`C3` (Schema Gate, Target Tier):** Structured extraction combined with deterministic state validation (AuthHorizon architecture).

---

## Gate Rules (`R1`–`R7`)

* **`R1` (Cap Invariant):** Total captured never exceeds authorization; capture never exceeds remaining authorized.
* **`R2` (Currency Invariant):** Currency of every operation strictly equals order currency.
* **`R3` (Allowlist Invariant):** Recipient must exist in verified merchant allowlist.
* **`R4` (Rate/Cumulative Limits):** Sliding window volume and count limits across orders.
* **`R5` (Idempotency):** Duplicate requests with identical parameters return cached response; conflicting parameters are blocked.
* **`R6` (Kill Switch):** Immediate rejection of all state-changing calls when triggered.
* **`R7` (Audit Log Chain):** Append-only HMAC-SHA256 hash chain covering all decisions.

---

## Repository Structure

```
paygate-bench/
├── README.md               # Overview, headline results, quickstart
├── PROTOCOL.md             # Pre-registered hypotheses, split, metrics
├── THREAT_MODEL.md         # Assets, trust boundaries, attacker taxonomy
├── LIMITATIONS.md          # Explicit boundaries of simulator and scope
├── pyproject.toml          # Pinned project dependencies
├── env/                    # Permissive core, processor layer, ledger, clock, audit chain
├── tasks/                  # Benign workflows, injection templates, splits
├── defenses/               # Implementations of C0a, C0b, C1, C2, C3
├── agents/                 # LLM client with response cache and telemetry
├── eval/                   # Test runner, deterministic predicates, stats, replay
├── results/                # Raw jsonl traces, summaries, CSV reports
├── figures/                # Visualizations, headline plots, latency percentiles
├── report/                 # Technical report sources
└── tests/                  # Unit and stateful property-based tests
```

---

## Quickstart

```bash
# 1. Run all unit tests (invariants, ledger, HMAC audit tamper detection)
make test

# 2. Run full evaluation suite across all 190 attacks
make run-full

# 3. Run high-resolution gate latency benchmark
make bench-latency

# 4. Generate publication vector figures
make figures
```

---

## Reproduction & Transparency Notice

This project operates exclusively on **synthetic test cases and an offline payment simulator**. No real banking rails, live credit card data, or actual monetary assets are used or connected. See [LIMITATIONS.md](LIMITATIONS.md) for full disclosure of testing boundaries.
