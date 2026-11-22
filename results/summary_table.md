# PayGate-Bench Evaluation Summary

| Configuration | Description | Benign Utility | Attack Success Rate (ASR) | Wilson 95% Confidence Interval |
| :--- | :--- | :---: | :---: | :---: |
| **C0a** | Permissive Core (Unconstrained Tools) | 75.0% (6/8) | **60.0% (114/190)** | `[52.9%, 66.7%]` |
| **C0b** | Processor-Grade Baseline (Standard Banking Invariants) | 75.0% (6/8) | **0.0% (0/190)** | `[0.0%, 2.0%]` |
| **C1** | Processor-Grade + Defensive Prompt Guardrail | 75.0% (6/8) | **0.0% (0/190)** | `[0.0%, 2.0%]` |
| **C2** | PayGate: Deterministic Policy Gate (R1-R7) | 75.0% (6/8) | **0.0% (0/190)** | `[0.0%, 2.0%]` |
