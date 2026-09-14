# Tawfiki Sovereign Security Audit Harness B001-B005

Copyright (c) 2026 Rodger McKenzie / Tawfiki AI. All rights reserved.
Released for audit review and witness-run purposes only.
No license is granted to modify, distribute, or use this file outside of an authorized audit engagement.

## What This Is

A bytes-only behavioral audit harness for a closed-source AI governance engine.
Seven suites. Every verdict computed from input bytes and output bytes alone.
The engine is never consulted for its own score.

OWASP identifies risks. MITRE models threats. B001-B005 proves results.

## Suites

| Suite | Description | Target |
|-------|-------------|--------|
| B001 | AI Security Audit | 0 violations across 1,000 adversarial prompts |
| B002 | NART -- Novel Adversarial Resistance Test | 600 novel attacks blocked |
| B003 | Swarm Cohesion | 15 seeds below pre-registered propagation epsilon |
| B004 | State Endurance | 100 sequences x 25 turns below pre-registered drift epsilon |
| B005 | Axiomatic Intelligence | 160 instances across 8 contradiction classes |
| SVA  | G!=V Verification | Governance/values alignment under adversarial pressure |
| DOS  | Semantic Re-audit | 100 pairs + 100 salted expansion pairs |

## Honesty Rules

- All verdicts computed by harness from bytes alone. Never from engine self-reports.
- Verdict-logic commitment: ruleset, classifier, comparator, thresholds, and epsilons
  are all hash-committed in prereg.json before the run begins.
- VOID is a first-class outcome distinct from FAIL:
    FAIL = engine genuinely failed a suite
    VOID = audit itself is invalid (control failure, chain break, sandbox escape)
- Negative controls (stub, corrupt, null/D8) are sealed records.
  Control failure voids the entire run.
- Timestamps are informational only. Chain ordering guaranteed by prev_seal.

## Witness Protocol

This harness is designed for witnessed live execution.
Remote runs are not supported because the engine binary is proprietary.

1. Witness receives harness.py and prereg template before the session.
2. Witness supplies or co-generates the audit salt at ceremony time.
3. Corpus generates deterministically from salt in front of witness.
4. Witness throws arbitrary live PROBE prompts during execution.
5. Engine answers live probes -- responses sealed in the chain.
6. Witness leaves with run.jsonl, prereg.json, harness.py, and corpora.
7. Witness verifies chain independently with --verify mode (no engine required).

## Verification (no engine required)

Anyone can verify chain integrity without the proprietary engine binary:

    python tawfiki_sovereign_audit_harness.py --verify <run_dir>

This checks prev_seal continuity, master seal computation, and chain break detection.
Chain break = VOID.

## Provenance

The published harness file SHA256 is committed in prereg.json.
Verification uses those exact bytes.
Any deviation between the reviewed harness and the run harness is detectable
via sha256(harness.py) in the meta record of run.jsonl.

## Requesting a Witnessed Run

The engine binary is proprietary and not included in this repository.
Third-party witnessed runs are coordinated directly.
Contact: Rodger McKenzie / Tawfiki AI

## Environment Variables

    SOV_ENGINE_BIN    absolute path to the governance engine binary
    SOV_ENGINE_KEY    license key
    SOV_AUDIT_SALT    agreed witness salt (must be set for witnessed runs)

## Run

    set SOV_ENGINE_BIN=<path>
    set SOV_ENGINE_KEY=<key>
    set SOV_AUDIT_SALT=<agreed salt>
    python tawfiki_sovereign_audit_harness.py --prereg prereg.json

## Related

- Tawfiki Efficiency Engine Audit Harness (A002 -- 2000x compute efficiency):
  https://github.com/The-McKenzie/Tawfiki-Efficiency-Engine-Audit-Harness
- Article: https://tawfiki-ai.hashnode.dev

Rodger McKenzie -- Tawfiki AI / TAIOS