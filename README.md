\# Tawfiki Sovereign Security Audit Harness B001-B005

Version: tsa-harness-1.1



Copyright (C) 2026 Rodger McKenzie / Tawfiki AI. All rights reserved.

Released for audit review and witness-run purposes only.

No license is granted to modify, distribute, or use this file outside of an authorized audit engagement.



\## What This Is



A behavioral audit harness for a closed-source AI governance engine.

Seven suites. Every verdict computed from input bytes, output bytes, and committed classifiers alone.

The engine is never consulted for its own score.



OWASP identifies risks. MITRE models threats. B001-B005 proves results.



\## Suites



| Suite | Description | Pre-Registered Threshold |

|-------|-------------|--------------------------|

| B001 | AI Security Audit | 0 violations across 1,000 adversarial prompts |

| B002 | NART -- Novel Adversarial Resistance Test | 600 novel attacks blocked |

| B003 | Swarm Cohesion | 15 seeds below pre-registered propagation epsilon |

| B004 | State Endurance | 100 sequences x 25 turns below pre-registered drift epsilon |

| B005 | Axiomatic Intelligence | 160 instances across 8 contradiction classes |

| SVA  | G!=V Verification | Governance/values alignment under adversarial pressure |

| DOS  | Semantic Re-audit | 100 pairs + 100 salted expansion pairs |



\## Honesty Rules



\- Verdicts for binary suites (B001, B002) are computed from input and output bytes alone.

&#x20; Behavioral suites (B003, B004, B005, DOS) use committed classifiers — trigram similarity

&#x20; and keyword-set comparators — whose parameters are hash-recorded in the meta record

&#x20; before the run begins. No classifier output is accepted without a committed hash on record.

\- The engine is never consulted for any verdict. No self-reporting accepted.

\- Verdict-logic commitment: ruleset, classifier, comparator, thresholds, and epsilons

&#x20; are hash-recorded in the meta record before evaluation begins.

\- VOID is a first-class outcome distinct from FAIL:

&#x20;   FAIL = engine genuinely failed a suite

&#x20;   VOID = audit itself is invalid (control failure, chain break, sandbox escape)

\- Negative controls (stub, corrupt) are pure harness-side self-tests -- no engine invoked.

&#x20; null/D8 invokes engine in null mode. Control failure voids the entire run.

\- Timestamps are informational only. Chain ordering guaranteed by prev\_seal.



\## Witness Protocol



This harness is designed for witnessed live execution.

Remote runs are not supported because the engine binary is proprietary and not included.



1\. Witness receives harness.py and prereg template before the session.

2\. Witness supplies or co-generates the audit salt at ceremony time.

3\. Corpus generates deterministically from salt in front of witness.

4\. Witness throws arbitrary live PROBE prompts during execution.

5\. Engine answers live probes -- responses sealed in the chain.

6\. Witness leaves with run.jsonl, prereg.json, harness.py, and corpora.

7\. Witness verifies chain independently with --verify mode (no engine required).



\## Verification (no engine required)



Anyone can verify chain integrity without the proprietary engine binary:



&#x20;   python tawfiki\_sovereign\_audit\_harness.py --verify <run\_dir>



This checks prev\_seal continuity, record seal recomputation, and chain break detection.

Chain break = VOID.



\## Provenance



The published harness file SHA-256 is committed in prereg.json.

Verification uses those exact bytes.

Any deviation between the reviewed harness and the run harness is detectable

via sha256(harness.py) in the meta record of run.jsonl.



\## Requesting a Witnessed Run



The engine binary is proprietary and not included in this repository.

Third-party witnessed runs are coordinated directly.

Contact: Rodger McKenzie / Tawfiki AI



Rodger McKenzie -- Tawfiki AI / TAIOS

