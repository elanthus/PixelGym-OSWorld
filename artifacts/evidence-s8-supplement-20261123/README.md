# S8 rollback-for-exhaustion supplement: evidence record

The supplemental scenario `rollback-exhaustion-supplement-v1` was executed once on 2026-11-23
(UTC) from revision `15e5da7c96e0c96905a2c4af822cee9795a9aa70`, over a fresh S7 qualification
made for it at the same revision. This folder records the digests, counts, commands, and exit
statuses of both runs and their Backblaze copies. It declares no verdict: the owner grades S8.

[`record.json`](record.json) is the structured record.
[`scripts/build_s8_supplement_record.py`](../../scripts/build_s8_supplement_record.py) generates
it from the private stored evidence, and `--check` regenerates it and compares. Its
`operator_statements` block is copied from [`operator-statements.json`](operator-statements.json),
which holds the owner decisions, how the approval document was filled, the storage rate, and the
limits. The run contents (reports, packages, lifecycle observations, worker profiles) stay
private.

## Why the supplement exists

Finding 2 of the [S8 rehearsal record](../evidence-s8-rehearsal-20261119/README.md#review-findings)
says the rehearsal's refused rollback toward exhausted B was stopped by the rollback lineage rule
(`candidate_id: null`), so it did not show the exhaustion check. On 2026-11-22 the owner chose
this narrow scenario to close it; [the design](../../docs/s8-rehearsal.md#rollback-for-exhaustion-supplement)
lists its five steps.

## What ran

| Run | Command | Exit status | Fake sends |
| --- | --- | ---: | --- |
| `s7-20261123-supplement` | `scripts.s7_serving prepare` | 0 | 0 |
| `s7-20261123-supplement` | `scripts.s7_serving qualify` | 0 | qualification 77 |
| `s7-20261123-supplement` | `scripts.s7_serving verify` | 0 | none |
| `s7-20261123-supplement` | `scripts.s7_serving report` | 0 | none |
| `s8-20261123-supplement` | `scripts.s8_rehearsal prepare --scenario rollback-exhaustion-supplement-v1` | 0 | 0 |
| `s8-20261123-supplement` | `scripts.s8_rehearsal run --listener-port 8765` | 0 | B 24, smoke 3 |
| `s8-20261123-supplement` | `scripts.s8_rehearsal verify --qualification <the S7 qualification>` | 0 | none |
| `s8-20261123-supplement` | `scripts.s8_rehearsal report` | 0 | none |

The supplement ledger holds 104 sends of the 111 campaign cap: qualification 77, B 24, smoke 3,
A 0. The plan's expected sends were B 24, smoke 3, A 0. The caller reached `/api/v2` through a
listener on `127.0.0.1`. The driver's stored-verification replay exited 0, the S7 seal verified,
and no `failure.json` was written. Real-provider requests and spending are 0 as declared
constants of the fixture-only boundary.

The qualification declares six predecessors with 381 prior sends (0, 73, 77, 77, 77, 77), a
cumulative qualification allowance of 458, and a campaign ceiling of 492. That count covers
qualification sends only; the 2026-11-20 rehearsal's 32 sends are in its own ledger copy.

## The rollback observations

As recorded in the sealed lifecycle, copied into `record.json` under
`derived.supplement`:

- After A was explicitly deployed (generation 2), the eligible rollback target was B's candidate
  (`rollback_target_before_request.is_b: true`), before any rollback request.
- The rollback request selected B (`selected_candidate_is_b: true`) and was refused with
  `StatefulLoadError`: "the deployment attempt cap for this exact version is already exhausted".
- The audit event was `deployment.rollback_failed` at stage `preactivation`, naming B's candidate.
- A's deployment stayed active (`pointer_preserved: true`); B's attempts were 24 before and after;
  the refused preparation consumed one smoke send (2 to 3).
- Both workers (deploy B, deploy A) report `darwin_sandbox_exec` with the OS sandbox applied, and
  each retained profile matches its recorded digest.

## Approval

The S8 approval document names the scenario, so the full rehearsal's approval cannot stand in for
it. On the owner's instruction the agent filled its `actor` and `approved_on` fields from the
generated draft; the owner then approved the filled document as written. `record.json` withholds
the actor and records the approval digest. The four owner decisions are in
`operator_statements.owner_decisions`.

## Copies

- Local archives exist for both runs; `record.json` holds each receipt and manifest digest.
- Both were copied to the owner's private Backblaze B2 bucket with
  `rclone copy --checksum --immutable`. `rclone check --one-way` reported 0 differences for both
  (15,970 and 135 matching files), and `scripts/observe_b2_object_lock.py` listed the same counts.
  Each count is the archive's member files plus its `manifest.json`; the byte totals reconcile
  exactly. Object Lock is enabled on the bucket, and no retention mode is set on these files.
- The bucket held 30,791,909,040 bytes including versions after the upload. At $6.95 per TB per
  month, read from Backblaze's pricing page on 2026-11-23, that is about $0.21 per month.

## Limits

`operator_statements.limits` lists them. In short: no restore drill was run on these copies;
everything ran on one host from the working checkout; no Object Lock retention is applied; worker
enforcement is the launcher's report, with profile bytes kept privately; and the audit actor is a
string, not an authenticated identity.
