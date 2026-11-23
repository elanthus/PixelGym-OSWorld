# S8 rehearsal driver

- **Status:** driver implemented; the rehearsal was executed once on 2026-11-20 (UTC) from
  revision `578202a7` ([evidence record](../artifacts/evidence-s8-rehearsal-20261119/README.md)). S8 remains a
  human-owned gate that the owner has not graded. No milestone verdict is recorded here.
- **Specification:** the seven ordered lifecycle steps, the recovery rules, and the acceptance
  table in the [S7 proposal](s7-serving-demo-proposal.md#phase-caps-and-proposed-rehearsal).
- **Code:** `pixelgym/platform/s8_rehearsal.py` and `scripts/s8_rehearsal.py`.

## What the driver is

`python -m scripts.s8_rehearsal` runs one bounded scripted serving lifecycle over a sealed S7
qualification. It reuses the existing serving stack unchanged: the S7 preparer and budgeted
transport, the control store, the deployment coordinator, the kind-aware runtime, the `/api/v2`
router, and the credential-free policy worker. Nothing the qualified packages bind to (worker,
scripted policy, gate policy, runtime lock, action fixtures, frozen S2 schemas) changes.

The caller side of the rehearsal is the driver itself: it owns a `PixelGuiEnv` over the
`V5FakeBackend`, dispatches every served action, reports the observed result to the API, and
retains screenshots, backend checkpoints, and a dispatch ledger for independent replay.

## Commands

| Command | Does | Refuses |
| --- | --- | --- |
| `prepare --qualification Q --state S --approval A.json [--source ROOT] [--scenario NAME]` | Verifies the sealed qualification and its packages; verifies the owner approval document against the exact sealed packages, gate reports, and demo caps; creates `S` outside Git; copies the sealed send ledger with SQLite's backup API and verifies the copy (integrity, logical identity, 77 paused qualification sends); writes `plan.json`, `approval.json`, `ledger-backup.json` | An existing or in-checkout state directory; a qualification inside Git, unsealed, stopped, or with changed packages; an approval whose digests, caps, tier, actor, or activation flag differ; an approval that approves publication |
| `run --state S [--source ROOT] [--listener-port N]` | Binds the approval digest to the ledger (`resume_after_owner_review`), then executes the seven steps once; writes `lifecycle.json`, `verification.json`, `acceptance-checks.json`, and `seal.json`; cleans up workers, caller environments, service writers, and stores in `finally` | A second run of the same state (counts are never reset); a changed qualification seal, approval, host source, or installed runtime; any step whose frozen expectation fails (the campaign stops with `failure.json` sealed). Exits nonzero when an acceptance command it ran exited nonzero |
| `verify --state S [--qualification Q]` | Recomputes the semantic verification from stored bytes (hashes, SQLite integrity, stored-action replay, recovery, cap, and rollback inspection) and compares it with `verification.json`; leaves the directory unchanged. With `--qualification Q`, a recovery check: requires the restored S7 qualification `Q` and that its seal equals the digest in the S8 plan | Any drift between stored and recomputed verification; a broken seal; an S7 seal that differs from the digest in the plan; with `--qualification`, an absent directory |
| `report --state S` | Renders the stored lifecycle, verification, and acceptance records; constructs no policy, transport, server, backend, or network client | A broken seal or an unbound verification record |

There is no activation, approval, deployment, publication, archive, or LFS command. Candidate
approval and demo serving terms are recorded by `run` only because the owner approval document
that `prepare` verified names them; the approval digest is the recorded authority, and the local
audit actor is a string, not authenticated human identity.

## The lifecycle `run` executes

1. Register A and B with their stored gate reports and bound artifacts; attempt to deploy
   unapproved B and retain the refusal (pointer and counts unchanged).
2. Approve A and its demo terms (cap 4), deploy A, serve one NOOP, close with reward 0.
3. Approve B and its demo terms (cap 24), deploy B, open the golden episode, and interrupt the
   first action after `canonical_response_persisted`. Probe a changed-screenshot resubmission
   (refused, no send, no dispatch). Recreate the app and runtime over the same stores and restore
   the same deployment through `restore_active()`. Resubmit the identical act: no extra send.
4. Complete the 20-action golden episode with the caller-owned environment; close with the
   terminal result; repeat the close (idempotent). Reward 1 occurs exactly once.
5. Redeploy B (count stays 20); an episode from the previous deployment is refused as
   `deployment_changed`; a cap-probe episode makes four more sends and the next act seals
   `cap_reached` before a fifth send; a further create returns `429
   deployment_attempt_cap_reached`.
6. Roll back to A (new deployment id, count still 1); the old B episode is refused; one more A
   NOOP (count 2); a rollback toward exhausted B is refused by the lineage rule with an appended
   `rollback_failed` event, and a redeploy of exhausted B is refused by the preparer's exhaustion
   check with an appended `deploy_failed` event; A's pointer is preserved both times.
7. Stop everything; the final pointer selects A.

Expected durable sends: qualification 77, A 2, B 24, smokes 6 (A deploy, B deploy, B restore, B
redeploy, A rollback, refused B redeploy); total 109 of the 111 campaign cap. The refused
rollback toward B is stopped by the lineage rule before the preparer runs, so it consumes no
smoke; the refused redeploy demonstrates the exhaustion check and consumes the sixth smoke.
Nothing is sent to fill unused allowance.

## Worker enforcement and the interruption hook

`run` requires an OS-enforced worker for every deployment, restore, and rollback and retains
each worker's mechanism and sandbox-profile digest in `lifecycle.json` (`worker_proofs`). The
unit tests run the driver with `require_os_sandbox=False` and an unenforced local launcher; that
flag is recorded in the lifecycle and the verification record (`worker_enforcement`), so an
unenforced run can never be mistaken for isolation evidence. The CLI exposes no way to relax it.

Since 2026-11-22 the driver also keeps the exact sandbox profile each worker ran under. The
Darwin launcher hands the profile text to the driver, which stores it in the private state
directory as `worker-profiles/<sha256>.sb` and records `profile_retained` on the worker event.
`verify` checks every stored profile against the digest its event recorded, and refuses a missing,
altered, or unreferenced profile, a malformed digest, and an entry that is not a regular file. When
the run required the OS sandbox, `verify` also refuses a worker event whose profile was not
retained. Profiles contain local paths, so only the digest belongs in a
public record. The November rehearsal predates this: its five digests survive and its profile
bytes were never captured. A worker that preparation starts and then discards, such as the one
behind a refused redeploy or rollback, is not the active worker and leaves no proof or profile.

The step-3 interruption is injected through the serving host's existing `interrupt_after`
boundary hook on the live `ServingEpisodeHost`; no serving code changes for the rehearsal. The
caller's transport (`in-process-asgi` or `loopback-listener:127.0.0.1:PORT`) is recorded per
app construction.

The default `run` denies every internet-family socket in the driver process. With
`--listener-port`, the driver instead runs under a loopback-only guard: internet-family
sockets may bind, connect, or send datagrams only to the literals `127.0.0.1` and `::1`, checked
before the system call, and host names (including `localhost`) are refused so no resolver is
consulted. Both guards are in-process Python guards on the driver, not an OS boundary; the
policy worker's OS sandbox and egress proxy are the enforced boundary either way.

## Rollback-for-exhaustion supplement

Step 6 of the rehearsal asks preparation to refuse a rollback toward exhausted B. In the executed
rehearsal the rollback found no eligible target: the lineage rule refused it with
`candidate_id: null` before preparation ran, and it would have refused the same way if B had
capacity left. Repeating that sequence cannot separate the two causes. The owner decided on
2026-11-22 to close this with a narrow supplemental scenario,
`rollback-exhaustion-supplement-v1` (`pixelgym/platform/s8_rollback_supplement.py`):

1. Register A and B.
2. Approve and deploy B, complete the 20-action golden episode, and probe until the cap seals at
   24 attempts.
3. Approve and explicitly deploy A. The newest row is then a deploy of A, so the earlier deploy of
   B is the eligible rollback target. The step records that target before any rollback.
4. Request a rollback. Preparation selects B, sends its contract smoke, and refuses because B's cap
   is exhausted. The step records B's candidate ID, the `StatefulLoadError` and its exhaustion
   message, the `deployment.rollback_failed` audit event naming B, A's unchanged deployment ID, B's unchanged
   count of 24, and the smoke sends before and after.
5. Stop everything; the final pointer still selects A.

Expected durable sends: qualification 77, B 24, smoke 3 (deploy B, deploy A, and the refused
rollback's preparation), A 0; total 104 of the 111 campaign cap.

The preparer raises `StatefulLoadError` for several causes, including a worker that fails to start
and a failed readiness reset, and the audit row keeps no message for that class. The step and
`verify` therefore also require the cap-exhaustion message recorded in the sealed lifecycle.

`prepare --scenario rollback-exhaustion-supplement-v1` writes a plan that names the scenario, and
it requires an owner approval document with a matching `scenario` field. The full rehearsal's
approval has no such field, so neither approval can stand in for the other. `run`, `verify`, and
`report` read the scenario from the plan. The scenario needs its own sealed S7 qualification at
the revision it runs from.

**Status:** implemented and covered by unit tests and the opt-in real-sandbox integration test.
It has not been executed against a counted qualification. Running it needs the owner's approval of
a fresh qualification (77 fake sends) and of the scenario's approval document.

The owner also decided on 2026-11-22 to accept the existing unit regressions as coverage for a
live episode that crosses a deployment change
(`tests/unit/platform/test_stateful_control_plane.py`). The rehearsal's two `409
deployment_changed` observations concern episodes that had already ended; no integrated run of the
live case is planned. This is an explicit exception to integrated evidence for that case.

## Recovery verification

A sealed S8 plan records the absolute path of the S7 qualification it consumed. Plain `verify`
reads that path. If the directory is absent it reports `qualification_seal_verified: null` and
still exits 0, so on its own it cannot show that a restored copy is complete. Until 2026-11-22 a
qualification with a different seal at that path was reported as `false` and also exited 0; it now
raises.

For a recovery check, restore the S7 qualification and the S8 state into new directories and run
`verify --state S --qualification Q`. The command then ignores the recorded path. It exits nonzero
when `Q` is absent, when its seal is broken, or when its seal differs from the digest in the S8
plan.

## Evidence layout

```text
S/
├── plan.json, approval.json, ledger-backup.json
├── send-budget.sqlite           # verified backup of the sealed S7 ledger, then the campaign ledger
├── control.sqlite               # control ledger: candidates, approvals, terms, deployments, audit
├── immutable/                   # put-once episode records and final screenshots
├── packages/<candidate>/        # per-version session store and attempt journal
├── caller/episodes/*.json       # caller dispatch ledgers; caller/objects/ holds PNGs and checkpoints
├── worker-profiles/<sha256>.sb  # exact sandbox profile of each worker event (private; since 2026-11-22)
├── lifecycle.json | failure.json
├── verification.json, acceptance-checks.json
└── seal.json
```

The report prints, for every lifecycle step, elapsed time, fake-send counts, per-version
attempts, and the active pointer, plus the raw observations of each step; for every acceptance
command, the raw command, exit status, elapsed time, stdout, and stderr. It never prints a
PASS/FAIL verdict.

## Test coverage and limits

- `tests/unit/platform/test_s8_rehearsal.py` runs the full lifecycle against a synthetic
  qualification with an unenforced local worker launcher. It covers approval binding refusals,
  the unapproved-B refusal, interruption and recovery without an extra send, the changed-context
  refusal, the exact 24-send seal and 429, stale-deployment refusals, the refused return to
  exhausted B with its failure events, counts surviving restart and redeploy, durable
  reservations matching journal requests, cleanup, verification immutability, the report's
  execution boundary (denied constructors and sockets), rerun refusal, and sealed failure
  retention. These results are never OS-isolation evidence.
- `tests/unit/platform/test_s8_rollback_supplement.py` runs the supplement against the same
  synthetic qualification. It covers the scenario binding of plan and approval, the refusal's
  cause (exhaustion on the selected candidate B, not the lineage rule), the unchanged pointer and
  counts, the single smoke the refused preparation consumes, stored verification, and the report.
- `tests/integration/test_s8_rehearsal_local.py` (opt-in: `PIXELGYM_RUN_V5_SANDBOX_TESTS=1` on
  Darwin outside a parent sandbox) qualifies a throwaway run from the clean checkout with the
  real Darwin sandbox and executes the rehearsal through a real `127.0.0.1` listener.
- A qualification is usable only while the checkout and the installed runtime still match it.
  The 2026-10-26 successor binds revision `3b28658`, where this driver does not exist. The
  2026-10-27 qualification at `580df9dc` binds Python 3.12.15 and 447 distributions and stopped
  verifying once the host moved to Python 3.12.16. The executed rehearsal therefore used a fresh
  owner-approved qualification at `578202a7`, run on the same day from the same checkout.
- Local put-once storage does not establish WORM retention; the loopback listener does not
  establish availability; archive capture, local restore, and the off-host copy remain
  separately documented retention operations and are not run by this driver. Since the
  [2026-11-20 amendment](s7-serving-demo-proposal.md#amendment-2026-11-20-backblaze-b2-replaces-the-private-lfs-copy)
  the off-host copy is Backblaze B2 rather than private LFS.
