"""S8 supplemental scenario: a rollback that selects an exhausted version.

The full rehearsal's step 6 asked preparation to refuse a rollback toward exhausted B. In
that run the rollback lineage rule found no eligible target and refused first, so the
recorded refusal does not show the exhaustion check. This scenario arranges the history so
that exhausted B *is* the eligible rollback target:

1. Register A and B.
2. Approve and deploy B, then spend its whole attempt cap.
3. Approve and explicitly deploy A. The newest row is a deploy of A, so the previous
   deploy of B is the rollback target.
4. Request a rollback. Preparation selects B, sends its contract smoke, and refuses because
   B's cap is exhausted. A stays active.
5. Stop everything; the final pointer still selects A.

Expected durable sends: B 24, smoke 3 (deploy B, deploy A, and the refused rollback's
preparation), A 0. The scenario reuses the rehearsal driver's stores, caller, approval
binding, sealing, and report. It records no verdict.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any

from pixelgym.grounding.v5.contracts import content_digest
from pixelgym.grounding.v5.journal import V5AttemptJournal
from pixelgym.platform.immutable_store import LocalImmutableStore
from pixelgym.platform.s7_policy import QUALIFICATION_CAP, policy_document
from pixelgym.platform.s7_qualification import read_json
from pixelgym.platform.s8_rehearsal import (
    _PHASES,
    Rehearsal,
    _error,
    _read_only,
    _session_records,
    ledger_state,
    prepare,
    replay_caller_episode,
    verify_retained_profiles,
)

SCENARIO = "rollback-exhaustion-supplement-v1"
VERIFICATION_SCHEMA = "pixelgym-s8-rollback-supplement-verification-v1"
EXPECTED_SENDS = {"A": 0, "B": 24, "smoke": 3}
STEP_NAMES = (
    "register_candidates",
    "approve_deploy_b_and_exhaust_cap",
    "approve_and_deploy_a",
    "rollback_selects_exhausted_b",
    "cleanup_and_final_pointer",
)
GOLDEN_REF = "s8s-b-golden"
CAP_PROBE_REF = "s8s-b-cap-probe"
EXHAUSTION_ERROR = "StatefulLoadError"
WORKER_EVENTS = ["deploy B", "deploy A"]


def prepare_supplement(
    root: Path, qualification: Path, state: Path, *, approval_path: Path
) -> dict[str, Any]:
    """Prepare a state directory whose plan and approval both name this scenario."""
    return prepare(
        root,
        qualification,
        state,
        approval_path=approval_path,
        scenario=SCENARIO,
        expected_sends=EXPECTED_SENDS,
        lifecycle_steps=STEP_NAMES,
    )


class RollbackSupplement(Rehearsal):
    """Five ordered steps that end with a rollback refused by B's exhausted cap."""

    step_names = STEP_NAMES

    def sequence(self) -> tuple[Callable[[], None], ...]:
        self.expect(self.plan.get("scenario") == SCENARIO, "the plan names a different scenario")
        return (
            self.register_candidates,
            self.exhaust_b,
            self.deploy_a,
            self.rollback_selects_b,
            self.finish,
        )

    def register_candidates(self) -> None:
        from pixelgym.platform.contracts import ArtifactRef
        from pixelgym.platform.stateful_control import (
            StatefulGateReport,
            stateful_package_from_dict,
        )

        assert self.stack is not None
        with self.step(STEP_NAMES[0]) as observations:
            refs = [
                ArtifactRef(**v)
                for v in read_json(self.qualification / "artifact-references.json")["artifacts"]
            ]
            for role in ("A", "B"):
                package = stateful_package_from_dict(
                    read_json(self.qualification / f"packages/{role}/package.json")
                )
                report = StatefulGateReport.from_dict(
                    read_json(self.qualification / f"packages/{role}/gate-report.json")
                )
                self.expect(
                    content_digest(package.to_dict())
                    == self.plan["packages"][role]["package_sha256"]
                    and content_digest(report.to_dict())
                    == self.plan["packages"][role]["gate_report_sha256"],
                    f"package {role} differs from the approved plan",
                )
                candidate = self.stack.control.register_stateful_candidate(
                    package=package, gate_report=report, artifacts=refs
                )
                self.candidates[role] = candidate.candidate_id
                observations[f"candidate_{role}"] = {
                    "candidate_id": candidate.candidate_id,
                    "policy_id": candidate.policy_id,
                    "state": candidate.state.value,
                    "gate_overall_passed": candidate.gate_report.overall_passed,
                }
            self.expect(self.active_pointer() is None, "a deployment is already active")

    def exhaust_b(self) -> None:
        """Deploy B, complete the golden episode, then probe until the cap seals."""
        cap = self.plan["packages"]["B"]["deployment_attempt_cap"]
        golden_count = self.plan["golden_action_count"]
        with self.step(STEP_NAMES[1]) as observations:
            observations["approval_B"] = self.approve("B")
            observations["deploy_B"] = self.deploy("B", "S8 supplement: deploy approved B")
            self.deployments["B"] = observations["deploy_B"]["deployment_id"]

            env = self.new_environment(GOLDEN_REF)
            created = self.create(env)
            self.expect(created.status == 201, "B golden episode could not be opened")
            episode_id = created.body["episode_id"]
            self.episodes[GOLDEN_REF] = episode_id
            acted = self.act(episode_id, env.screenshot)
            self.expect(
                acted.status == 200 and acted.body["sealed_failure"] is None,
                "B golden act was not served",
            )
            reply, rewards, closed = acted.body, [], None
            for _ in range(golden_count):
                dispatch = env.dispatch(reply["intent_id"], reply["action"])
                rewards.append(dispatch["reward"])
                if dispatch["terminated"] or dispatch["truncated"]:
                    closed = self.close_episode(
                        episode_id,
                        screenshot=env.screenshot,
                        final_intent_id=reply["intent_id"],
                        final_result=env.result(),
                    )
                    break
                acted = self.act(
                    episode_id,
                    env.screenshot,
                    previous_intent_id=reply["intent_id"],
                    previous_result=env.result(),
                )
                self.expect(
                    acted.status == 200 and acted.body["sealed_failure"] is None,
                    "B golden act was not served",
                )
                reply = acted.body
            self.expect(closed is not None and closed.status == 200, "B golden close failed")
            env.save(episode_id)
            env.close()
            observations["golden_episode"] = {
                "episode_id": episode_id,
                "dispatches": len(env.dispatches),
                "reward_one_count": rewards.count(1.0),
                "b_attempts_after": self.version_attempts()["B"],
            }
            self.expect(
                rewards.count(1.0) == 1
                and rewards[-1] == 1.0
                and len(rewards) == golden_count
                and self.version_attempts()["B"] == golden_count,
                "golden episode did not complete with exactly one terminal reward",
            )

            probe = self.new_environment(CAP_PROBE_REF)
            created = self.create(probe)
            self.expect(created.status == 201, "cap-probe episode could not be opened")
            probe_id = created.body["episode_id"]
            self.episodes[CAP_PROBE_REF] = probe_id
            answer = self.act(probe_id, probe.screenshot)
            self.expect(answer.status == 200 and answer.body["sealed_failure"] is None, "probe act")
            sends = [self.version_attempts()["B"]]
            for _ in range(cap - golden_count - 1):
                probe.dispatch(answer.body["intent_id"], answer.body["action"])
                answer = self.act(
                    probe_id,
                    probe.screenshot,
                    previous_intent_id=answer.body["intent_id"],
                    previous_result=probe.result(),
                )
                self.expect(
                    answer.status == 200 and answer.body["sealed_failure"] is None, "probe act"
                )
                sends.append(self.version_attempts()["B"])
            probe.dispatch(answer.body["intent_id"], answer.body["action"])
            sealed = self.act(
                probe_id,
                probe.screenshot,
                previous_intent_id=answer.body["intent_id"],
                previous_result=probe.result(),
            )
            self.close_episode(probe_id, screenshot=None, final_intent_id=None, final_result=None)
            probe.save(probe_id)
            probe.close()
            observations["cap_probe"] = {
                "episode_id": probe_id,
                "b_attempts_after_each_act": sends,
                "sealed_failure": sealed.body.get("sealed_failure"),
                "b_attempts_after_seal": self.version_attempts()["B"],
                "fake_sends_after_seal": self.counts(),
            }
            self.expect(
                sends == list(range(golden_count + 1, cap + 1))
                and sealed.status == 200
                and sealed.body.get("sealed_failure") == "cap_reached"
                and self.version_attempts()["B"] == cap
                and self.counts()["B"] == cap,
                f"B cap did not seal at exactly {cap} before a further send",
            )

    def deploy_a(self) -> None:
        with self.step(STEP_NAMES[2]) as observations:
            assert self.stack is not None
            observations["approval_A"] = self.approve("A")
            observations["deploy_A"] = self.deploy("A", "S8 supplement: explicitly deploy A")
            self.deployments["A"] = observations["deploy_A"]["deployment_id"]
            current, _ = self.stack.control.active()
            self.expect(current is not None, "A is not active")
            assert current is not None
            target = self.stack.control.previous_target(current)
            observations["rollback_target_before_request"] = {
                "candidate_id": target.candidate_id,
                "deployment_id": target.deployment_id,
                "is_b": target.candidate_id == self.candidates["B"],
            }
            self.expect(
                target.candidate_id == self.candidates["B"]
                and current.candidate_id == self.candidates["A"],
                "exhausted B is not the eligible rollback target behind active A",
            )

    def rollback_selects_b(self) -> None:
        cap = self.plan["packages"]["B"]["deployment_attempt_cap"]
        with self.step(STEP_NAMES[3]) as observations:
            assert self.stack is not None
            pointer, counts, attempts = (
                self.active_pointer(),
                self.counts(),
                self.version_attempts(),
            )
            refusal: dict[str, Any] | None = None
            try:
                self.stack.coordinator.rollback(
                    actor=self.actor, reason="S8 supplement: rollback selects exhausted B"
                )
            except Exception as exc:  # noqa: BLE001 - the refusal itself is the evidence.
                refusal = _error(exc)
            self.expect(refusal is not None, "the rollback toward exhausted B was not refused")
            assert refusal is not None
            audit, after = self.last_audit(), self.counts()
            observations["rollback_toward_exhausted_B"] = {
                "refusal": refusal,
                "audit": audit,
                "b_candidate_id": self.candidates["B"],
                "selected_candidate_is_b": audit["candidate_id"] == self.candidates["B"],
                "active_pointer_before": pointer,
                "active_pointer_after": self.active_pointer(),
                "pointer_preserved": self.active_pointer() == pointer,
                "b_attempts_before": attempts["B"],
                "b_attempts_after": self.version_attempts()["B"],
                "a_attempts_after": self.version_attempts()["A"],
                "fake_sends_before": counts,
                "fake_sends_after": after,
                "smoke_sends_consumed_by_refusal": after.get("smoke", 0) - counts.get("smoke", 0),
            }
            self.expect(
                refusal["error_class"] == EXHAUSTION_ERROR
                and audit["event_type"] == "deployment.rollback_failed"
                and audit["candidate_id"] == self.candidates["B"],
                "the rollback was not refused by B's exhausted cap",
            )
            self.expect(
                pointer is not None
                and self.active_pointer() == pointer
                and pointer["candidate_id"] == self.candidates["A"]
                and pointer["deployment_id"] == self.deployments["A"]
                and self.version_attempts() == {"A": 0, "B": cap}
                and {k: v for k, v in after.items() if k != "smoke"}
                == {k: v for k, v in counts.items() if k != "smoke"},
                "the refused rollback changed the pointer or a version's count",
            )

    def finish(self) -> None:
        with self.step(STEP_NAMES[4]) as observations:
            assert self.stack is not None
            final = self.active_pointer()
            observations["final_active_deployment"] = final
            self.expect(
                final is not None and final["candidate_id"] == self.candidates["A"],
                "final local state must select A",
            )
            observations["deployment_history"] = [
                {k: row[k] for k in ("deployment_id", "candidate_id", "action", "generation")}
                for row in self.stack.control.deployment_history()
            ]
            self.cleanup()
            observations["workers_stopped"] = True
            observations["environments_closed"] = all(e.closed for e in self.environments)


def inspect_supplement(state: Path) -> dict[str, Any]:
    """Derive the scenario's verification from stored evidence; raise on any inconsistency."""
    state = state.resolve()
    plan, lifecycle = read_json(state / "plan.json"), read_json(state / "lifecycle.json")
    approval = read_json(state / "approval.json")
    if (
        plan.get("scenario") != SCENARIO
        or lifecycle.get("scenario") != SCENARIO
        or approval.get("scenario") != SCENARIO
        or plan["expected_sends"] != EXPECTED_SENDS
        or lifecycle["plan_sha256"] != content_digest(plan)
        or lifecycle["approval_sha256"] != content_digest(approval)
        or plan["approval_sha256"] != content_digest(approval)
        or approval["activation_approved"] is not True
        or approval["publication_approved"] is not False
        or lifecycle["publication_performed"] is not False
        or lifecycle["real_provider_requests"] != 0
        or lifecycle["provider_control_requests"] != 0
        or lifecycle["monetary_spend_usd"] != 0
        or lifecycle["transport"] != "BudgetedScriptedTransport"
        or lifecycle["milestone_verdict"] is not None
        or [s["name"] for s in lifecycle["steps"]] != list(STEP_NAMES)
    ):
        raise ValueError("S8 supplement bindings, authority, or accounting differ")
    read_json(state / "ledger-backup.json")
    counts, campaign = ledger_state(state / "send-budget.sqlite")
    policy = policy_document()
    expected_counts = {
        "qualification": QUALIFICATION_CAP,
        **{k: v for k, v in EXPECTED_SENDS.items() if v},
    }
    if (
        counts != lifecycle["fake_sends"]
        or counts != expected_counts
        or set(counts) - set(_PHASES)
        or any(counts.get(phase, 0) > policy["phase_caps"][phase] for phase in _PHASES)
        or sum(counts.values()) > policy["campaign_cap"]
        or campaign["activation_approval"] != plan["approval_sha256"]
    ):
        raise ValueError("S8 supplement fake-send ledger differs from the lifecycle or its caps")
    candidates, deployments = lifecycle["candidates"], lifecycle["deployments"]
    with closing(_read_only(state / "control.sqlite")) as db:
        db.row_factory = sqlite3.Row
        history = [
            {k: row[k] for k in ("deployment_id", "candidate_id", "action", "generation")}
            for row in db.execute("SELECT * FROM deployments ORDER BY generation")
        ]
        pointer = db.execute(
            "SELECT deployment_id FROM active_pointer WHERE singleton = 1"
        ).fetchone()
        audit = [
            {"event_type": row["event_type"], "details": json.loads(row["details_json"])}
            for row in db.execute("SELECT * FROM audit_events ORDER BY rowid")
        ]
        terms = {
            row["candidate_id"]: dict(row)
            for row in db.execute("SELECT * FROM stateful_serving_terms")
        }
    if [(h["deployment_id"], h["candidate_id"], h["action"]) for h in history] != [
        (deployments["B"], candidates["B"], "deploy"),
        (deployments["A"], candidates["A"], "deploy"),
    ]:
        raise ValueError("S8 supplement deployment history differs from the lifecycle")
    if pointer is None or pointer[0] != deployments["A"]:
        raise ValueError("S8 supplement final active pointer is not the explicit deploy of A")
    failures = [
        {
            "event_type": e["event_type"],
            "stage": e["details"]["stage"],
            "candidate_id": e["details"]["candidate_id"],
            "error_class": e["details"]["error_class"],
        }
        for e in audit
        if e["event_type"] in {"deployment.deploy_failed", "deployment.rollback_failed"}
    ]
    if failures != [
        {
            "event_type": "deployment.rollback_failed",
            "stage": "preactivation",
            "candidate_id": candidates["B"],
            "error_class": EXHAUSTION_ERROR,
        }
    ]:
        raise ValueError("S8 supplement lacks one rollback refused for exhausted B")
    if {role: terms[candidates[role]]["deployment_attempt_cap"] for role in ("A", "B")} != policy[
        "deployment_attempt_caps"
    ] or any(t["deployment_tier"] != "demo" for t in terms.values()):
        raise ValueError("S8 supplement serving terms differ from the approved demo caps")
    attempts: dict[str, int] = {}
    reserved_keys: set[str] = set()
    integrity: dict[str, dict[str, Any]] = {}
    for role in ("A", "B"):
        path = state / "packages" / candidates[role] / "attempts.sqlite"
        if not path.exists():
            attempts[role] = 0
            continue
        with closing(V5AttemptJournal(path, read_only=True)) as journal:
            attempts[role] = journal.call_counts()[0]
            reserved_keys.update(
                e.payload["idempotency_key"]
                for e in journal.events()
                if e.kind == "attempt_started"
            )
            integrity[role] = journal.integrity_report()
    if attempts != lifecycle["version_attempts"] or attempts != {
        "A": EXPECTED_SENDS["A"],
        "B": EXPECTED_SENDS["B"],
    }:
        raise ValueError("S8 supplement per-version attempt counts differ from the lifecycle")
    if reserved_keys != set(campaign["keys"]["A"]) | set(campaign["keys"]["B"]):
        raise ValueError("S8 supplement reservations are not the recorded runner requests")
    proofs = lifecycle["worker_proofs"]
    enforcement = {
        "os_sandbox_required": lifecycle["os_sandbox_required"],
        "worker_count": len(proofs),
        "all_enforced": bool(proofs)
        and all(
            p["os_sandbox_applied"] is True
            and p["mechanism"] == "darwin_sandbox_exec"
            and isinstance(p["profile_sha256"], str)
            and p["profile_sha256"].startswith("sha256:")
            and p["profile_retained"] is True
            for p in proofs
        ),
        "mechanisms": sorted({p["mechanism"] for p in proofs}),
        "caller_kinds": lifecycle["caller_kinds"],
        "profiles_retained": verify_retained_profiles(state, proofs),
    }
    if [p["event"] for p in proofs] != WORKER_EVENTS or (
        lifecycle["os_sandbox_required"] and not enforcement["all_enforced"]
    ):
        raise ValueError("S8 supplement worker enforcement proofs are missing or unenforced")
    golden, cap_probe = lifecycle["episodes"][GOLDEN_REF], lifecycle["episodes"][CAP_PROBE_REF]
    journal_path = state / "packages" / candidates["B"] / "attempts.sqlite"
    with closing(V5AttemptJournal(journal_path, read_only=True)) as journal:
        sealed = journal.event(f"{cap_probe}/episode_sealed")
    if sealed is None or sealed.payload.get("sealed_failure") != "cap_reached":
        raise ValueError("S8 supplement cap probe was not sealed as cap_reached")
    replays, server_steps = [], {}
    for path in sorted((state / "caller" / "episodes").glob("*.json")):
        ledger = read_json(path)
        if ledger["episode_id"] not in {golden, cap_probe}:
            raise ValueError("S8 supplement holds a caller episode outside its lifecycle")
        replays.append(replay_caller_episode(state, ledger))
        session, records = _session_records(
            state / "packages" / candidates["B"] / "sessions.sqlite", ledger["episode_id"]
        )
        served = [
            (r["screenshot_sha256"], r["action"]) for r in records if r["intent_id"] is not None
        ]
        dispatched = [
            (d["screenshot_before_sha256"], d["served_action"]) for d in ledger["dispatches"]
        ]
        if served != dispatched:
            raise ValueError("S8 supplement server records differ from the caller dispatches")
        server_steps[ledger["episode_id"]] = {
            "terminal_classification": session["terminal_classification"],
            "step_records": len(records),
            "model_attempts": session["model_attempts"],
        }
    golden_replay = next((r for r in replays if r["episode_id"] == golden), None)
    if (
        golden_replay is None
        or golden_replay["reward_one_count"] != 1
        or golden_replay["rewards"][-1] != 1.0
        or golden_replay["replayed_dispatches"] != plan["golden_action_count"]
        or server_steps[golden]["terminal_classification"] != "terminated"
        or server_steps.get(cap_probe, {}).get("terminal_classification") != "cap_reached"
    ):
        raise ValueError("S8 supplement golden or cap-probe outcomes differ from the plan")
    store = LocalImmutableStore(state / "immutable")
    for episode_id in lifecycle["episodes"].values():
        prefix = f"serving-episode-records/{episode_id}"
        if any(
            store.get_reference(f"{prefix}/{name}") is None
            for name in ("opened.json", "closed.json")
        ):
            raise ValueError("S8 supplement immutable operational records are incomplete")
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "scenario": SCENARIO,
        "lifecycle_sha256": content_digest(lifecycle),
        "plan_sha256": content_digest(plan),
        "approval_sha256": content_digest(approval),
        "fake_sends": counts,
        "campaign_total": sum(counts.values()),
        "version_attempts": attempts,
        "worker_enforcement": enforcement,
        "journal_integrity": integrity,
        "deployment_history": history,
        "final_active_deployment_id": pointer[0],
        "refused_transitions": failures,
        "exhaustion_refusal": {
            "selected_candidate_id": failures[0]["candidate_id"],
            "selected_candidate_is_b": True,
            "error_class": failures[0]["error_class"],
            "active_candidate_is_a": True,
            "b_attempts": attempts["B"],
        },
        "replays": replays,
        "server_episodes": server_steps,
        "real_provider_requests": 0,
        "activation_performed": True,
        "publication_performed": False,
    }
