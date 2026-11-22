"""S8 rollback-for-exhaustion supplement against a synthetic qualification.

Workers here use an unenforced local launcher, so nothing in this file is OS-isolation
evidence. The scenario's point is the refusal's cause: the rollback must select exhausted B
and be refused by the exhaustion check, not by the rollback lineage rule.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pixelgym.platform import s8_rollback_supplement as supplement
from pixelgym.platform.s7_budget import S7SendBudget
from pixelgym.platform.s7_evidence import inventory, verify_seal
from pixelgym.platform.s7_qualification import read_json
from pixelgym.platform.s8_rehearsal import (
    Rehearsal,
    RehearsalStopped,
    bind_approval,
    prepare,
)
from pixelgym.platform.s8_rollback_supplement import (
    EXPECTED_SENDS,
    SCENARIO,
    STEP_NAMES,
    RollbackSupplement,
    inspect_supplement,
    prepare_supplement,
)
from scripts import s8_rehearsal as cli
from scripts.s7_serving import no_network
from tests.unit.platform.test_s7_review_boundaries import qualified_fixture  # noqa: F401
from tests.unit.platform.test_s8_rehearsal import (
    REPOSITORY_ROOT,
    approval_document,
    synthetic_host,
    unit_preparer,
)
from tests.unit.platform.test_stateful_control_plane import LocalWorkerLauncher


def supplement_state(qualification: Path, directory: Path, name: str = "supplement") -> Path:
    approval = directory / f"{name}-approval.json"
    approval.write_bytes(json.dumps(approval_document(qualification, scenario=SCENARIO)).encode())
    state = directory / name
    prepare_supplement(
        qualification.parent / "checkout", qualification, state, approval_path=approval
    )
    return state


@pytest.fixture(scope="module")
def ran(qualified_fixture: Path, tmp_path_factory: Any) -> SimpleNamespace:  # noqa: F811
    directory = tmp_path_factory.mktemp("s8-supplement")
    launcher = LocalWorkerLauncher()
    with pytest.MonkeyPatch.context() as patch:
        synthetic_host(patch)
        state = supplement_state(qualified_fixture, directory)
        lifecycle = RollbackSupplement(
            qualified_fixture.parent / "checkout",
            state,
            preparer_factory=unit_preparer(launcher),
            require_os_sandbox=False,
        )
        with cli.no_inet_sockets():
            result = lifecycle.run()
        with no_network():
            checks = cli.finalize(REPOSITORY_ROOT, state)
    return SimpleNamespace(
        qualification=qualified_fixture,
        state=state,
        lifecycle=result,
        checks=checks,
        launcher=launcher,
        scenario=lifecycle,
        steps={step["name"]: step["observations"] for step in result["steps"]},
    )


def test_plan_and_approval_both_name_the_scenario(ran: SimpleNamespace) -> None:
    plan = read_json(ran.state / "plan.json")
    assert plan["scenario"] == SCENARIO
    assert plan["expected_sends"] == EXPECTED_SENDS
    assert plan["lifecycle_steps"] == list(STEP_NAMES)
    assert read_json(ran.state / "approval.json")["scenario"] == SCENARIO
    assert ran.lifecycle["scenario"] == SCENARIO
    assert [s["name"] for s in ran.lifecycle["steps"]] == list(STEP_NAMES)


def test_an_approval_for_one_lifecycle_cannot_stand_in_for_the_other(
    qualified_fixture: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic_host(monkeypatch)
    root = qualified_fixture.parent / "checkout"
    plain = tmp_path / "plain.json"
    plain.write_bytes(json.dumps(approval_document(qualified_fixture)).encode())
    named = tmp_path / "named.json"
    named.write_bytes(json.dumps(approval_document(qualified_fixture, scenario=SCENARIO)).encode())

    with pytest.raises(ValueError, match="fields differ from the approval schema"):
        prepare_supplement(root, qualified_fixture, tmp_path / "a", approval_path=plain)
    with pytest.raises(ValueError, match="fields differ from the approval schema"):
        prepare(root, qualified_fixture, tmp_path / "b", approval_path=named)
    with pytest.raises(ValueError, match="names a different scenario"):
        bind_approval(
            qualified_fixture,
            approval_document(qualified_fixture, scenario="another-scenario"),
            scenario=SCENARIO,
        )
    assert not (tmp_path / "a").exists() and not (tmp_path / "b").exists()


def test_b_is_exhausted_before_a_is_deployed(ran: SimpleNamespace) -> None:
    exhaust = ran.steps["approve_deploy_b_and_exhaust_cap"]
    assert exhaust["golden_episode"]["dispatches"] == 20
    assert exhaust["golden_episode"]["reward_one_count"] == 1
    assert exhaust["cap_probe"]["b_attempts_after_each_act"] == [21, 22, 23, 24]
    assert exhaust["cap_probe"]["sealed_failure"] == "cap_reached"
    assert exhaust["cap_probe"]["b_attempts_after_seal"] == 24
    target = ran.steps["approve_and_deploy_a"]["rollback_target_before_request"]
    assert target["is_b"] is True
    assert target["candidate_id"] == ran.lifecycle["candidates"]["B"]


def test_the_rollback_selects_b_and_is_refused_by_exhaustion(ran: SimpleNamespace) -> None:
    observed = ran.steps["rollback_selects_exhausted_b"]["rollback_toward_exhausted_B"]
    b, a = ran.lifecycle["candidates"]["B"], ran.lifecycle["candidates"]["A"]
    # The cause: the exhaustion check on the selected candidate, not the lineage rule.
    assert observed["refusal"]["error_class"] == "StatefulLoadError"
    assert "already exhausted" in observed["refusal"]["message"]
    assert "no eligible known-good deployment" not in observed["refusal"]["message"]
    assert observed["audit"]["event_type"] == "deployment.rollback_failed"
    assert observed["audit"]["stage"] == "preactivation"
    assert observed["audit"]["candidate_id"] == b == observed["b_candidate_id"]
    assert observed["selected_candidate_is_b"] is True
    # A's deployment and both attempt counts are unchanged.
    assert observed["pointer_preserved"] is True
    assert observed["active_pointer_after"]["candidate_id"] == a
    assert observed["active_pointer_after"]["deployment_id"] == ran.lifecycle["deployments"]["A"]
    assert observed["b_attempts_before"] == observed["b_attempts_after"] == 24
    assert observed["a_attempts_after"] == 0
    # The refused preparation consumed exactly one smoke and no version send.
    assert observed["smoke_sends_consumed_by_refusal"] == 1
    assert observed["fake_sends_before"]["B"] == observed["fake_sends_after"]["B"] == 24


def test_sends_match_the_scenario_and_stay_within_caps(ran: SimpleNamespace) -> None:
    counts = S7SendBudget(ran.state / "send-budget.sqlite").counts()
    assert counts == {"qualification": 77, "B": 24, "smoke": 3}
    assert ran.lifecycle["fake_sends"] == counts
    assert ran.lifecycle["version_attempts"] == {"A": 0, "B": 24}
    assert ran.lifecycle["real_provider_requests"] == 0
    assert ran.lifecycle["milestone_verdict"] is None
    final = ran.steps["cleanup_and_final_pointer"]
    assert final["final_active_deployment"]["candidate_id"] == ran.lifecycle["candidates"]["A"]
    assert [h["action"] for h in final["deployment_history"]] == ["deploy", "deploy"]
    assert final["workers_stopped"] is True and final["environments_closed"] is True


def test_cleanup_stopped_every_worker_including_the_refused_preparation(
    ran: SimpleNamespace,
) -> None:
    # Three launches: deploy B, deploy A, and the worker preparation started for the refused
    # rollback. None may outlive the scenario.
    assert len(ran.launcher.processes) == 3
    assert all(process.poll() is not None for process in ran.launcher.processes)
    assert ran.scenario.stack is None
    assert all(env.closed for env in ran.scenario.environments)
    assert not list(ran.state.rglob("*-wal"))


def test_stored_verification_binds_the_exhaustion_refusal(ran: SimpleNamespace) -> None:
    verification = read_json(ran.state / "verification.json")
    assert verification["scenario"] == SCENARIO
    assert verification["refused_transitions"] == [
        {
            "event_type": "deployment.rollback_failed",
            "stage": "preactivation",
            "candidate_id": ran.lifecycle["candidates"]["B"],
            "error_class": "StatefulLoadError",
        }
    ]
    assert verification["exhaustion_refusal"]["selected_candidate_is_b"] is True
    assert verification["final_active_deployment_id"] == ran.lifecycle["deployments"]["A"]
    assert verification["fake_sends"] == {"qualification": 77, "B": 24, "smoke": 3}
    assert {r["client_episode_ref"] for r in verification["replays"]} == {
        "s8s-b-golden",
        "s8s-b-cap-probe",
    }
    assert verification["worker_enforcement"]["worker_count"] == 2
    assert verification["worker_enforcement"]["all_enforced"] is False
    assert verification["worker_enforcement"]["profiles_retained"] == 0
    assert [p["event"] for p in ran.lifecycle["worker_proofs"]] == ["deploy B", "deploy A"]
    verify_seal(ran.state)


def test_verify_and_report_use_the_scenario_and_leave_the_state_unchanged(
    ran: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = inventory(ran.state)
    with no_network():
        result = cli.verify(ran.state, ran.qualification)
    assert result["qualification_seal_verified"] is True
    assert result["fake_sends"] == {"qualification": 77, "B": 24, "smoke": 3}
    assert result["campaign_total"] == 104
    assert result["milestone_verdict"] is None
    assert [c["exit_status"] for c in ran.checks["checks"]] == [0]
    monkeypatch.setattr("sys.argv", ["s8_rehearsal", "report", "--state", str(ran.state)])
    cli.main()
    report = capsys.readouterr().out
    assert f"Supplemental scenario: `{SCENARIO}`." in report
    assert "rollback_selects_exhausted_b" in report and "deployment.rollback_failed" in report
    assert "PASS" not in report and "FAIL" not in report
    assert inventory(ran.state) == before


def test_verification_refuses_a_refusal_attributed_to_another_candidate(
    ran: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = supplement.read_json
    lifecycle = dict(original(ran.state / "lifecycle.json"))
    swapped = {**lifecycle, "candidates": {"A": lifecycle["candidates"]["B"], "B": "other"}}

    def altered(path: Path) -> Any:
        return swapped if path == ran.state / "lifecycle.json" else original(path)

    monkeypatch.setattr(supplement, "read_json", altered)
    with pytest.raises(ValueError):
        inspect_supplement(ran.state)


def test_a_full_rehearsal_plan_cannot_run_as_the_supplement(
    qualified_fixture: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synthetic_host(monkeypatch)
    approval = tmp_path / "approval.json"
    approval.write_bytes(json.dumps(approval_document(qualified_fixture)).encode())
    state = tmp_path / "full"
    prepare(qualified_fixture.parent / "checkout", qualified_fixture, state, approval_path=approval)
    assert "scenario" not in read_json(state / "plan.json")
    assert cli.scenario_of(state) is None
    lifecycle = RollbackSupplement(
        qualified_fixture.parent / "checkout",
        state,
        preparer_factory=unit_preparer(LocalWorkerLauncher()),
        require_os_sandbox=False,
    )
    with pytest.raises(RehearsalStopped, match="names a different scenario"):
        lifecycle.run()
    assert read_json(state / "failure.json")["milestone_verdict"] is None
    assert issubclass(RollbackSupplement, Rehearsal)
