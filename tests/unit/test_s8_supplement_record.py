"""The S8 supplement record is derived from stored inputs and records outcomes as observed."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from pixelgym.grounding.v5.contracts import content_digest
from pixelgym.platform.s7_qualification import seal as seal_qualification
from scripts import build_s8_supplement_record as generator
from scripts.build_s8_supplement_record import S7_RUN, S8_RUN, Inputs, MissingInput

PUBLIC = Path(__file__).resolve().parents[2] / "artifacts/evidence-s8-supplement-20261123"
REVISION = "6" * 40
S7_SENDS = {"qualification": 3}
S8_SENDS = {"B": 2, "qualification": 3, "smoke": 3}
PROFILE = b"(version 1)\n(deny default)\n"
PROFILE_DIGEST = "sha256:" + hashlib.sha256(PROFILE).hexdigest()
EXHAUSTED = "the deployment attempt cap for this exact version is already exhausted"


def _write(path: Path, value: Any) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    elif isinstance(value, str):
        path.write_text(value)
    else:
        path.write_text(json.dumps(value, sort_keys=True))
    return value


def _ledger(path: Path, counts: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE sends (phase TEXT, request_key TEXT)")
        for phase, count in counts.items():
            db.executemany(
                "INSERT INTO sends VALUES (?, ?)", [(phase, f"{phase}-{i}") for i in range(count)]
            )
        db.commit()


def _refusal(message: str = EXHAUSTED) -> dict[str, Any]:
    return {
        "selected_candidate_is_b": True,
        "refusal": {"error_class": "StatefulLoadError", "message": message},
        "audit": {"event_type": "deployment.rollback_failed", "candidate_id": "candidate-b"},
        "pointer_preserved": True,
        "b_attempts_before": 2,
        "b_attempts_after": 2,
        "smoke_sends_consumed_by_refusal": 1,
    }


def _lifecycle(state: Path, refusal: dict[str, Any], sends: dict[str, int]) -> dict[str, Any]:
    return _write(
        state / "lifecycle.json",
        {
            "scenario": generator.SCENARIO,
            "fake_sends": sends,
            "milestone_verdict": None,
            "caller_kinds": ["loopback-listener:127.0.0.1:1"],
            "actor_verification_source": "legacy_unverified",
            "os_sandbox_required": True,
            "worker_proofs": [
                {
                    "event": "deploy B",
                    "deployment_id": "deployment-b",
                    "mechanism": "fixture",
                    "os_sandbox_applied": True,
                    "profile_retained": True,
                    "profile_sha256": PROFILE_DIGEST,
                }
            ],
            "version_attempts": {"A": 0, "B": 2},
            "elapsed_seconds": 2.0,
            "steps": [
                {
                    "step": 3,
                    "name": "approve_and_deploy_a",
                    "elapsed_seconds": 1.0,
                    "fake_sends_after": sends,
                    "observations": {
                        "rollback_target_before_request": {
                            "candidate_id": "candidate-b",
                            "is_b": True,
                        }
                    },
                },
                {
                    "step": 4,
                    "name": "rollback_selects_exhausted_b",
                    "elapsed_seconds": 1.0,
                    "fake_sends_after": sends,
                    "observations": {"rollback_toward_exhausted_B": refusal},
                },
            ],
            "activation_performed": True,
            "publication_performed": False,
            "real_provider_requests": 0,
        },
    )


def _write_s8_outputs(inputs: Inputs, lifecycle: dict[str, Any], sends: dict[str, int]) -> None:
    state, logs = inputs.s8_run / "state", inputs.s8_run / "review/command-logs"
    verification = json.loads((state / "verification.json").read_text())
    output = {
        "fake_sends": sends,
        "lifecycle_sha256": content_digest(lifecycle),
        "milestone_verdict": None,
        "qualification_seal_verified": True,
        "verification_sha256": content_digest(verification),
    }
    _write(logs / "run.stdout.json", output)
    _write(logs / "verify-command.log", f"command: tool verify\n{json.dumps(output)}\nexit=0\n")


def build_tree(root: Path) -> tuple[Inputs, Path]:
    """A small synthetic copy of every private input the generator reads, plus a public folder."""
    inputs = Inputs(
        s7_run=root / "runs/s7",
        s8_run=root / "runs/s8",
        receipts=root / "receipts",
        archives=root / "archives",
        b2_logs=root / "runs/s8/review/b2-logs",
    )
    public = root / "public"
    q, s7_logs = inputs.s7_run / "qualification", inputs.s7_run / "review/command-logs"
    _write(q / "source-binding.json", {"revision": REVISION, "files": {}})
    lock = _write(q / "runtime-lock.json", {"python": "3.12.0", "distributions": {"a": {}}})
    policy = {"campaign_cap": 9, "phase_caps": {"A": 2, "B": 2, "qualification": 3, "smoke": 3}}
    _write(q / "gate-policy.json", policy)
    plan = _write(
        q / "plan.json",
        {
            "run_id": S7_RUN,
            "qualification_approval": "Owner approved in chat a fixture qualification.",
            "gate_policy_sha256": content_digest(policy).removeprefix("sha256:"),
            "runtime_lock_sha256": content_digest(lock),
            "cumulative_accounting": {
                "records": [{"qualification_sends": 4}],
                "previous_qualification_sends": 4,
                "qualification_allowance": 7,
                "campaign_allowance": 13,
            },
        },
    )
    verification = _write(q / "verification.json", {"cumulative_qualification_sends": 7})
    _ledger(q / "send-budget.sqlite", S7_SENDS)
    packages = {}
    for role in ("A", "B"):
        package = _write(q / f"packages/{role}/package.json", {"policy_id": f"sha256:{role}"})
        report = _write(q / f"packages/{role}/gate-report.json", {"overall_passed": True})
        packages[role] = {
            "package_sha256": content_digest(package),
            "gate_report_sha256": content_digest(report),
        }
    seal = seal_qualification(q)
    s7_output = {
        "activation_performed": False,
        "fake_sends": S7_SENDS,
        "packages": packages,
        "publication_performed": False,
        "real_provider_requests": 0,
        "report_sha256": "sha256:" + "r" * 64,
        "verification_sha256": content_digest(verification),
    }
    _write(s7_logs / "qualify.stdout.json", s7_output)
    _write(
        s7_logs / "prepare-command.log",
        f"command: tool prepare --run {Path.home()}/private/run\nsource_head: {REVISION}\n"
        '{"fake_sends": 0}\nexit=0\n',
    )
    _write(s7_logs / "qualify-command.log", "command: tool qualify\nexit=0\n")
    _write(s7_logs / "qualify.stderr.log", "")
    verify_line = json.dumps({k: s7_output[k] for k in ("report_sha256", "verification_sha256")})
    _write(s7_logs / "verify-command.log", f"command: tool verify\n{verify_line}\nexit=0\n")
    _write(s7_logs / "report-command.log", "command: tool report\nexit=0\n")
    _write(inputs.s7_run / "review/REPORT.md", b"# S7 report\n")

    state, s8_logs = inputs.s8_run / "state", inputs.s8_run / "review/command-logs"
    approval = _write(
        state / "approval.json",
        {"activation_approved": True, "publication_approved": False, "approved_on": "a-date"},
    )
    _write(
        state / "plan.json",
        {
            "scenario": generator.SCENARIO,
            "expected_sends": {"A": 0, "B": 2, "smoke": 3},
            "evidence_label": "fixture-label",
            "source_revision": REVISION,
            "approval_sha256": content_digest(approval),
            "qualification_plan_sha256": content_digest(plan),
            "qualification_seal_sha256": content_digest(seal),
        },
    )
    _write(state / f"worker-profiles/{PROFILE_DIGEST.removeprefix('sha256:')}.sb", PROFILE)
    lifecycle = _lifecycle(state, _refusal(), S8_SENDS)
    _write(state / "verification.json", {"campaign_total": 8})
    _write(state / "seal.json", {"files": {}})
    _write(
        state / "acceptance-checks.json",
        {"checks": [{"name": "replay", "exit_status": 0, "elapsed_seconds": 0.1}]},
    )
    _ledger(state / "send-budget.sqlite", S8_SENDS)
    _write_s8_outputs(inputs, lifecycle, S8_SENDS)
    _write(s8_logs / "prepare-command.log", "command: tool prepare\nexit=0\n")
    _write(s8_logs / "prepare.stderr.log", "")
    _write(s8_logs / "run-command.log", "command: tool run\nexit=0\n")
    _write(s8_logs / "report-command.log", "command: tool report\nexit=0\n")
    _write(inputs.s8_run / "review/REPORT.md", b"# S8 report\n")

    manifest = b'{"files": []}'
    files = []
    for run in (S7_RUN, S8_RUN):
        _write(inputs.receipts / f"{run}-local.json", {"bytes": 100, "file_count": 4})
        _write(inputs.archives / run / "manifest.json", manifest)
        files += [{"name": f"{run}/f{i}", "size": 25, "retention_mode": None} for i in range(4)]
        files.append(
            {"name": f"{run}/manifest.json", "size": len(manifest), "retention_mode": None}
        )
        logs = inputs.b2_logs
        _write(logs / f"{run}-copy.log", "started_utc: t0\ncommand: rclone copy x\nexit=0\n")
        _write(logs / f"{run}-check.stderr.log", "0 differences found\n5 matching files\n")
        _write(logs / f"{run}-check.exit", f"{run} check exit=0\n")
    _write(
        inputs.b2_logs / "object-lock.json",
        {
            "bucket": "a-private-bucket-name",
            "bucket_type": "allPrivate",
            "object_lock_enabled": True,
            "default_retention": {"mode": None, "period": None},
            "file_count": len(files),
            "bytes": sum(f["size"] for f in files),
            "files": files,
            "model_calls": 0,
            "mutations": 0,
        },
    )
    _write(inputs.b2_logs / "bucket-size.json", {"count": 20, "bytes": 2_000_000_000_000})
    _write(
        public / "operator-statements.json",
        {
            "schema_version": generator.STATEMENTS_SCHEMA,
            "owner_decisions": [{"id": 1, "decision": "x", "recorded_as": "chat"}],
            "operator_observations": {"backblaze_storage": {"storage_rate_usd_per_tb_month": 6.95}},
        },
    )
    return inputs, public


def _build(inputs: Inputs, public: Path) -> dict[str, Any]:
    return generator.build(inputs, public / "operator-statements.json")


def _argv(inputs: Inputs, public: Path, *extra: str) -> list[str]:
    argv = ["--statements", str(public / "operator-statements.json")]
    argv += ["--output", str(public / "record.json"), *extra]
    for name in Inputs.__dataclass_fields__:
        argv += [f"--{name.replace('_', '-')}", str(getattr(inputs, name))]
    return argv


def test_counts_digests_and_rollback_observations_are_derived(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)

    record = _build(inputs, public)
    derived = record["derived"]

    assert record["schema_version"] == generator.SCHEMA and record["milestone_verdict"] is None
    qualified, supplement = derived["qualification"], derived["supplement"]
    assert qualified["run_id"] == S7_RUN and supplement["run_id"] == S8_RUN
    assert qualified["ledger_sends"] == S7_SENDS and supplement["ledger_sends"] == S8_SENDS
    assert qualified["qualification_approval"].startswith("Owner approved in chat")
    assert supplement["scenario"] == generator.SCENARIO
    assert supplement["campaign_total"] == 8 and supplement["approval"]["actor"] == "withheld"
    assert supplement["rollback_target_before_request"] == {
        "candidate_id": "candidate-b",
        "is_b": True,
    }
    assert supplement["rollback_toward_exhausted_B"]["refusal"]["message"] == EXHAUSTED
    assert supplement["worker_proofs"][0]["stored_profile_matches_digest"] is True
    prefixes = derived["retention"]["backblaze_prefixes"]
    assert prefixes[S7_RUN]["count_reconciliation"]["observed_equals_expected"] is True
    assert prefixes[S8_RUN]["matching_files"] == 5 and prefixes[S8_RUN]["check_exit_status"] == 0
    assert derived["retention"]["object_lock_observation"]["observed_equals_both_prefixes"] is True
    assert derived["storage_estimate"]["estimated_monthly_charge_usd"] == 13.9
    rendered = generator.encode(record)
    assert "a-private-bucket-name" not in rendered and str(Path.home()) not in rendered


def test_a_refusal_with_another_cause_is_recorded_not_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    state = inputs.s8_run / "state"
    other = {**_refusal("worker failed to start"), "selected_candidate_is_b": False}
    _write_s8_outputs(inputs, _lifecycle(state, other, S8_SENDS), S8_SENDS)

    supplement = _build(inputs, public)["derived"]["supplement"]

    assert (
        supplement["rollback_toward_exhausted_B"]["refusal"]["message"] == "worker failed to start"
    )
    assert supplement["rollback_toward_exhausted_B"]["selected_candidate_is_b"] is False


def test_send_counts_that_differ_from_the_plan_are_recorded_not_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    state = inputs.s8_run / "state"
    sends = {"B": 2, "qualification": 3, "smoke": 4}
    (state / "send-budget.sqlite").unlink()
    _ledger(state / "send-budget.sqlite", sends)
    _write_s8_outputs(inputs, _lifecycle(state, _refusal(), sends), sends)

    supplement = _build(inputs, public)["derived"]["supplement"]

    assert supplement["ledger_sends"] == sends
    assert supplement["plan_expected_sends"] == {"A": 0, "B": 2, "smoke": 3}


def test_an_incomplete_upload_is_recorded_as_not_reconciling(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    observed = json.loads((inputs.b2_logs / "object-lock.json").read_text())
    observed["files"] = [f for f in observed["files"] if f["name"] != f"{S8_RUN}/f0"]
    _write(inputs.b2_logs / "object-lock.json", observed)

    retention = _build(inputs, public)["derived"]["retention"]

    assert (
        retention["backblaze_prefixes"][S8_RUN]["count_reconciliation"]["observed_equals_expected"]
        is False
    )
    assert (
        retention["backblaze_prefixes"][S7_RUN]["count_reconciliation"]["observed_equals_expected"]
        is True
    )


def test_an_altered_worker_profile_is_recorded_as_not_matching(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    profile = inputs.s8_run / f"state/worker-profiles/{PROFILE_DIGEST.removeprefix('sha256:')}.sb"
    profile.write_bytes(b"(version 1)\n(allow default)\n")

    proofs = _build(inputs, public)["derived"]["supplement"]["worker_proofs"]

    assert proofs[0]["stored_profile_matches_digest"] is False


def test_a_plan_for_another_scenario_is_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    plan_path = inputs.s8_run / "state/plan.json"
    _write(plan_path, {**json.loads(plan_path.read_text()), "scenario": None})

    with pytest.raises(ValueError, match="rollback-for-exhaustion scenario"):
        _build(inputs, public)


def test_a_lifecycle_digest_that_differs_from_the_run_output_is_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    run_output = inputs.s8_run / "review/command-logs/run.stdout.json"
    _write(
        run_output, {**json.loads(run_output.read_text()), "lifecycle_sha256": "sha256:" + "0" * 64}
    )

    with pytest.raises(ValueError, match="lifecycle digest differs"):
        _build(inputs, public)


@pytest.mark.parametrize(
    "relative",
    [
        "runs/s8/review/b2-logs/bucket-size.json",
        f"runs/s8/review/b2-logs/{S7_RUN}-check.exit",
        f"receipts/{S8_RUN}-local.json",
        "runs/s7/review/command-logs/qualify.stdout.json",
    ],
)
def test_a_missing_private_input_fails_instead_of_emitting_a_placeholder(
    tmp_path: Path, relative: str
) -> None:
    inputs, public = build_tree(tmp_path)
    (tmp_path / relative).unlink()

    with pytest.raises(MissingInput):
        _build(inputs, public)


def test_an_unexpected_operator_statements_schema_is_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    _write(public / "operator-statements.json", {"schema_version": "other"})

    with pytest.raises(ValueError, match="operator-statements schema"):
        _build(inputs, public)


def test_check_passes_on_a_fresh_record_and_fails_after_one_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs, public = build_tree(tmp_path)
    assert generator.main(_argv(inputs, public)) == 0
    assert generator.main(_argv(inputs, public, "--check")) == 0

    stored = json.loads((public / "record.json").read_text())
    stored["derived"]["supplement"]["campaign_total"] = 9
    (public / "record.json").write_text(json.dumps(stored, indent=2, sort_keys=True) + "\n")

    assert generator.main(_argv(inputs, public, "--check")) == 1
    assert "/derived/supplement/campaign_total" in capsys.readouterr().err


def test_checked_in_record_and_statements_have_the_expected_shape() -> None:
    record = json.loads((PUBLIC / "record.json").read_text())
    statements_bytes = (PUBLIC / "operator-statements.json").read_bytes()

    assert record["schema_version"] == generator.SCHEMA and record["milestone_verdict"] is None
    assert record["operator_statements"] == json.loads(statements_bytes)
    assert record["generated_by"]["operator_statements_sha256"] == (
        hashlib.sha256(statements_bytes).hexdigest()
    )
    assert record["derived"]["supplement"]["scenario"] == generator.SCENARIO
    assert record["derived"]["supplement"]["approval"]["actor"] == "withheld"


def test_checked_in_files_hold_no_local_user_path_or_name() -> None:
    for path in sorted(PUBLIC.iterdir()):
        assert not generator.exposes_local_user(path.read_text(encoding="utf-8")), path.name
