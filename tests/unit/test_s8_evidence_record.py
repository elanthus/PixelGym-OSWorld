"""The S8 evidence record is derived from stored inputs and checked against the stored file."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import pytest

from pixelgym.grounding.v5.contracts import content_digest
from scripts import build_s8_evidence_record as generator
from scripts.build_s8_evidence_record import NOT_CAPTURED, Inputs, MissingInput

PUBLIC = Path(__file__).resolve().parents[2] / "artifacts/evidence-s8-rehearsal-20261119"
REVISION = "5" * 40
S7_SENDS = {"qualification": 3}
S8_SENDS = {"A": 1, "B": 2, "qualification": 3, "smoke": 1}


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
        db.execute("CREATE TABLE campaign (paused INTEGER, activation_approval TEXT)")
        db.execute("INSERT INTO campaign VALUES (1, NULL)")
        for phase, count in counts.items():
            db.executemany(
                "INSERT INTO sends VALUES (?, ?)", [(phase, f"{phase}-{i}") for i in range(count)]
            )
        db.commit()


def _steps(path: Path, rows: list[dict[str, Any]]) -> bytes:
    data = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    _write(path, data)
    return data


def _observation(path: Path, files: int, size: int) -> None:
    _write(
        path,
        {
            "bucket": "a-private-bucket-name",
            "bucket_type": "allPrivate",
            "object_lock_enabled": True,
            "default_retention": {"mode": None, "period": None},
            "file_count": files,
            "bytes": size,
            "files": [{"name": "f", "size": size, "retention_mode": None}],
            "model_calls": 0,
            "mutations": 0,
        },
    )


def build_tree(root: Path) -> tuple[Inputs, Path]:
    """A small synthetic copy of every private input the generator reads, plus a public folder."""
    inputs = Inputs(
        s7_run=root / "runs/s7",
        s8_run=root / "runs/s8",
        receipts=root / "receipts",
        archives=root / "archives",
        drill=root / "drill",
        cache_s8=root / "cache/s8",
        cache_s7_backup=root / "cache/s7-backup",
        cache_drill=root / "cache/drill",
    )
    public = root / "public"
    q, s7_logs = inputs.s7_run / "qualification", inputs.s7_run / "review/command-logs"
    binding = _write(q / "source-binding.json", {"revision": REVISION, "files": {}})
    _write(q / "runtime-lock.json", {"python": "3.12.0", "distributions": {"a": {}, "b": {}}})
    policy = {"campaign_cap": 9, "phase_caps": {"A": 2, "B": 2, "qualification": 3, "smoke": 2}}
    _write(q / "gate-policy.json", policy)
    plan = _write(
        q / "plan.json",
        {
            "run_id": "s7-fixture",
            "gate_policy_sha256": "p" * 64,
            "cumulative_accounting": {
                "records": [{"qualification_sends": 0}, {"qualification_sends": 4}],
                "previous_qualification_sends": 4,
                "qualification_allowance": 7,
                "campaign_allowance": 13,
            },
        },
    )
    seal = _write(q / "seal.json", {"files": {"plan.json": "x"}})
    verification = _write(q / "verification.json", {"cumulative_qualification_sends": 7})
    _ledger(q / "send-budget.sqlite", S7_SENDS)
    packages = {}
    for role in ("A", "B"):
        package = _write(q / f"packages/{role}/package.json", {"policy_id": f"sha256:{role}"})
        report = _write(
            q / f"packages/{role}/gate-report.json", {"overall_passed": True, "r": role}
        )
        packages[role] = {
            "package_sha256": content_digest(package),
            "gate_report_sha256": content_digest(report),
        }
    s7_output = {
        "activation_performed": False,
        "fake_sends": S7_SENDS,
        "packages": packages,
        "publication_performed": False,
        "real_provider_requests": 0,
        "report_sha256": "sha256:" + "r" * 64,
        "verification_sha256": content_digest(verification),
    }
    _write(s7_logs / "qualification.stdout.json", s7_output)
    _write(
        s7_logs / "prepare-command.log",
        f"command: tool prepare --run {Path.home()}/private/run\nstarted_utc: t0\n"
        f"source_head: {REVISION}\ngit_status_entries: 0\n"
        '{"fake_sends": 0}\nexit=0\nfinished_utc: t1\n',
    )
    _write(s7_logs / "qualify-command.log", "command: tool qualify\nstarted_utc: t1\nexit=0\n")
    _write(s7_logs / "qualify.stderr.log", "")
    verify_line = json.dumps(
        {k: s7_output[k] for k in ("report_sha256", "verification_sha256")}, sort_keys=True
    )
    _write(s7_logs / "verify-command.log", f"command: tool verify\n{verify_line}\nexit=0\n")
    _write(s7_logs / "report-command.log", "report exit=0,       12 lines, stderr        0 bytes\n")
    s7_report = _write(inputs.s7_run / "review/REPORT.md", b"# S7 report\n")

    state, s8_logs = inputs.s8_run / "state", inputs.s8_run / "review/command-logs"
    approval = _write(
        state / "approval.json",
        {"activation_approved": True, "publication_approved": False, "approved_on": "a-date"},
    )
    _write(
        state / "plan.json",
        {
            "evidence_label": "fixture-label",
            "source_revision": REVISION,
            "approval_sha256": content_digest(approval),
            "qualification_plan_sha256": content_digest(plan),
            "qualification_seal_sha256": content_digest(seal),
        },
    )
    lifecycle = _write(
        state / "lifecycle.json",
        {
            "fake_sends": S8_SENDS,
            "milestone_verdict": None,
            "caller_kinds": ["in-process-asgi", "in-process-asgi"],
            "actor_verification_source": "legacy_unverified",
            "os_sandbox_required": True,
            "worker_proofs": [
                {
                    "event": "deploy A",
                    "deployment_id": "deployment-1",
                    "mechanism": "fixture",
                    "os_sandbox_applied": True,
                    "profile_sha256": "sha256:" + "f" * 64,
                }
            ],
            "version_attempts": {"A": 1, "B": 2},
            "elapsed_seconds": 1.5,
            "steps": [
                {"step": 1, "name": "one", "elapsed_seconds": 1.5, "fake_sends_after": S8_SENDS}
            ],
            "activation_performed": True,
            "publication_performed": False,
            "real_provider_requests": 0,
        },
    )
    s8_verification = _write(state / "verification.json", {"campaign_total": 7})
    _write(state / "seal.json", {"files": {}})
    _write(
        state / "acceptance-checks.json",
        {"checks": [{"name": "replay", "exit_status": 0, "elapsed_seconds": 0.1, "stdout": "x"}]},
    )
    _ledger(state / "send-budget.sqlite", S8_SENDS)
    s8_output = {
        "fake_sends": S8_SENDS,
        "lifecycle_sha256": content_digest(lifecycle),
        "milestone_verdict": None,
        "qualification_seal_verified": True,
        "verification_sha256": content_digest(s8_verification),
    }
    _write(s8_logs / "run.stdout.json", s8_output)
    _write(s8_logs / "prepare-command.log", "command: tool prepare\nexit=0\n")
    _write(s8_logs / "prepare.stderr.log", "")
    _write(s8_logs / "run-command.log", "command: tool run\nexit=0\nstderr_bytes: 0\n")
    _write(
        s8_logs / "verify-command.log",
        f"command: tool verify\n{json.dumps(s8_output, sort_keys=True)}\nexit=0\n",
    )
    _write(s8_logs / "report-command.log", "report exit=0,       30 lines, stderr        0 bytes\n")
    s8_report = _write(inputs.s8_run / "review/REPORT.md", b"# S8 report\n")

    manifest = b'{"files": []}'
    for run in generator.ARCHIVED_RUNS:
        _write(inputs.receipts / f"{run}-local.json", {"bytes": 100, "file_count": 4})
        _write(inputs.archives / run / "manifest.json", manifest)
    uploaded = 100 + len(manifest)
    _observation(inputs.cache_s7_backup / "object-lock.json", 5, uploaded)
    _write(inputs.cache_s7_backup / "copy.log", "copy exit=0\n")
    _write(
        inputs.cache_s7_backup / "check.log",
        "NOTICE: 0 differences found\nNOTICE: 5 matching files\ncheck exit=0\n",
    )
    _observation(inputs.cache_s8 / "object-lock.json", 5, uploaded)
    _write(inputs.cache_s8 / "copy.log", "NOTICE: nothing else\n")
    _write(inputs.cache_s8 / "check.log", "NOTICE: 0 differences found\nNOTICE: 5 matching files\n")
    _observation(inputs.cache_drill / "object-lock.json", 2, 20)

    recovery = inputs.cache_s8 / "recovery-checks"
    row = {"name": "s8-local-verify", "exit_status": 0, "command": "verify ~/restored"}
    _write(public / "recovery-check-steps.jsonl", _steps(recovery / "steps.jsonl", [row]))
    for copy in ("local", "b2"):
        _write(recovery / f"s8-{copy}-verify.stdout", s8_output)
        _write(recovery / f"s7-{copy}-verify.stdout", s7_output)
        _write(recovery / f"s8-{copy}-report.stdout", s8_report)
        _write(recovery / f"s7-{copy}-report.stdout", s7_report)
    regression = [{"name": "unit", "exit_status": 0, "summary_line": "1 passed"}]
    _write(
        public / "acceptance-regression-steps.jsonl",
        _steps(inputs.cache_s8 / "acceptance-regression/steps.jsonl", regression),
    )

    verifier = _write(inputs.drill / "tools/verify_s7_bundle.py", b"print('verify')\n")
    _write(public / "recovery-drill-20261122/verify_s7_bundle.py.txt", verifier)
    _write(inputs.drill / "tools/drill.sh", b"#!/bin/sh\n")
    for side in ("local", "b2"):
        logs = inputs.drill / f"drill-{side}/logs"
        rows = [
            {"name": "restore", "expected_exit": "zero", "exit_status": 0, "sandboxed": True},
            {"name": "negative", "expected_exit": "nonzero", "exit_status": 1, "sandboxed": True},
        ]
        _write(
            public / f"recovery-drill-20261122/{side}-steps.jsonl",
            _steps(logs / "steps.jsonl", rows),
        )
        _write(
            logs / "s7-bundle-verify.stdout",
            {
                "verification_sha256": content_digest(verification),
                "seal_sha256": content_digest(seal),
            },
        )
        _write(logs / "s8-recovery-verify.stdout", s8_output)
        _write(logs / "s8-report.stdout", s8_report)
        _write(logs / "checkout-revision.txt", "c" * 40 + "\n")
        _write(inputs.drill / f"drill-{side}/sandbox-profile.sb", b"(version 1)\n")
        _write(inputs.drill / f"drill-{side}/s8/run/review/REPORT.md", s8_report)
        _write(logs / "negative-absent-qualification.stderr", "trace\nValueError: absent\n")
        _write(logs / "negative-different-qualification.stderr", "ValueError: differs\n")
        _write(
            logs / "observe-plain-verify-without-qualification.stderr",
            f"PermissionError: '{Path.home()}/private/qualification'\n",
        )

    _write(
        public / "operator-statements.json",
        {
            "schema_version": generator.STATEMENTS_SCHEMA,
            "owner_decisions": [{"id": 1, "date": "d", "decision": "x", "recorded_as": "chat"}],
            "operator_observations": {
                "backblaze_storage": {
                    "bucket_total_bytes_with_versions_after_drill_upload": 2_000_000_000_000,
                    "storage_rate_usd_per_tb_month": 6.95,
                }
            },
        },
    )
    assert binding["revision"] == REVISION
    return inputs, public


def _argv(inputs: Inputs, public: Path, *extra: str) -> list[str]:
    argv = [
        "--statements",
        str(public / "operator-statements.json"),
        "--output",
        str(public / "record.json"),
        *extra,
    ]
    for name in Inputs.__dataclass_fields__:
        argv += [f"--{name.replace('_', '-')}", str(getattr(inputs, name))]
    return argv


def test_counts_and_digests_are_derived_from_the_stored_inputs(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)

    record = generator.build(inputs, public / "operator-statements.json")
    derived = record["derived"]

    assert record["schema_version"] == generator.SCHEMA and record["milestone_verdict"] is None
    qualified, rehearsed = derived["qualification"], derived["rehearsal"]
    assert qualified["ledger_sends"] == S7_SENDS and rehearsed["ledger_sends"] == S8_SENDS
    assert rehearsed["campaign_total"] == 7 and rehearsed["campaign_cap"] == 9
    plan = json.loads((inputs.s7_run / "qualification/plan.json").read_text())
    assert qualified["plan_sha256"] == content_digest(plan)
    assert qualified["predecessor_qualification_sends"] == [0, 4]
    assert qualified["runtime"]["distribution_count"] == 2
    assert qualified["rendered_report_file_sha256"] == hashlib.sha256(b"# S7 report\n").hexdigest()
    assert rehearsed["approval"]["actor"] == "withheld"
    assert rehearsed["worker_proofs"] == [
        {
            "event": "deploy A",
            "mechanism": "fixture",
            "os_sandbox_applied": True,
            "profile_sha256": "sha256:" + "f" * 64,
        }
    ]
    prefixes = derived["retention"]["backblaze_prefixes"]
    assert prefixes[generator.S7_RUN]["copy_exit_status"] == 0
    assert prefixes[generator.S7_RUN]["check_exit_status"] == 0
    assert prefixes[generator.S8_RUN]["copy_exit_status"] == NOT_CAPTURED
    assert prefixes[generator.S8_RUN]["check_exit_status"] == NOT_CAPTURED
    assert prefixes[generator.S8_RUN]["count_reconciliation"]["uploaded_files"] == 5
    assert prefixes[generator.S8_RUN]["file_retention_modes_observed"] == [None]
    assert "a-private-bucket-name" not in json.dumps(record)
    drill = derived["recovery_drill_20261122"]
    assert drill["local"]["expected_zero_all_zero"] and drill["b2"]["expected_nonzero_all_nonzero"]
    assert drill["verifier_outputs_identical_across_drills"] is True
    assert drill["local"]["stderr_last_line"]["negative-absent-qualification"] == (
        "ValueError: absent"
    )
    assert derived["storage_estimate"]["estimated_monthly_charge_usd"] == 13.9
    assert record["operator_statements"]["owner_decisions"][0]["recorded_as"] == "chat"
    assert all(c["equals_private_source"] for c in derived["checked_in_copies"].values())


def test_local_user_paths_are_redacted(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)

    rendered = generator.encode(generator.build(inputs, public / "operator-statements.json"))

    assert str(Path.home()) not in rendered and "/Users/" not in rendered
    assert "tool prepare --run ~/private/run" in rendered
    assert "PermissionError: '~/private/qualification'" in rendered


def test_check_passes_on_a_fresh_record_and_fails_after_one_edit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inputs, public = build_tree(tmp_path)
    assert generator.main(_argv(inputs, public)) == 0
    assert generator.main(_argv(inputs, public, "--check")) == 0

    output = public / "record.json"
    stored = json.loads(output.read_text())
    stored["derived"]["rehearsal"]["campaign_total"] = 8
    output.write_text(generator.encode(stored))
    capsys.readouterr()
    assert generator.main(_argv(inputs, public, "--check")) == 1
    message = capsys.readouterr().err
    assert "/derived/rehearsal/campaign_total: generated 7 != stored 8" in message
    assert json.loads(output.read_text())["derived"]["rehearsal"]["campaign_total"] == 8

    output.unlink()
    assert generator.main(_argv(inputs, public, "--check")) == 1


@pytest.mark.parametrize(
    "missing",
    [
        "runs/s8/state/lifecycle.json",
        "runs/s7/qualification/send-budget.sqlite",
        "receipts/s8-20261119-main-local.json",
        "cache/s8/check.log",
        "drill/drill-b2/logs/s8-recovery-verify.stdout",
    ],
)
def test_a_missing_private_input_fails_instead_of_emitting_a_placeholder(
    tmp_path: Path, missing: str
) -> None:
    inputs, public = build_tree(tmp_path)
    (tmp_path / missing).unlink()

    with pytest.raises(MissingInput, match="required private input is absent"):
        generator.build(inputs, public / "operator-statements.json")
    assert not (public / "record.json").exists()


def test_disagreeing_private_evidence_is_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    ledger = inputs.s8_run / "state/send-budget.sqlite"
    with closing(sqlite3.connect(ledger)) as db:
        db.execute("INSERT INTO sends VALUES ('B', 'extra')")
        db.commit()
    with pytest.raises(ValueError, match="S8 send counts differ"):
        generator.build(inputs, public / "operator-statements.json")

    inputs, public = build_tree(tmp_path / "second")
    copied = public / "recovery-check-steps.jsonl"
    copied.write_text(copied.read_text() + "\n")
    with pytest.raises(ValueError, match="differs from its private source"):
        generator.build(inputs, public / "operator-statements.json")


def test_an_unexpected_operator_statements_schema_is_refused(tmp_path: Path) -> None:
    inputs, public = build_tree(tmp_path)
    statements = public / "operator-statements.json"
    value = json.loads(statements.read_text())
    statements.write_text(json.dumps({**value, "schema_version": "other"}))
    with pytest.raises(ValueError, match="operator-statements schema"):
        generator.build(inputs, statements)


def test_checked_in_record_and_statements_have_the_expected_shape() -> None:
    record = json.loads((PUBLIC / "record.json").read_text())
    statements = json.loads((PUBLIC / "operator-statements.json").read_text())

    assert record["schema_version"] == generator.SCHEMA
    assert statements["schema_version"] == generator.STATEMENTS_SCHEMA
    assert record["milestone_verdict"] is None
    assert record["operator_statements"] == statements
    assert (
        record["generated_by"]["operator_statements_sha256"]
        == hashlib.sha256((PUBLIC / "operator-statements.json").read_bytes()).hexdigest()
    )
    assert set(record["derived"]) == {
        "acceptance_regression",
        "checked_in_copies",
        "qualification",
        "recovery_checks_20261120",
        "recovery_drill_20261122",
        "rehearsal",
        "retention",
        "storage_estimate",
    }
    assert {"owner_decisions", "operator_observations", "not_captured", "review_findings"} <= set(
        statements
    )
    assert [d["id"] for d in statements["owner_decisions"]] == list(range(1, 8))
    assert record["derived"]["rehearsal"]["approval"]["actor"] == "withheld"
    for name, copy in record["derived"]["checked_in_copies"].items():
        assert copy["sha256"] == hashlib.sha256((PUBLIC / name).read_bytes()).hexdigest()


def test_checked_in_files_hold_no_local_user_path_or_name() -> None:
    for name in ("record.json", "operator-statements.json"):
        text = (PUBLIC / name).read_text()
        assert "/Users/" not in text and "/home/" not in text
        assert f"/{Path.home().name}" not in text
