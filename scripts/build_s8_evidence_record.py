"""Build or check the S8 rehearsal evidence record from private stored evidence; no network.

The record under ``artifacts/evidence-s8-rehearsal-20261119/`` has two kinds of content:

* ``derived``: computed here from the sealed S7 qualification, the sealed S8 state, the archive
  receipts, and the retained command and step logs. Nothing in it is typed by hand.
* ``operator_statements``: copied verbatim from ``operator-statements.json``. It holds what cannot
  be derived: owner decisions, review findings, limits, values the operator saw on a terminal
  that no retained log holds, and fields that were never captured.

The private inputs stay private. Only digests, counts, exit statuses, timestamps, and commands
with local paths redacted reach the record. ``--check`` rebuilds the record in memory and exits
nonzero when it differs from the checked-in file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from collections.abc import Iterator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pixelgym.grounding.v5.contracts import content_digest
from pixelgym.platform.s7_evidence import inventory

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLIC = REPOSITORY_ROOT / "artifacts/evidence-s8-rehearsal-20261119"
SCHEMA = "pixelgym-s8-rehearsal-evidence-record-v2"
STATEMENTS_SCHEMA = "pixelgym-s8-operator-statements-v1"
NOT_CAPTURED = "not captured in a retained log"
S7_RUN, S8_RUN, DRILL_PREFIX = "s7-20261119-main", "s8-20261119-main", "s8-recovery-drill-20261122"
ARCHIVED_RUNS = ("s7-20261027-s8driver", S7_RUN, S8_RUN)
_HOME = Path.home()
_STATE = _HOME / ".local/state/pixelgym"
# An absolute home directory on macOS or Linux at the start of a path, not a nested directory
# such as ``~/dev/x/root``; ``~/`` paths are already redacted.
_HOME_PATH = re.compile(r"(?<![\w.~-])(?:(?:/Users|/home)/[^/\s\"']+|/root(?=[/\s\"']|$))")


class MissingInput(ValueError):
    """A private input the record depends on is absent; never emit a placeholder for it."""


@dataclass(frozen=True)
class Inputs:
    """Where the private evidence and the retained logs live."""

    s7_run: Path
    s8_run: Path
    receipts: Path
    archives: Path
    drill: Path
    cache_s8: Path
    cache_s7_backup: Path
    cache_drill: Path

    @classmethod
    def defaults(cls) -> Inputs:
        cache = REPOSITORY_ROOT / ".cache"
        return cls(
            s7_run=_STATE / "evidence/runs" / S7_RUN,
            s8_run=_STATE / "evidence/runs" / S8_RUN,
            receipts=_STATE / "evidence/receipts",
            archives=_STATE / "evidence/archives",
            drill=_STATE / "recovery/20261122",
            cache_s8=cache / S8_RUN,
            cache_s7_backup=cache / f"{S7_RUN}-backup",
            cache_drill=cache / DRILL_PREFIX,
        )


# Reading -------------------------------------------------------------------------------------


def _bytes(path: Path) -> bytes:
    if not path.is_file():
        raise MissingInput(f"required private input is absent: {redact(str(path))}")
    return path.read_bytes()


def _json(path: Path) -> Any:
    return json.loads(_bytes(path))


def _text(path: Path) -> str:
    return _bytes(path).decode()


def _sha256(path: Path) -> str:
    return hashlib.sha256(_bytes(path)).hexdigest()


def _steps(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in _text(path).splitlines() if line.strip()]


def redact(text: str) -> str:
    """Replace the operator's home directory, and any other user directory, with ``~``."""
    text = text.replace(str(_HOME), "~")
    return _HOME_PATH.sub("~", text)


def _strings(value: Any) -> Iterator[str]:
    """Every decoded string key and value, so JSON escaping cannot hide a match."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)


def exposes_local_user(text: str) -> bool:
    """Whether text still holds an absolute home path or the account name as a whole word.

    ``_`` is a word character, so an account named like a common word (``sandbox``) does not
    match inside keys such as ``worker_os_sandbox_required``; a standalone occurrence does.
    """
    return (
        str(_HOME) in text
        or _HOME_PATH.search(text) is not None
        or re.search(rf"\b{re.escape(_HOME.name)}\b", text) is not None
    )


def ledger_counts(path: Path) -> dict[str, int]:
    """Durable fake-send counts per phase, read from the SQLite ledger without changing it."""
    if not path.is_file():
        raise MissingInput(f"required private input is absent: {redact(str(path))}")
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        return {
            str(k): int(v)
            for k, v in db.execute("SELECT phase, count(*) FROM sends GROUP BY phase")
        }


def command_log(path: Path) -> dict[str, Any]:
    """Parse a retained command log: ``key: value`` lines, ``exit=N``, and one JSON output line."""
    record: dict[str, Any] = {"log": path.name, "exit_status": NOT_CAPTURED}
    for line in _text(path).splitlines():
        line = line.strip()
        if match := re.fullmatch(
            r"(?:report )?exit=(\d+)(?:,\s*(\d+) lines, stderr\s+(\d+) bytes)?", line
        ):
            record["exit_status"] = int(match[1])
            if match[2] is not None:
                record["output_lines"], record["stderr_bytes"] = int(match[2]), int(match[3])
        elif line.startswith("{"):
            record["output"] = json.loads(line)
        elif match := re.fullmatch(r"(command|started_utc|finished_utc|source_head): (.+)", line):
            record[match[1]] = redact(match[2])
        elif match := re.fullmatch(r"(git_status_entries|stderr_bytes): (\d+)", line):
            record[match[1]] = int(match[2])
    return record


def _rclone_check(path: Path) -> dict[str, Any]:
    text = _text(path)
    differences = re.findall(r"(\d+) differences found", text)
    matching = re.findall(r"(\d+) matching files", text)
    status = re.search(r"check exit=(\d+)", text)
    if not differences or not matching:
        raise MissingInput(f"rclone check log holds no result: {redact(str(path))}")
    return {
        "differences": int(differences[-1]),
        "matching_files": int(matching[-1]),
        "check_exit_status": int(status[1]) if status else NOT_CAPTURED,
    }


def _copy_exit(path: Path) -> int | str:
    status = re.search(r"copy exit=(\d+)", _text(path))
    return int(status[1]) if status else NOT_CAPTURED


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"private evidence disagrees with itself: {message}")


# Sections ------------------------------------------------------------------------------------


def qualification(
    inputs: Inputs, qualify_stdout: str = "qualification.stdout.json"
) -> dict[str, Any]:
    run, logs = inputs.s7_run / "qualification", inputs.s7_run / "review/command-logs"
    plan, lock = _json(run / "plan.json"), _json(run / "runtime-lock.json")
    _require(
        plan["runtime_lock_sha256"] == content_digest(lock),
        "S7 runtime lock differs from the digest its plan binds",
    )
    binding, accounting = _json(run / "source-binding.json"), plan["cumulative_accounting"]
    qualify_output = _json(logs / qualify_stdout)
    verify = command_log(logs / "verify-command.log")
    verification_sha256 = content_digest(_json(run / "verification.json"))
    counts = ledger_counts(run / "send-budget.sqlite")
    packages = {}
    for role in ("A", "B"):
        package = _json(run / f"packages/{role}/package.json")
        report = _json(run / f"packages/{role}/gate-report.json")
        packages[role] = {
            "policy_id": package["policy_id"],
            "package_sha256": content_digest(package),
            "gate_report_sha256": content_digest(report),
            "stored_gate_overall_passed": report["overall_passed"],
        }
        logged = qualify_output["packages"][role]
        _require(
            logged["package_sha256"] == packages[role]["package_sha256"]
            and logged["gate_report_sha256"] == packages[role]["gate_report_sha256"],
            f"package {role} digests differ from the qualify output",
        )
    _require(counts == qualify_output["fake_sends"], "S7 ledger differs from the qualify output")
    _require(
        verification_sha256
        == qualify_output["verification_sha256"]
        == verify["output"]["verification_sha256"],
        "S7 verification digest differs across verification.json, qualify, and verify",
    )
    _require(
        qualify_output["report_sha256"] == verify["output"]["report_sha256"],
        "S7 report digest differs between qualify and verify",
    )
    qualify = command_log(logs / "qualify-command.log")
    qualify["stderr_bytes"] = len(_bytes(logs / "qualify.stderr.log"))
    # After every read, so a deleted input raises MissingInput rather than a seal mismatch.
    _require(inventory(run) == _json(run / "seal.json"), "S7 qualification differs from its seal")
    return {
        "run_id": plan["run_id"],
        "source_revision": binding["revision"],
        "source_binding_sha256": content_digest(binding),
        "runtime": {
            "python": lock["python"],
            "distribution_count": len(lock["distributions"]),
            "runtime_lock_sha256": content_digest(lock),
        },
        "gate_policy_sha256": plan["gate_policy_sha256"],
        "plan_sha256": content_digest(plan),
        "seal_sha256": content_digest(_json(run / "seal.json")),
        "verification_sha256": verification_sha256,
        "report_sha256": qualify_output["report_sha256"],
        "rendered_report_file_sha256": _sha256(inputs.s7_run / "review/REPORT.md"),
        "ledger_sends": counts,
        "predecessor_qualification_sends": [
            r["qualification_sends"] for r in accounting["records"]
        ],
        "previous_qualification_sends": accounting["previous_qualification_sends"],
        "qualification_allowance": accounting["qualification_allowance"],
        "campaign_allowance": accounting["campaign_allowance"],
        "activation_performed": qualify_output["activation_performed"],
        "publication_performed": qualify_output["publication_performed"],
        "real_provider_requests": qualify_output["real_provider_requests"],
        "packages": packages,
        "commands": [
            command_log(logs / "prepare-command.log"),
            qualify,
            verify,
            command_log(logs / "report-command.log"),
        ],
    }


def rehearsal(inputs: Inputs, qualified: dict[str, Any]) -> dict[str, Any]:
    state, logs = inputs.s8_run / "state", inputs.s8_run / "review/command-logs"
    plan, lifecycle = _json(state / "plan.json"), _json(state / "lifecycle.json")
    approval = _json(state / "approval.json")
    run_output = _json(logs / "run.stdout.json")
    counts = ledger_counts(state / "send-budget.sqlite")
    lifecycle_sha256 = content_digest(lifecycle)
    verification_sha256 = content_digest(_json(state / "verification.json"))
    verify = command_log(logs / "verify-command.log")
    _require(
        plan["approval_sha256"] == content_digest(approval), "approval digest differs from the plan"
    )
    _require(counts == lifecycle["fake_sends"] == run_output["fake_sends"], "S8 send counts differ")
    _require(
        lifecycle_sha256 == run_output["lifecycle_sha256"] == verify["output"]["lifecycle_sha256"],
        "S8 lifecycle digest differs across lifecycle.json, run, and verify",
    )
    _require(
        verification_sha256
        == run_output["verification_sha256"]
        == verify["output"]["verification_sha256"],
        "S8 verification digest differs across verification.json, run, and verify",
    )
    _require(
        plan["qualification_plan_sha256"] == qualified["plan_sha256"],
        "S8 plan binds another S7 plan",
    )
    _require(
        plan["qualification_seal_sha256"] == qualified["seal_sha256"],
        "S8 plan binds another S7 seal",
    )
    _require(
        lifecycle["milestone_verdict"] is None and run_output["milestone_verdict"] is None,
        "a verdict is stored",
    )
    policy = _json(inputs.s7_run / "qualification/gate-policy.json")
    _require(
        content_digest(policy).removeprefix("sha256:")
        == qualified["gate_policy_sha256"].removeprefix("sha256:"),
        "S7 gate policy differs from the digest its plan binds",
    )
    checks = _json(state / "acceptance-checks.json")["checks"]
    run = command_log(logs / "run-command.log")
    prepare = command_log(logs / "prepare-command.log")
    prepare["stderr_bytes"] = len(_bytes(logs / "prepare.stderr.log"))
    # After every read, so a deleted input raises MissingInput rather than a seal mismatch.
    _require(inventory(state) == _json(state / "seal.json"), "S8 state differs from its seal")
    return {
        "run_id": S8_RUN,
        "evidence_label": plan["evidence_label"],
        "source_revision": plan["source_revision"],
        "caller_transports": sorted(set(lifecycle["caller_kinds"])),
        "plan_sha256": content_digest(plan),
        "seal_sha256": content_digest(_json(state / "seal.json")),
        "lifecycle_sha256": lifecycle_sha256,
        "verification_sha256": verification_sha256,
        "rendered_report_file_sha256": _sha256(inputs.s8_run / "review/REPORT.md"),
        "approval_sha256": plan["approval_sha256"],
        "approval": {
            "activation_approved": approval["activation_approved"],
            "publication_approved": approval["publication_approved"],
            "approved_on_as_written": approval["approved_on"],
            "actor": "withheld",
            "actor_verification_source": lifecycle["actor_verification_source"],
        },
        "worker_os_sandbox_required": lifecycle["os_sandbox_required"],
        "worker_proofs": [
            {k: p[k] for k in ("event", "mechanism", "os_sandbox_applied", "profile_sha256")}
            for p in lifecycle["worker_proofs"]
        ],
        "ledger_sends": counts,
        "campaign_total": sum(counts.values()),
        "campaign_cap": policy["campaign_cap"],
        "phase_caps": policy["phase_caps"],
        "version_attempts": lifecycle["version_attempts"],
        "lifecycle_elapsed_seconds": lifecycle["elapsed_seconds"],
        "lifecycle_steps": [
            {
                "step": s["step"],
                "name": s["name"],
                "elapsed_seconds": s["elapsed_seconds"],
                "fake_sends_after": s["fake_sends_after"],
            }
            for s in lifecycle["steps"]
        ],
        "activation_performed": lifecycle["activation_performed"],
        "publication_performed": lifecycle["publication_performed"],
        "real_provider_requests": lifecycle["real_provider_requests"],
        "qualification_seal_verified": run_output["qualification_seal_verified"],
        "milestone_verdict": lifecycle["milestone_verdict"],
        "failure_record_present": (state / "failure.json").exists(),
        "driver_acceptance_checks": [
            {
                "name": c["name"],
                "exit_status": c["exit_status"],
                "elapsed_seconds": c["elapsed_seconds"],
            }
            for c in checks
        ],
        "commands": [prepare, run, verify, command_log(logs / "report-command.log")],
    }


def _observation(path: Path) -> dict[str, Any]:
    observed = _json(path)
    return {
        "bucket_type": observed["bucket_type"],
        "object_lock_enabled": observed["object_lock_enabled"],
        "default_retention": observed["default_retention"],
        "observed_file_count": observed["file_count"],
        "observed_bytes": observed["bytes"],
        "file_retention_modes_observed": sorted(
            {f["retention_mode"] for f in observed["files"]}, key=str
        ),
        "model_calls": observed["model_calls"],
        "mutations": observed["mutations"],
    }


def retention(inputs: Inputs) -> dict[str, Any]:
    archives = {run: _json(inputs.receipts / f"{run}-local.json") for run in ARCHIVED_RUNS}
    uploads = {
        S7_RUN: (inputs.cache_s7_backup / "object-lock.json", inputs.cache_s7_backup),
        S8_RUN: (inputs.cache_s8 / "object-lock.json", inputs.cache_s8),
    }
    prefixes: dict[str, Any] = {}
    for run, (observation, logs) in uploads.items():
        entry = _observation(observation)
        entry.update(_rclone_check(logs / "check.log"))
        entry["copy_exit_status"] = _copy_exit(logs / "copy.log")
        manifest_bytes = len(_bytes(inputs.archives / run / "manifest.json"))
        receipt = archives[run]
        entry["count_reconciliation"] = {
            "archive_member_files": receipt["file_count"],
            "archive_member_bytes": receipt["bytes"],
            "manifest_json_files": 1,
            "manifest_json_bytes": manifest_bytes,
            "uploaded_files": receipt["file_count"] + 1,
            "uploaded_bytes": receipt["bytes"] + manifest_bytes,
        }
        _require(
            entry["observed_file_count"] == receipt["file_count"] + 1
            and entry["observed_bytes"] == receipt["bytes"] + manifest_bytes
            and entry["matching_files"] == entry["observed_file_count"],
            f"Backblaze counts for {run} do not reconcile with the receipt plus manifest.json",
        )
        prefixes[run] = entry
    prefixes[DRILL_PREFIX] = _observation(inputs.cache_drill / "object-lock.json")
    return {"local_archives": archives, "backblaze_prefixes": prefixes}


def recovery_checks(
    inputs: Inputs, qualified: dict[str, Any], rehearsed: dict[str, Any]
) -> dict[str, Any]:
    """The 2026-11-20 restores from the local archive and Backblaze, run from the checkout."""
    logs = inputs.cache_s8 / "recovery-checks"
    steps = _steps(logs / "steps.jsonl")
    reports = {
        "s8_original": rehearsed["rendered_report_file_sha256"],
        "s8_local_restore": _sha256(logs / "s8-local-report.stdout"),
        "s8_backblaze_restore": _sha256(logs / "s8-b2-report.stdout"),
        "s7_original": qualified["rendered_report_file_sha256"],
        "s7_local_restore": _sha256(logs / "s7-local-report.stdout"),
        "s7_backblaze_restore": _sha256(logs / "s7-b2-report.stdout"),
    }
    # Read every verifier output first, so a missing one raises even after an earlier mismatch.
    outputs = {
        (run, copy): _json(logs / f"{run}-{copy}-verify.stdout")
        for copy in ("local", "b2")
        for run in ("s8", "s7")
    }
    verify_matches = all(
        outputs["s8", copy]["verification_sha256"] == rehearsed["verification_sha256"]
        and outputs["s8", copy]["lifecycle_sha256"] == rehearsed["lifecycle_sha256"]
        and outputs["s7", copy]["verification_sha256"] == qualified["verification_sha256"]
        for copy in ("local", "b2")
    )
    return {
        "steps": steps,
        "step_count": len(steps),
        "nonzero_exit_statuses": [s["name"] for s in steps if s["exit_status"] != 0],
        "rendered_report_sha256": reports,
        "restored_reports_equal_originals": len(
            {v for k, v in reports.items() if k.startswith("s8")}
        )
        == 1
        and len({v for k, v in reports.items() if k.startswith("s7")}) == 1,
        "verify_digests_match_original": verify_matches,
    }


def _drill_side(root: Path, qualified: dict[str, Any], rehearsed: dict[str, Any]) -> dict[str, Any]:
    logs = root / "logs"
    steps = _steps(logs / "steps.jsonl")
    s7, s8 = _json(logs / "s7-bundle-verify.stdout"), _json(logs / "s8-recovery-verify.stdout")
    _require(
        s7["verification_sha256"] == qualified["verification_sha256"],
        "drill S7 verification digest differs",
    )
    _require(s7["seal_sha256"] == qualified["seal_sha256"], "drill S7 seal differs")
    _require(
        s8["verification_sha256"] == rehearsed["verification_sha256"],
        "drill S8 verification digest differs",
    )
    _require(
        s8["lifecycle_sha256"] == rehearsed["lifecycle_sha256"], "drill S8 lifecycle digest differs"
    )
    return {
        "step_count": len(steps),
        "exit_statuses": {s["name"]: s["exit_status"] for s in steps},
        "expected_zero_all_zero": all(
            s["exit_status"] == 0 for s in steps if s["expected_exit"] == "zero"
        ),
        "expected_nonzero_all_nonzero": all(
            s["exit_status"] != 0 for s in steps if s["expected_exit"] == "nonzero"
        ),
        "sandboxed_steps": sum(1 for s in steps if s["sandboxed"]),
        "sandbox_profile_sha256": _sha256(root / "sandbox-profile.sb"),
        "s7_verifier_output": s7,
        "s8_verifier_output": s8,
        "s8_report_sha256_rendered": _sha256(logs / "s8-report.stdout"),
        "s8_report_sha256_archived_copy": _sha256(root / "s8/run/review/REPORT.md"),
        "stderr_last_line": {
            name: redact(_text(logs / f"{name}.stderr").strip().splitlines()[-1])
            for name in (
                "negative-absent-qualification",
                "negative-different-qualification",
                "observe-plain-verify-without-qualification",
            )
        },
    }


def recovery_drill(
    inputs: Inputs, qualified: dict[str, Any], rehearsed: dict[str, Any]
) -> dict[str, Any]:
    """The 2026-11-22 drill with the original runs and the working checkout blocked."""
    local = _drill_side(inputs.drill / "drill-local", qualified, rehearsed)
    b2 = _drill_side(inputs.drill / "drill-b2", qualified, rehearsed)
    revisions = {
        _text(inputs.drill / f"drill-{side}/logs/checkout-revision.txt").strip()
        for side in ("local", "b2")
    }
    _require(len(revisions) == 1, "the two drills ran from different code revisions")
    return {
        "code_revision": revisions.pop(),
        "s7_verifier_sha256": _sha256(inputs.drill / "tools/verify_s7_bundle.py"),
        "drill_script_sha256": _sha256(inputs.drill / "tools/drill.sh"),
        "local": local,
        "b2": b2,
        "verifier_outputs_identical_across_drills": local["s7_verifier_output"]
        == b2["s7_verifier_output"]
        and local["s8_verifier_output"] == b2["s8_verifier_output"],
    }


def checked_in_copies(inputs: Inputs, public: Path) -> dict[str, Any]:
    """The step logs and verifier checked in beside the record must equal their private sources."""
    pairs = {
        "recovery-check-steps.jsonl": inputs.cache_s8 / "recovery-checks/steps.jsonl",
        "acceptance-regression-steps.jsonl": inputs.cache_s8 / "acceptance-regression/steps.jsonl",
        "recovery-drill-20261122/local-steps.jsonl": inputs.drill / "drill-local/logs/steps.jsonl",
        "recovery-drill-20261122/b2-steps.jsonl": inputs.drill / "drill-b2/logs/steps.jsonl",
        "recovery-drill-20261122/verify_s7_bundle.py.txt": inputs.drill
        / "tools/verify_s7_bundle.py",
    }
    copies = {}
    for name, private in pairs.items():
        digest = _sha256(public / name)
        _require(digest == _sha256(private), f"checked-in {name} differs from its private source")
        copies[name] = {"sha256": digest, "equals_private_source": True}
    return copies


def build(inputs: Inputs, statements_path: Path) -> dict[str, Any]:
    """Assemble the record. Every private input must exist; disagreements raise."""
    statements = _json(statements_path)
    if statements.get("schema_version") != STATEMENTS_SCHEMA:
        raise ValueError("unexpected operator-statements schema")
    qualified = qualification(inputs)
    rehearsed = rehearsal(inputs, qualified)
    _require(
        rehearsed["source_revision"] == qualified["source_revision"],
        "S7 and S8 source revisions differ",
    )
    kept = retention(inputs)
    storage = statements["operator_observations"]["backblaze_storage"]
    record = {
        "schema_version": SCHEMA,
        "generated_by": {
            "script": "scripts/build_s8_evidence_record.py",
            "operator_statements_file": statements_path.name,
            "operator_statements_sha256": hashlib.sha256(_bytes(statements_path)).hexdigest(),
        },
        "milestone_verdict": None,
        "derived": {
            "qualification": qualified,
            "rehearsal": rehearsed,
            "retention": kept,
            "recovery_checks_20261120": recovery_checks(inputs, qualified, rehearsed),
            "acceptance_regression": {
                "steps": _steps(inputs.cache_s8 / "acceptance-regression/steps.jsonl")
            },
            "recovery_drill_20261122": recovery_drill(inputs, qualified, rehearsed),
            "checked_in_copies": checked_in_copies(inputs, statements_path.parent),
            "storage_estimate": {
                "inputs_are_operator_statements": True,
                "bucket_total_bytes_with_versions": storage[
                    "bucket_total_bytes_with_versions_after_drill_upload"
                ],
                "storage_rate_usd_per_tb_month": storage["storage_rate_usd_per_tb_month"],
                "estimated_monthly_charge_usd": round(
                    storage["bucket_total_bytes_with_versions_after_drill_upload"]
                    / 1e12
                    * storage["storage_rate_usd_per_tb_month"],
                    2,
                ),
            },
        },
        "operator_statements": statements,
    }
    if any(exposes_local_user(text) for text in _strings(record)):
        raise ValueError("the record would contain a local user path or name")
    return record


def encode(record: dict[str, Any]) -> str:
    return json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + "\n"


def differences(expected: Any, actual: Any, path: str = "") -> list[str]:
    """JSON paths at which two records differ, for a readable ``--check`` summary."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        found: list[str] = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                found.append(f"{path}/{key}: only in the checked-in record")
            elif key not in actual:
                found.append(f"{path}/{key}: missing from the checked-in record")
            else:
                found.extend(differences(expected[key], actual[key], f"{path}/{key}"))
        return found
    if expected != actual:
        return [
            f"{path}: generated {json.dumps(expected)[:110]} != stored {json.dumps(actual)[:110]}"
        ]
    return []


def main(argv: list[str] | None = None) -> int:
    defaults = Inputs.defaults()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "s7_run",
        "s8_run",
        "receipts",
        "archives",
        "drill",
        "cache_s8",
        "cache_s7_backup",
        "cache_drill",
    ):
        parser.add_argument(
            f"--{name.replace('_', '-')}", type=Path, default=getattr(defaults, name)
        )
    parser.add_argument("--statements", type=Path, default=PUBLIC / "operator-statements.json")
    parser.add_argument("--output", type=Path, default=PUBLIC / "record.json")
    parser.add_argument(
        "--check", action="store_true", help="compare with the output file; write nothing"
    )
    args = parser.parse_args(argv)
    inputs = Inputs(
        **{name: getattr(args, name).expanduser().resolve() for name in Inputs.__dataclass_fields__}
    )
    record = build(inputs, args.statements)
    if not args.check:
        args.output.write_text(encode(record), encoding="utf-8")
        print(f"wrote {args.output.name}")
        return 0
    if not args.output.is_file():
        print(f"{args.output.name} is absent", file=sys.stderr)
        return 1
    found = differences(record, json.loads(args.output.read_text(encoding="utf-8")))
    if found or args.output.read_text(encoding="utf-8") != encode(record):
        print(f"{args.output.name} differs from the regenerated record:", file=sys.stderr)
        for line in found[:40] or ["formatting only"]:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"{args.output.name} matches the regenerated record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
