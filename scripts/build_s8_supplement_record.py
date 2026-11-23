"""Build or check the S8 rollback-for-exhaustion supplement evidence record; no network.

The record under ``artifacts/evidence-s8-supplement-20261123/`` has two kinds of content:

* ``derived``: computed here from the sealed S7 qualification, the sealed S8 supplement state,
  the archive receipts, and the retained command and Backblaze logs. Nothing in it is typed by
  hand.
* ``operator_statements``: copied verbatim from ``operator-statements.json``. It holds what
  cannot be derived: owner decisions, how the approval document was filled, the storage rate and
  the date it was read, and limits.

The qualification and supplement sections reuse the rehearsal record's readers
(``scripts/build_s8_evidence_record.py``), so both records apply the same digest and seal
checks. Disagreement between stored digests raises. Outcomes are recorded as observed, never
required: a refusal with another cause, a different send count, or a Backblaze count that does
not reconcile is written into the record, not refused. ``--check`` rebuilds the record in memory
and exits nonzero when it differs from the checked-in file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pixelgym.platform.s8_rollback_supplement import EXPECTED_SENDS, SCENARIO
from scripts import build_s8_evidence_record as rehearsal_record
from scripts.build_s8_evidence_record import (
    MissingInput,
    _bytes,
    _json,
    _require,
    _strings,
    command_log,
    differences,
    encode,
    exposes_local_user,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLIC = REPOSITORY_ROOT / "artifacts/evidence-s8-supplement-20261123"
SCHEMA = "pixelgym-s8-supplement-evidence-record-v1"
STATEMENTS_SCHEMA = "pixelgym-s8-supplement-operator-statements-v1"
S7_RUN, S8_RUN = "s7-20261123-supplement", "s8-20261123-supplement"
_EVIDENCE = Path.home() / ".local/state/pixelgym/evidence"

__all__ = ["Inputs", "MissingInput", "build", "main"]


@dataclass(frozen=True)
class Inputs:
    """Where the private evidence and the retained logs live."""

    s7_run: Path
    s8_run: Path
    receipts: Path
    archives: Path
    b2_logs: Path

    @classmethod
    def defaults(cls) -> Inputs:
        s8_run = _EVIDENCE / "runs" / S8_RUN
        return cls(
            s7_run=_EVIDENCE / "runs" / S7_RUN,
            s8_run=s8_run,
            receipts=_EVIDENCE / "receipts",
            archives=_EVIDENCE / "archives",
            b2_logs=s8_run / "review/b2-logs",
        )


def _step_observations(lifecycle: dict[str, Any], name: str) -> dict[str, Any]:
    for step in lifecycle["steps"]:
        if step["name"] == name:
            return dict(step["observations"])
    raise MissingInput(f"the supplement lifecycle holds no step named {name}")


def supplement(inputs: Inputs, qualified: dict[str, Any]) -> dict[str, Any]:
    """The rehearsal section's checks, plus the scenario binding and the rollback observations."""
    base = rehearsal_record.rehearsal(inputs, qualified)  # type: ignore[arg-type]
    state = inputs.s8_run / "state"
    plan, lifecycle = _json(state / "plan.json"), _json(state / "lifecycle.json")
    _require(
        plan.get("scenario") == lifecycle.get("scenario") == SCENARIO,
        "the S8 plan or lifecycle does not name the rollback-for-exhaustion scenario",
    )
    proofs = []
    for proof in lifecycle["worker_proofs"]:
        profile = (
            state / "worker-profiles" / (proof["profile_sha256"].removeprefix("sha256:") + ".sb")
        )
        stored = (
            "sha256:" + hashlib.sha256(profile.read_bytes()).hexdigest()
            if profile.is_file()
            else None
        )
        proofs.append(
            {
                **{
                    k: proof[k]
                    for k in (
                        "event",
                        "mechanism",
                        "os_sandbox_applied",
                        "profile_retained",
                        "profile_sha256",
                    )
                },
                "stored_profile_matches_digest": stored == proof["profile_sha256"],
            }
        )
    deployed_a = _step_observations(lifecycle, "approve_and_deploy_a")
    rollback = _step_observations(lifecycle, "rollback_selects_exhausted_b")
    return {
        **base,
        "run_id": S8_RUN,
        "scenario": plan["scenario"],
        "plan_expected_sends": plan["expected_sends"],
        "driver_expected_sends": dict(EXPECTED_SENDS),
        "worker_proofs": proofs,
        "rollback_target_before_request": deployed_a["rollback_target_before_request"],
        "rollback_toward_exhausted_B": rollback["rollback_toward_exhausted_B"],
    }


def _check_log(inputs: Inputs, run: str) -> dict[str, Any]:
    text = _bytes(inputs.b2_logs / f"{run}-check.stderr.log").decode()
    status = re.search(r"check exit=(\d+)", _bytes(inputs.b2_logs / f"{run}-check.exit").decode())
    found = re.findall(r"(\d+) differences found", text)
    matching = re.findall(r"(\d+) matching files", text)
    if not found or not matching or status is None:
        raise MissingInput(f"rclone check log for {run} holds no result")
    return {
        "check_exit_status": int(status[1]),
        "differences": int(found[-1]),
        "matching_files": int(matching[-1]),
    }


def retention(inputs: Inputs) -> dict[str, Any]:
    observation = _json(inputs.b2_logs / "object-lock.json")
    archives, prefixes = {}, {}
    expected_files = expected_bytes = 0
    for run in (S7_RUN, S8_RUN):
        receipt = _json(inputs.receipts / f"{run}-local.json")
        manifest_bytes = len(_bytes(inputs.archives / run / "manifest.json"))
        listed = [f for f in observation["files"] if f["name"].startswith(run + "/")]
        copy = command_log(inputs.b2_logs / f"{run}-copy.log")
        entry = {
            "copy_command": copy.get("command"),
            "copy_exit_status": copy["exit_status"],
            "copy_started_utc": copy.get("started_utc"),
            "copy_finished_utc": copy.get("finished_utc"),
            **_check_log(inputs, run),
            "observed_file_count": len(listed),
            "observed_bytes": sum(f["size"] for f in listed),
            "file_retention_modes_observed": sorted({f["retention_mode"] for f in listed}, key=str),
            "count_reconciliation": {
                "archive_member_files": receipt["file_count"],
                "archive_member_bytes": receipt["bytes"],
                "manifest_json_files": 1,
                "manifest_json_bytes": manifest_bytes,
                "expected_uploaded_files": receipt["file_count"] + 1,
                "expected_uploaded_bytes": receipt["bytes"] + manifest_bytes,
            },
        }
        entry["count_reconciliation"]["observed_equals_expected"] = (
            entry["observed_file_count"] == receipt["file_count"] + 1
            and entry["observed_bytes"] == receipt["bytes"] + manifest_bytes
            and entry["matching_files"] == entry["observed_file_count"]
        )
        archives[run], prefixes[run] = receipt, entry
        expected_files += receipt["file_count"] + 1
        expected_bytes += receipt["bytes"] + manifest_bytes
    bucket = rehearsal_record._observation(inputs.b2_logs / "object-lock.json")
    bucket["observed_equals_both_prefixes"] = (
        bucket["observed_file_count"] == expected_files
        and bucket["observed_bytes"] == expected_bytes
    )
    return {
        "local_archives": archives,
        "backblaze_prefixes": prefixes,
        "object_lock_observation": bucket,
    }


def build(inputs: Inputs, statements_path: Path) -> dict[str, Any]:
    """Assemble the record. Every private input must exist; disagreeing digests raise."""
    statements = _json(statements_path)
    if statements.get("schema_version") != STATEMENTS_SCHEMA:
        raise ValueError("unexpected operator-statements schema")
    qualified = rehearsal_record.qualification(inputs, "qualify.stdout.json")  # type: ignore[arg-type]
    plan = _json(inputs.s7_run / "qualification/plan.json")
    qualified["qualification_approval"] = plan["qualification_approval"]
    supplemented = supplement(inputs, qualified)
    _require(
        supplemented["source_revision"] == qualified["source_revision"],
        "S7 and S8 source revisions differ",
    )
    size = _json(inputs.b2_logs / "bucket-size.json")
    storage = statements["operator_observations"]["backblaze_storage"]
    record = {
        "schema_version": SCHEMA,
        "generated_by": {
            "script": "scripts/build_s8_supplement_record.py",
            "operator_statements_file": statements_path.name,
            "operator_statements_sha256": hashlib.sha256(_bytes(statements_path)).hexdigest(),
        },
        "milestone_verdict": None,
        "derived": {
            "qualification": qualified,
            "supplement": supplemented,
            "retention": retention(inputs),
            "storage_estimate": {
                "bucket_total_bytes_with_versions": size["bytes"],
                "bucket_total_objects_with_versions": size["count"],
                "storage_rate_usd_per_tb_month": storage["storage_rate_usd_per_tb_month"],
                "rate_is_operator_statement": True,
                "estimated_monthly_charge_usd": round(
                    size["bytes"] / 1e12 * storage["storage_rate_usd_per_tb_month"], 2
                ),
            },
        },
        "operator_statements": statements,
    }
    if any(exposes_local_user(text) for text in _strings(record)):
        raise ValueError("the record would contain a local user path or name")
    return record


def main(argv: list[str] | None = None) -> int:
    defaults = Inputs.defaults()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in Inputs.__dataclass_fields__:
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
    stored = args.output.read_text(encoding="utf-8")
    found = differences(record, json.loads(stored))
    if found or stored != encode(record):
        print(f"{args.output.name} differs from the regenerated record:", file=sys.stderr)
        for line in found[:40] or ["formatting only"]:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"{args.output.name} matches the regenerated record")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
