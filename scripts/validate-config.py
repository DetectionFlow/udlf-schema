#!/usr/bin/env -S uv run --quiet --no-project --with pyyaml --with jsonschema python
"""Opt-in validation of UDLF deployment `config` blocks.

The UDLF core schema leaves `config` free-form on purpose, so `check-jsonschema`
alone cannot check it — and it cannot dispatch on the sibling `platform` field
either. This runs that second, explicit pass: for each deployment it looks up
`schemas/udlf/config/<platform>/v<version>.json` and validates the block
against it.

A deployment whose platform has no sub-schema is skipped, not failed — that is
the escape hatch working as intended. Pass --strict to fail on skips instead,
which is what you want in a repo where every platform in use is modelled.

It also runs the cross-field checks the core schema cannot express, because they
span the deployment and its config, or depend on a value inherited from the
top level that a `deployments[]` subschema cannot see.

    ./scripts/validate-config.py examples/*.udlf.yaml
    ./scripts/validate-config.py --strict examples/**/*.udlf.yaml
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import jsonschema
import yaml

SCHEMA_DIR = (
    pathlib.Path(__file__).resolve().parent.parent / "schemas" / "udlf" / "config"
)


def sub_schema_for(platform: str, declared: object) -> pathlib.Path | None:
    """Resolve a platform to a sub-schema file.

    A config block may declare the revision it was authored against via a
    `schema` key (`splunk-es::0.1.0`). We honour it exactly, so a block pinned
    to 0.1.0 keeps validating against 0.1.0 after a later revision ships —
    rather than guessing at compatibility, which pre-1.0 semver does not
    promise. With no `schema` key, use the highest version available.

    `declared` is whatever the config block put in `schema`, which the core
    schema does not constrain — it may be any JSON type. A non-string is not a
    resolvable pin, so fall through to the highest version and let the
    sub-schema report the type error properly rather than crashing here.
    """
    directory = SCHEMA_DIR / platform
    if not directory.is_dir():
        return None

    if isinstance(declared, str) and "::" in declared:
        pinned = directory / f"v{declared.split('::', 1)[1]}.json"
        return pinned if pinned.exists() else None

    versions = sorted(
        directory.glob("v*.json"),
        key=lambda p: [int(n) for n in p.stem.lstrip("v").split(".")],
    )
    return versions[-1] if versions else None


def cross_checks(doc: dict, dep: dict) -> list[str]:
    """Rules spanning the deployment, its config, and inherited top-level values.

    The core schema catches `lifecycle: decommissioned` alongside `enabled: true`
    only when the deployment states its own lifecycle, since a `deployments[]`
    subschema cannot see the top-level value it would otherwise inherit. And no
    JSON Schema can reach from `enabled` into the sibling `config`, which is
    where contentctl's own constraint on `enabled_by_default` lives.
    """
    problems = []
    config = dep.get("config") or {}

    lifecycle = dep.get("lifecycle", doc.get("lifecycle"))
    if lifecycle == "decommissioned" and dep.get("enabled") is True:
        source = "its own" if "lifecycle" in dep else "the inherited top-level"
        problems.append(
            f"enabled: true conflicts with {source} lifecycle: decommissioned, "
            f"a retired deployment is removed, not shipped switched on"
        )

    if dep.get("platform") == "splunk-contentctl-v5-6" and dep.get("enabled") is True:
        # contentctl permits enabled_by_default only for *production* TTP, Anomaly
        # and Correlation. UDLF `lifecycle: live` is what maps onto production, so
        # an explicit `enabled: true` anywhere else cannot be honoured. Only the
        # explicit value is checked: where `enabled` is omitted the deployer clamps
        # the default to false below `live`, which is not an authoring error.
        if config.get("type") == "Hunting":
            problems.append(
                "enabled: true cannot be honoured on a Hunting detection, because "
                "contentctl permits enabled_by_default only for production TTP, "
                "Anomaly and Correlation"
            )
        elif lifecycle != "live":
            problems.append(
                f"enabled: true cannot be honoured at lifecycle: {lifecycle}, because "
                f"contentctl permits enabled_by_default only for production detections "
                f"(UDLF lifecycle: live)"
            )

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=pathlib.Path)
    ap.add_argument(
        "--strict",
        action="store_true",
        help="fail when a config block has no matching sub-schema",
    )
    args = ap.parse_args()

    checked = failed = skipped = conflicts = 0

    for path in args.files:
        doc = yaml.safe_load(path.read_text()) or {}
        for i, dep in enumerate(doc.get("deployments") or []):
            platform = dep.get("platform", "<missing>")
            where = f"{path}: deployments[{i}] ({platform})"

            # Cross-field checks run on every deployment, config or not. They are
            # collected rather than printed, so each deployment gets one verdict.
            problems = cross_checks(doc, dep)
            conflicts += len(problems)

            config = dep.get("config")
            schema_file = (
                sub_schema_for(platform, config.get("schema"))
                if config is not None
                else None
            )

            if config is not None and schema_file is None:
                skipped += 1
                level = "FAIL" if args.strict else "skip"
                print(f"{level} {where}: no sub-schema under {SCHEMA_DIR}")
            elif schema_file is not None:
                checked += 1
                validator = jsonschema.Draft202012Validator(
                    json.loads(schema_file.read_text())
                )
                errors = sorted(
                    validator.iter_errors(config), key=lambda e: list(e.path)
                )
                if errors:
                    failed += 1
                    problems.extend(
                        f"{'/'.join(str(q) for q in err.path) or '<root>'}: "
                        f"{err.message}"
                        for err in errors
                    )

            if problems:
                print(f"FAIL {where}")
                for problem in problems:
                    print(f"       {problem}")
            elif schema_file is not None:
                print(f"ok   {where}")

    summary = f"\n{checked} config block(s) checked, {failed} failed"
    if skipped:
        summary += f", {skipped} skipped"
    if conflicts:
        summary += f", {conflicts} cross-field conflict(s)"
    print(summary)

    return 1 if failed or conflicts or (args.strict and skipped) else 0


if __name__ == "__main__":
    sys.exit(main())
