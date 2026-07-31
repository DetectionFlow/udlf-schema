#!/usr/bin/env -S uv run --quiet --no-project --with pyyaml --with jsonschema python
"""Structural validation of UDLF lookup documents and their data.

`check-jsonschema` validates the document's shape but cannot reach outside it,
so three things it can't check are exactly the ones that break a deploy:

  * `key` must name one of the declared `columns`
  * a `data.file` must exist, and its CSV header must match `columns` in order
  * inline `data.rows` must use exactly the declared column names

It also rejects duplicate column names, which JSON Schema cannot express over a
list of objects, and flags a `file` path that escapes the document's directory.

Run it after the schema pass — it validates against the schema first, so a
document that fails there is reported once, here, rather than twice.

    ./scripts/validate-lookups.py examples/lookups/*.udlf.yaml
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import pathlib
import sys

import jsonschema
import yaml

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schemas" / "udlf" / "lookup"


def latest_schema() -> pathlib.Path:
    versions = sorted(
        SCHEMA_DIR.glob("v*.json"),
        key=lambda p: [int(n) for n in p.stem.lstrip("v").split(".")],
    )
    if not versions:
        raise SystemExit(f"no lookup schema found under {SCHEMA_DIR}")
    return versions[-1]


def check(path: pathlib.Path, validator: jsonschema.Draft202012Validator) -> list[str]:
    """Return a list of problems with one lookup document. Empty means good."""
    try:
        doc = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        return [f"unparseable YAML: {exc}"]

    problems = [
        f"{'/'.join(str(p) for p in err.path) or '<root>'}: {err.message}"
        for err in sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    ]
    if problems:
        # Shape is wrong, so the cross-checks below would report noise on top.
        return problems

    declared = [col["name"] for col in doc["columns"]]
    duplicates = {name for name in declared if declared.count(name) > 1}
    if duplicates:
        problems.append(f"columns: duplicate name(s) {sorted(duplicates)}")

    if doc["key"] not in declared:
        problems.append(f"key: '{doc['key']}' is not one of columns {declared}")

    data = doc["data"]

    if "file" in data:
        if ".." in pathlib.PurePosixPath(data["file"]).parts:
            problems.append(f"data.file: '{data['file']}' must not escape the document's directory")
            return problems

        target = path.parent / data["file"]
        if not target.is_file():
            problems.append(f"data.file: '{data['file']}' does not exist")
            return problems

        rows = list(csv.reader(io.StringIO(target.read_text())))
        if not rows:
            problems.append(f"data.file: '{data['file']}' is empty")
            return problems

        header = [cell.strip() for cell in rows[0]]
        if header != declared:
            problems.append(
                f"data.file: header {header} does not match columns {declared}"
            )
        for n, row in enumerate(rows[1:], start=2):
            if row and len(row) != len(header):
                problems.append(
                    f"data.file: line {n} has {len(row)} field(s), expected {len(header)}"
                )
    else:
        for n, row in enumerate(data["rows"], start=1):
            if sorted(row) != sorted(declared):
                problems.append(
                    f"data.rows[{n - 1}]: keys {sorted(row)} do not match columns {sorted(declared)}"
                )

    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", type=pathlib.Path)
    args = ap.parse_args()

    schema_file = latest_schema()
    validator = jsonschema.Draft202012Validator(json.loads(schema_file.read_text()))

    failed = 0
    for path in args.files:
        problems = check(path, validator)
        if not problems:
            print(f"ok   {path}")
            continue
        failed += 1
        print(f"FAIL {path}")
        for problem in problems:
            print(f"       {problem}")

    print(f"\n{len(args.files)} lookup(s) checked against {schema_file.name}, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
