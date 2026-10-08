#!/usr/bin/env -S uv run --quiet --no-project --with pyyaml --with jsonschema python
"""Structural validation of UDLF macro documents.

`check-jsonschema` validates a macro's shape, including the per-language rules
about which of `type` and `default` are allowed. Four things it cannot express
are checked here instead:

  * for `kql`, a defaulted argument may not be followed by a non-defaulted one —
    Kusto requires optional parameters last, so the reverse order produces an
    invalid Sentinel function signature
  * argument names must be unique
  * every declared argument must actually appear at its substitution point in
    `definition` ($name$ for spl, ?name for cql) — a declared-but-unused
    argument is a rename that was only half applied
  * for `spl`, `name` is the Splunk stanza name, so it must end in `(N)` exactly
    when the macro takes N arguments — a bare name with arguments, or `(N)` with
    a different count, is the same half-applied rename

Run it after the schema pass — it validates against the schema first, so a
document that fails there is reported once, here, rather than twice.

    ./scripts/validate-macros.py examples/macros/*.udlf.yaml
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

import jsonschema
import yaml

SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schemas" / "udlf" / "macro"

# How each language marks a substitution point. 'kql' is absent on purpose: its
# parameters are bare identifiers, so there is no token to search for without
# risking a match inside a string literal or a field name.
SUBSTITUTION = {"spl": "${}$", "cql": "?{}"}

# A Splunk macros.conf stanza name for a parameterised macro: `name(N)`.
SPL_STANZA = re.compile(r"^(.*)\((\d+)\)$")


def check_spl_name(name: str, argument_count: int) -> list[str]:
    """Check an SPL macro's name agrees with its argument count."""
    match = SPL_STANZA.match(name)
    if not match:
        if argument_count:
            return [
                f"name: '{name}' takes {argument_count} argument(s), so the "
                f"Splunk stanza name is '{name}({argument_count})'"
            ]
        return []

    problems = []
    bare, declared = match.group(1), int(match.group(2))
    if not bare:
        problems.append(f"name: '{name}' has nothing before the argument count")
    if declared == 0:
        problems.append(f"name: '{name}' — a zero-argument macro uses the bare name")
    elif declared != argument_count:
        problems.append(
            f"name: '{name}' declares {declared} argument(s) but 'arguments' "
            f"has {argument_count}"
        )
    return problems


def latest_schema() -> pathlib.Path:
    versions = sorted(
        SCHEMA_DIR.glob("v*.json"),
        key=lambda p: [int(n) for n in p.stem.lstrip("v").split(".")],
    )
    if not versions:
        raise SystemExit(f"no macro schema found under {SCHEMA_DIR}")
    return versions[-1]


def check(path: pathlib.Path, validator: jsonschema.Draft202012Validator) -> list[str]:
    """Return a list of problems with one macro document. Empty means good."""
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

    arguments = doc.get("arguments") or []
    language = doc["language"]

    if language == "spl":
        problems.extend(check_spl_name(doc["name"], len(arguments)))

    if not arguments:
        return problems

    names = [arg["name"] for arg in arguments]
    duplicates = {name for name in names if names.count(name) > 1}
    if duplicates:
        problems.append(f"arguments: duplicate name(s) {sorted(duplicates)}")

    if language == "kql":
        seen_default = None
        for arg in arguments:
            if "default" in arg:
                seen_default = arg["name"]
            elif seen_default is not None:
                problems.append(
                    f"arguments: '{arg['name']}' has no default but follows "
                    f"'{seen_default}', which does — Kusto requires defaulted "
                    f"parameters last"
                )
                break

    token = SUBSTITUTION.get(language)
    if token:
        definition = doc["definition"]
        for name in names:
            if token.format(name) not in definition:
                problems.append(
                    f"arguments: '{name}' is declared but "
                    f"'{token.format(name)}' never appears in definition"
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

    print(f"\n{len(args.files)} macro(s) checked against {schema_file.name}, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
