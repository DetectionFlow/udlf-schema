# AGENTS.md

This repository holds security detections in **UDLF** (Universal Detection Lifecycle Format).
Each `*.udlf.yaml` file is one detection and is self-contained.

## Ground truth

Never describe, invent or recall a UDLF field from memory. Read the source every time:

| | |
|---|---|
| Schema | the URL in the file's `yaml-language-server` header — e.g. `https://detectionflow.com/schemas/udlf/v0.2.0` |
| Specification | <https://github.com/DetectionFlow/udlf-schema/blob/main/udlf-specification.md> |
| Config sub-schemas | `https://detectionflow.com/schemas/udlf/config/<platform>/v<version>` |

If a field is not in the schema, it does not exist. If the schema and something you remember
disagree, the schema wins.

## Rules

**1. Never fabricate or reuse a UUID.** A new detection gets a fresh `uuid4` (`uuidgen`). Never
copy an `id` from an example, another detection, or your own earlier output. Where a
`links[].target` is a UUID (`related`, `part_of_strategy`, `supersedes`, `superseded_by`), it must
resolve to something that actually exists in this repo — check, don't assume. A `derived_from`
target is a URI instead: a permalink to the upstream rule, or an internal scheme such as
`splunk:<id>` for content imported from your own SIEM.

**2. Validate before proposing any change.** Nothing ships unvalidated:

```sh
uvx check-jsonschema --schemafile https://detectionflow.com/schemas/udlf/v0.2.0 path/to/detection.udlf.yaml
```

`deployments[].config` is free-form to the core schema, so that pass does not check it. Validating
it needs a second, platform-dispatching pass — `scripts/validate-config.py`, which lives in the
[udlf-schema](https://github.com/DetectionFlow/udlf-schema) repo, not this one. If it is not
available here, read the relevant config sub-schema and check the block by hand.

**3. Bump the version and append a changelog entry on every edit.** `metadata.version` is semver;
raise it, then append one `changelog` entry (`date`, `version`, `author`, `summary`) recording
what changed and why. The changelog is append-only — never rewrite or reorder existing entries.
A newly created or imported detection starts at `1.0.0` with a first entry recording its origin.

**4. Deploy-neutral: never put secrets or infrastructure into `config`.** `config` carries
deployment *policy* — schedule, suppression, severity, notable and risk annotation. It never
carries credentials, API keys, tokens, hostnames, search-head or workspace URLs, tenant ids, or
anything else that identifies *where* content lands. Those belong to the deployer. When importing
from a vendor export, strip them rather than carrying them across.

**5. Keep the two axes straight.** `lifecycle` (`research → development → testing → live →
decommissioned`) is maturity. A deployment's `mode` (`alert | warranty | monitoring | disabled`)
is runtime behaviour. They are independent — a `live` detection can sit in `warranty` on a new
platform. Never use one to express the other.

## Scope

One logical change at a time. Touch the detections the task names and no others — a schema
version bump, a bulk retag, or a repo-wide reformat is its own piece of work.
