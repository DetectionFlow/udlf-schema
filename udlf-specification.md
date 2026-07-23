# Universal Detection Lifecycle Format (UDLF) Specification v0.2

UDLF is a YAML format for managing the full lifecycle of cybersecurity detection logic
across multiple SIEM platforms. It is a **deploy-neutral source of truth**: a UDLF file
carries a detection's logic, threat context, tests, relationships and deployment *policy* —
but never deployment *mechanics or secrets*.

- **Schema (detection):** `udlf-schema.json` — `$id: https://detectionflow.com/schemas/udlf/v0.2.0`
- **Schema (strategy):** `udlf-strategy-schema.json` — `$id: https://detectionflow.com/schemas/udlf/strategy/v0.2.0`
- **Draft:** JSON Schema 2020-12
- **File extension:** `.udlf.yaml`

## Problem statement

Modern detection engineering runs detection-as-code, but existing formats (Sigma, YARA-L,
ESCU, …) describe a *single* detection for a *single* platform. Reality is messier:

> One threat-idea becomes **N variants** — each potentially in its own query language, deployed
> to its own platform, at its own lifecycle stage, in its own runtime mode. A detection may run
> live SPL on Splunk while a KQL variant sits in warranty on Sentinel.

UDLF v0.2 models this directly. A single detection holds an array of logic **variants** and an
array of **deployments**, decoupling *what the logic is* from *where and how it runs*.

## Core concepts

### Deploy-neutral source of truth

UDLF files describe deployment **policy** — which named target, which runtime mode, which
lifecycle stage. They never contain deployment **mechanics or secrets** (SIEM `base_url`,
`token`, `app`, `owner`, `verify_ssl`). Those are infrastructure config owned by the platform
or CI pipeline and resolved from the named `target`. This keeps content files safe to share
and portable across environments.

### The deployer

UDLF describes intent; a **deployer** (an AI agent, deterministic code, or a CI/CD pipeline)
acts on it. Given a deployment's `target`, the deployer resolves the real infrastructure,
selects the matching logic variant (e.g. `splunk-es` → the `spl` variant), translates or
compiles as needed, and pushes it in the requested `mode`.

### Two independent axes: lifecycle and mode

Maturity and runtime behavior are separate concerns:

| Axis | Field | Values | Meaning |
|------|-------|--------|---------|
| **Maturity** | `lifecycle` | `research` → `development` → `testing` → `live` → `decommissioned` | How mature the detection (or a specific deployment) is. Re-engineering re-enters `development`/`testing`. |
| **Runtime** | `mode` | `alert`, `warranty`, `monitoring`, `disabled` | How a deployment behaves once shipped. `warranty` = runs to validate coverage without alerting. |

Top-level `lifecycle` is the overall stage **and** the pre-deployment default. Each deployment
may override `lifecycle` and always sets `mode`; a deployment that omits `lifecycle` inherits
the top-level value.

### Multi-variant logic

`detection_content` is an array. Each entry pairs a `language` with its `logic`. This is where
"each in its own language" lives — a detection can hold hand-authored SPL and KQL side by side.

`language: sigma` is special: instead of a raw query string, `logic` holds an **embedded native
Sigma rule object**, validated against the pinned upstream SigmaHQ schema. This lets you wrap an
existing Sigma rule in UDLF to gain lifecycle, deployment and test management while keeping the
original rule intact and schema-validated. Trace it back to its origin with a `derived_from` link.

## The detection object

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.2.0
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d          # UUID v4
title: Process Injection with Defensive Tooling Tampering
lifecycle: testing                                # overall stage + pre-deployment default

metadata:
  created_at: "2026-06-10"                        # required
  updated_at: "2026-07-20"
  version: "0.3.0"                                # required, semver
  authors:
    - Alex Rivera

threat:
  attack_version: "19"                            # ATT&CK release authored against
  attack:
    - technique: T1055                            # required; ^T\d{4}(\.\d{3})?$
      tactics: [Stealth]                          # optional; additive union enum
    - technique: T1562.001
      tactics: [Defense Impairment]
  software: [S0154]                               # ^S\d{4}$
  groups: [G0016]                                 # ^G\d{4}$
  cve: []                                         # ^CVE-\d{4}-\d{4,}$
  custom_tags:                                    # free-form dict, any values
    domain: endpoint
    analytic_story: [Defense Evasion Techniques]

detection_context:
  severity: high                                  # critical|high|medium|low|informational
  description: |
    Detects process injection followed by tampering with endpoint security tooling.
  false_positives: [EDR agent self-updates]
  how_to_implement: [Collect Sysmon Event IDs 8, 10]
  investigation_steps: [Correlate injector with tampered service]
  references: [https://attack.mitre.org/techniques/T1055/]

data:
  log_sources: [Sysmon]
  required_fields: [SourceImage, TargetImage, GrantedAccess]
  data_sources: [Process Access, Service Modification]

detection_content:                                # array of language+logic variants
  - language: spl
    logic: |
      index=endpoint EventCode=10 GrantedAccess IN ("0x1F0FFF") | ...
  - language: kql
    logic: |
      DeviceEvents | where ActionType == "CreateRemoteThread" | ...

tests:
  - name: True positive - injection then service stop
    framework: replay                             # open/extensible framework field
    attack_data:
      - data: https://example.com/recorded.log
        source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
        sourcetype: xmlwineventlog
    expected: hit                                 # optional: hit | miss
  - name: Benign self-update must not fire
    framework: synthetic
    log: { EventCode: 7036, service_name: SentinelAgent }
    expected: miss
  - name: Atomic - process injection
    framework: atomic-red-team
    technique: T1055.001
    test_guid: 6f5e7d3c-2b1a-4c9d-8e7f-0a1b2c3d4e5f

links:                                            # typed relationships (loose)
  - type: part_of_strategy
    target: c0ffee00-1234-4abc-9def-000000000001
  - type: related
    target: 550e8400-e29b-41d4-a716-446655440000

deployments:                                      # where + how it runs
  - target: splunk-es                             # named env, NO secrets
    mode: alert
    lifecycle: live                               # overrides top-level
  - target: sentinel-prod
    mode: warranty                                # lifecycle omitted -> inherits `testing`
```

### Detection field reference

| Field | Required | Type | Notes |
|-------|:---:|------|-------|
| `id` | ✓ | string (uuid) | Unique detection identifier. |
| `title` | ✓ | string (1–256) | Human-readable title. |
| `lifecycle` | ✓ | enum | `research`\|`development`\|`testing`\|`live`\|`decommissioned`. Overall stage + pre-deployment default. |
| `metadata` | ✓ | object | Provenance/versioning. Requires `created_at` + `version`. |
| `metadata.created_at` | ✓ | string (date) | `YYYY-MM-DD`. |
| `metadata.version` | ✓ | string | Semver `^\d+\.\d+\.\d+$`. |
| `metadata.updated_at` | | string (date) | `YYYY-MM-DD`. |
| `metadata.authors` | | string[] | Replaces v0.1 `created_by`. |
| `detection_content` | | array | Logic variants; each `{ language, logic }`. |
| `detection_content[].language` | ✓* | enum | `spl`\|`kql`\|`sigma`\|`yara`\|`yara-l`\|`python`\|`sql`. |
| `detection_content[].logic` | ✓* | string \| object | String query, **or** an embedded Sigma object when `language: sigma`. |
| `threat` | | object | ATT&CK and related tagging. |
| `threat.attack_version` | | string | Authoring release; does not gate validation. |
| `threat.attack[].technique` | ✓* | string | `^T\d{4}(\.\d{3})?$`. |
| `threat.attack[].tactics` | | enum[] | Additive union enum (16 values, v18 ∪ v19). |
| `threat.software` / `groups` / `cve` | | string[] | `^S\d{4}$` / `^G\d{4}$` / `^CVE-\d{4}-\d{4,}$`. |
| `threat.custom_tags` | | object | Free-form dict; any values. |
| `detection_context` | | object | Human context (severity, description, false_positives, how_to_implement, investigation_steps, references). |
| `data` | | object | `log_sources`, `required_fields`, `data_sources` — string arrays. |
| `tests` | | array | Validation tests; see below. |
| `links` | | array | Typed relationships; see below. |
| `deployments` | | array | Where/how it runs; see below. |

\* Required only within its parent object when that object is present.

### Tactics enum

Validated against an **additive union** — forward-tolerant, values are added on new ATT&CK
releases and never removed. Current set (v18 ∪ v19):

`Reconnaissance, Resource Development, Initial Access, Execution, Persistence,
Privilege Escalation, Defense Evasion, Stealth, Defense Impairment, Credential Access,
Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact`

`Defense Evasion` is retained for back-compat and Mobile/ICS; `Stealth` and `Defense Impairment`
are v19 additions (v19 released 2026-04-28).

### tests

Each entry requires `name` and `framework`. `framework` is intentionally **open/extensible** —
unknown values validate with just `name`/`framework`. The three known frameworks are validated
conditionally:

| framework | required fields | model |
|-----------|-----------------|-------|
| `replay` | `attack_data: [{ data (uri), source?, sourcetype? }]` | Replay a recorded log (ESCU `attack_data`). |
| `synthetic` | `log` (inline object) | Generated event (Panther-style). |
| `atomic-red-team` | `technique` (regex), `test_guid` (uuid) | Live execution via Atomic Red Team. |

`expected` is optional: `hit` (should fire) or `miss` (benign data must **not** fire — the way
to express a false-positive test).

### links

Typed relationships, validated loosely: `type` (enum) and `target` (uuid or uri) are required;
type-specific fields are permitted but not enforced.

| type | purpose | extra fields |
|------|---------|--------------|
| `derived_from` | Provenance to an imported source. | `source_format`, `source_id`, `source_version` |
| `supersedes` / `superseded_by` | Version succession. | — |
| `related` | Loose association. | — |
| `part_of_strategy` | Membership in a strategy. | — |

`source_version` tracks the source's own version (ESCU/Elastic integer, Sigma `modified` date,
or a commit SHA), not the import date.

### deployments

Each entry binds the detection to a named environment. Requires `target` and `mode`; `lifecycle`
is optional and inherits the top-level value. Secrets and connection details are **never** here —
they are resolved from `target` by the deployer/CI.

## The strategy object

A strategy is an analytic-story-style grouping that references detections by id and describes the
threat it addresses.

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/strategy/v0.2.0
id: c0ffee00-1234-4abc-9def-000000000001
title: Defense Evasion via Security Tooling Tampering

metadata:
  created_at: "2026-06-01"
  version: "0.2.0"
  authors: [Detection Engineering Team]

narrative:
  description: Coverage for adversaries who tamper with endpoint controls to evade detection.
  goal: Detect the tamper-then-operate pattern across endpoint platforms.
  threat:
    attack_version: "19"
    attack:
      - technique: T1562.001
        tactics: [Defense Impairment]
    groups: [G0016]
    software: [S0154]

members:                                          # detection references only
  - detection: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
  - detection: 550e8400-e29b-41d4-a716-446655440000

references:
  - https://attack.mitre.org/tactics/TA0005/
```

### Strategy field reference

| Field | Required | Type | Notes |
|-------|:---:|------|-------|
| `id` | ✓ | string (uuid) | Unique strategy identifier. |
| `title` | ✓ | string (1–256) | Human-readable title. |
| `metadata` | ✓ | object | Same shape/rules as a detection's `metadata`. |
| `narrative` | | object | `description`, `goal`, and a self-contained `threat` subset (same shape as detection `threat`). |
| `members` | | array | `{ detection: <uuid> }` references only. May be empty. |
| `references` | | string[] (uri) | External reading. |

## Migrating from v0.1

| v0.1 | v0.2 |
|------|------|
| `format: udlf\|sigma\|escu` | **Removed.** The variant's `language` is the discriminator; `sigma` is a `language` whose `logic` is an embedded, validated Sigma object. |
| `detection_content: { language, logic }` (object) | `detection_content: [ { language, logic } ]` (**array** of variants). |
| `lifecycle: deployed` | `lifecycle: live`. (`warranty`/`tuning` removed — warranty is a `mode`; re-engineering re-enters `development`/`testing`.) |
| `metadata.created_by` (string) | `metadata.authors` (array). |
| `metadata.source_url` | A `links: [{ type: derived_from, target, source_version }]` entry. |
| `tags.attack_tactics` + `tags.attack_techniques` (flat lists) | `threat.attack: [{ technique, tactics }]` (paired). Plus `threat.software`/`groups`/`cve`. |
| `tags.custom_tags` (string list) | `threat.custom_tags` (**dict**). |
| `detection_context` | Unchanged (name retained). |
| — | New: `data`, `tests`, `links`, `deployments`, and the `strategy` object. |
| `type` | **Removed** in v0.2 (may be reintroduced later). |
| `risk`/RBA, `drilldowns`, `license`, `confidence`/`impact`, `contributors` | Not included. RBA is re-synthesized at ESCU deploy time. |

## Validation

```bash
# Detection examples
uvx check-jsonschema --schemafile udlf-schema.json examples/*.udlf.yaml

# Strategy examples
uvx check-jsonschema --schemafile udlf-strategy-schema.json examples/strategies/*.udlf.yaml
```

The Sigma `$ref` is pinned to an immutable upstream tag
(`SigmaHQ/sigma-specification` `v2.1.0`); validating a `language: sigma` variant resolves it over
the network.

## Deferred (post-v0.2)

- **Per-platform `schedule` / `suppression`** on a deployment (reserved-optional shape:
  `schedule { frequency, lookback, max_results }`, `suppression { fields, window }`).
- **`tests` extensibility** — user-defined test frameworks + schemas, and an AI-execution
  framework (describe commands, an agent runs them).
- **Structured deployment `target`** and native-schema validation for non-Sigma imports
  (ESCU/Elastic).

## Resources

- Sigma — https://github.com/SigmaHQ/sigma-specification
- CoreTIDE — https://github.com/OpenTideHQ/CoreTide
- YARA-L — https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview
- SPL — https://help.splunk.com/en/splunk-enterprise/search/search-manual
- Splunk contentctl — https://github.com/splunk/contentctl
- KQL — https://learn.microsoft.com/en-us/kusto/query/
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- NOVA — https://github.com/fr0gger/nova-framework
