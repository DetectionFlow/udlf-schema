# Universal Detection Lifecycle Format (UDLF) Specification v0.2

UDLF is a YAML format for managing the full lifecycle of cybersecurity detection logic
across multiple SIEM platforms. It is a **deploy-neutral source of truth**: a UDLF file
carries a detection's logic, threat context, tests, relationships and deployment *policy* —
but never deployment *mechanics or secrets*.

- **Schema (detection):** `schemas/udlf/v0.2.2.json` — `$id: https://detectionflow.com/schemas/udlf/v0.2.2.json`
- **Schema (strategy):** `schemas/udlf/strategy/v0.2.0.json` — `$id: https://detectionflow.com/schemas/udlf/strategy/v0.2.0.json`
- **Draft:** JSON Schema 2020-12
- **File extension:** `.udlf.yaml`

Every schema's repo path mirrors its `$id` path — `.json` extension included — so `schemas/` can be
served directly at the published URLs and old versions stay resolvable alongside new ones.

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

UDLF files describe deployment **policy** — which platform, which named endpoint, which runtime
mode, which lifecycle stage, and platform-specific policy (`schedule`/`suppression`/`rba` and vendor
round-trip fields) carried in the free-form per-deployment `config` block, whose known shapes are
described by [optional sub-schemas](#config-sub-schemas-opt-in).
They never contain deployment **mechanics or secrets** (SIEM `base_url`, `token`, `app`, `owner`,
`verify_ssl`). Those are infrastructure config owned by the
platform or CI pipeline and resolved from the named endpoint. This keeps content files safe to
share and portable across environments.

### The deployer

UDLF describes intent; a **deployer** (an AI agent, deterministic code, or a CI/CD pipeline)
acts on it. Given a deployment's `platform` (and optional `name`), the deployer resolves the real
infrastructure and secrets for that endpoint, selects the matching logic variant
(e.g. `platform: splunk-es` → the `spl` variant), translates or compiles as needed, and pushes it
in the requested `mode` with any platform-specific `config` (`schedule` / `suppression` / `rba` / …).
`platform` also picks the delivery path: `splunk-es` means the deployer builds and uploads an app
itself, while `splunk-contentctl-v5-6` and `splunk-contentctl-ng` mean it emits a contentctl-shaped
detection and lets a contentctl pipeline do the build. The `deployments` block is
a **directive**: UDLF says *what* to deploy and *how it should behave*; the deployer — per-org
custom code or example scripts — turns that into a real pipeline. Engineers (human or AI) can read
the YAML and see exactly what is deployed where.

### Two independent axes: lifecycle and mode

Maturity and runtime behavior are separate concerns:

| Axis | Field | Values | Meaning |
|------|-------|--------|---------|
| **Maturity** | `lifecycle` | `research` → `development` → `testing` → `live` → `decommissioned` | How mature the detection (or a specific deployment) is. Re-engineering re-enters `development`/`testing`. |
| **Runtime** | `mode` | `alert`, `warranty`, `monitoring`, `disabled` | How a deployment behaves once shipped (see below). |

Top-level `lifecycle` is the overall stage **and** the pre-deployment default. Each deployment
may override `lifecycle` and always sets `mode`; a deployment that omits `lifecycle` inherits
the top-level value.

The four modes are **orthogonal runtime behaviors** — a deployer acts on each differently:

| mode | behavior |
|------|----------|
| `alert` | Runs and generates alerts/notables (pages the SOC). |
| `warranty` | Runs against known-good/known-bad data to validate coverage; produces a **test result, not an alert**. |
| `monitoring` | Runs on a schedule and surfaces **non-alerting output for human review** — dashboards, risk/RBA contribution, hunt-triage queues, situational awareness. Does **not** alert. |
| `disabled` | Present but not executing. |

`mode` is about *behavior*, not *purpose*. A hunting query and a dashboard search that both run
without alerting are the same `mode: monitoring` — their intent lives in `detection_context` /
`threat.custom_tags`, not in the runtime enum.

#### Where hunting lives

Threat hunting is **not** a mode. It appears three ways, depending on how the hunt is run:

- **Ad-hoc / manual hunt** — a detection with **no `deployments` entry**. It lives in the repo as
  logic (e.g. a `hunting/` folder) and is executed on demand. This is the common case and needs no
  mode at all.
- **Maturing hunt** — a hunt on its way to becoming a standing detection sits at
  `lifecycle: research` / `development`, graduating toward `live`.
- **Operationalised hunt** — a hunt promoted to a scheduled, non-alerting standing search is a
  deployment with `mode: monitoring`.

### Multi-variant logic

`detection_content` is an array. Each entry pairs a `language` with its `logic`. This is where
"each in its own language" lives — a detection can hold hand-authored SPL and KQL side by side.

Several entries may share a `language`: a `tstats`-accelerated SPL next to a raw-log SPL, or one
variant tuned per client. Add an optional `description` to say which is which — a short label like
`Raw log SPL version` or `Tuned for client X`. It is documentation for whoever reads or maintains
the file, not a selector: `platform` still picks the *language*, so where two same-language variants
exist the deployer needs out-of-band knowledge of which one that endpoint should get.

`language: sigma` is special: instead of a raw query string, `logic` holds an **embedded native
Sigma rule object**, validated against the pinned upstream SigmaHQ schema. This lets you wrap an
existing Sigma rule in UDLF to gain lifecycle, deployment and test management while keeping the
original rule intact and schema-validated. Trace it back to its origin with a `derived_from` link.

### Supporting content: macros and lookups

Real detections lean on content that does not belong inside the detection file. A **macro** is a
reusable snippet of query logic — shared plumbing every search repeats. A **lookup** is a reference
dataset — a list of attacker tool names, RMM binaries, or approved CIDR ranges — too large and too
frequently changed to inline. Both are authored as their own top-level UDLF documents and referenced
from a logic variant's `requires` block.

The two behave differently because the platforms do:

- **A macro is language-scoped.** Only three targets have the primitive, and each expresses it
  differently: a Splunk `macros.conf` stanza expanded as text, a Microsoft Sentinel `savedSearches`
  function with a `functionAlias`, a CrowdStrike LogScale saved query called as `$"name"()`. So a
  macro document carries exactly one `language` (`spl`, `kql` or `cql`), and the KQL equivalent of an
  SPL macro is a *separate document reusing the same `name`*. Platforms with no macro primitive —
  Elastic, Google SecOps, Cortex XSIAM, SentinelOne — are absent from the enum by design: a macro
  that could never be materialised should not be authorable.
- **A lookup is not.** Reference data is language-neutral, and six of the seven modelled platforms
  have the primitive in some form (Splunk csv lookup, Sentinel watchlist, Google SecOps reference
  list, Elastic value list, Cortex lookup dataset, CrowdStrike lookup file). A lookup document has no
  `language`, no `platform` and no `deployments` — it is materialised onto whatever platforms its
  requiring detections target.

A Splunk tuning filter is not a special case: it is an ordinary macro with an `spl` definition.

#### Why `requires` is declared, and why per variant

contentctl derives a detection's dependencies by regex-scanning the search text for backticked
macros and `inputlookup`/`lookup` references. That works because it handles one language. UDLF
carries several per detection, so inference would need a parser per language — and an explicit list
does something inference cannot: it tells a deployer targeting a platform with *no* such primitive
(SentinelOne has neither) that it must inline the content rather than create a shared object.

`requires` sits inside each `detection_content` entry, not at the top level, because a dependency is
a property of a specific logic string rather than of the threat idea. Two variants may share a
language and still disagree — a `tstats`-accelerated SPL needs a summaries-only macro while its
raw-log sibling does not — which a detection-level list could not express.

Resolution follows from that placement: a **macro** resolves on `name` plus the enclosing variant's
`language`; a **lookup** resolves on `name` alone. References are by name rather than by id because
the name is the token the deployer must substitute at the call site.

## The detection object

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.2.2.json
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d          # UUID v4
title: Process Injection with Defensive Tooling Tampering
lifecycle: testing                                # overall stage + pre-deployment default

metadata:
  created_at: "2026-06-10"                        # required
  version: "0.3.0"                                # required, semver
  authors:
    - Alex Rivera

detection_context:
  severity: high                                  # critical|high|medium|low|informational
  description: |
    Detects process injection followed by tampering with endpoint security tooling.
  false_positives: |                              # free text
    EDR agent self-updates can trigger CreateRemoteThread on security processes.
  implementation_guidance: |                      # free text (renamed from how_to_implement)
    Collect Sysmon Event IDs 8 and 10. Requires GrantedAccess in the event data.
  investigation_guidance: |                       # free text
    Correlate the injector process with the tampered service and review parent lineage.
  attack_procedures: |                            # TTP procedure(s): example attacker execution that fires this
    C:\tools\injector.exe --pid 4820 --shellcode beacon.bin
    sc.exe stop SentinelAgent
  references: [https://attack.mitre.org/techniques/T1055/]

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

detection_content:                                # array of language+logic variants
  - language: spl
    description: Raw log SPL version                # optional label; only documentation
    logic: |
      index=endpoint EventCode=10 GrantedAccess IN ("0x1F0FFF")
      | `security_content_ctime(firstTime)`
      | lookup attacker_tools attacker_tool_names AS SourceImage OUTPUT description
    requires:                                     # scoped to THIS variant, not the detection
      - type: macro                               # resolves on name + this variant's language
        name: security_content_ctime
      - type: lookup                              # resolves on name alone
        name: attacker_tools
  - language: kql
    description: Tuned for client X
    logic: |
      DeviceEvents | where ActionType == "CreateRemoteThread" | ...
                                                  # no `requires` — this variant needs neither

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
  - name: splunk-prod                             # friendly endpoint; NO secrets here
    platform: splunk-es                           # discriminator: variant + config meaning
    mode: alert
    lifecycle: live                               # overrides top-level
    config:                                       # free-form, platform-scoped; UDLF validates nothing here
      schedule: { cron: "*/10 * * * *", lookback: "-15m" }
      suppression: { fields: [dest, SourceImage], window: "24h" }
      rba:                                        # mode=alert -> notable + risk
        message: "Process injection from $SourceImage$ on $dest$"
        risk_objects: [{ field: dest, type: system, score: 70 }]   # score is per object
        threat_objects: [{ field: SourceImage, type: process_name }]
  - name: sentinel-prod
    platform: sentinel
    mode: warranty                                # lifecycle omitted -> inherits `testing`

changelog:                                        # top-level, last: append-only, grows unbounded
  - date: "2026-06-10"
    version: "0.1.0"
    author: Alex Rivera
    summary: Initial SPL logic created.
  - date: "2026-07-20"
    version: "0.3.0"
    author: Detection Engineering Team
    summary: Added KQL variant for sentinel-prod and tuned GrantedAccess values.
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
| `metadata.authors` | | string[] | Replaces v0.1 `created_by`. |
| `detection_content` | | array | Logic variants; each `{ language, description?, logic }`. |
| `detection_content[].language` | ✓* | enum | `spl`\|`kql`\|`cql`\|`sigma`\|`yara`\|`yara-l`\|`python`\|`sql`. `cql` is CrowdStrike Query Language (Falcon NG-SIEM / LogScale). |
| `detection_content[].description` | | string (1–256) | Short label distinguishing variants that share a language. Documentation only; not a deploy-time selector. |
| `detection_content[].logic` | ✓* | string \| object | String query, **or** an embedded Sigma object when `language: sigma`. |
| `detection_content[].requires` | | array | Supporting content **this variant** depends on; `{ type, name }`. |
| `…requires[].type` | ✓* | enum | `macro`\|`lookup`. |
| `…requires[].name` | ✓* | string | The supporting document's `name` — the same token appearing in this variant's logic. `^[a-z][a-z0-9_]{2,63}$`. |
| `detection_context` | | object | Human context (see below). |
| `detection_context.severity` | | enum | `critical`\|`high`\|`medium`\|`low`\|`informational`. |
| `detection_context.description` | | string | What the detection identifies. |
| `detection_context.false_positives` | | string | Known false-positive scenarios. **Free text** (was an array in draft v0.2.0). |
| `detection_context.implementation_guidance` | | string | How to implement (data sources, prerequisites, tuning). **Free text**. Renamed from `how_to_implement`. |
| `detection_context.investigation_guidance` | | string | Indicative investigation pointers. **Free text** (was an array). |
| `detection_context.attack_procedures` | | string | The TTP procedure(s) that trigger the detection — the attacker command line / example execution that would fire it. **Free text**; may gain structure later. |
| `detection_context.references` | | string[] (uri) | External reading URLs. |
| `threat` | | object | ATT&CK and related tagging. |
| `threat.attack_version` | | string | Authoring release; does not gate validation. |
| `threat.attack[].technique` | ✓* | string | `^T\d{4}(\.\d{3})?$`. |
| `threat.attack[].tactics` | | enum[] | Additive union enum (16 values, v18 ∪ v19). |
| `threat.software` / `groups` / `cve` | | string[] | `^S\d{4}$` / `^G\d{4}$` / `^CVE-\d{4}-\d{4,}$`. |
| `threat.custom_tags` | | object | Free-form dict; any values. |
| `tests` | | array | Validation tests; see below. |
| `links` | | array | Typed relationships; see below. |
| `deployments` | | array | Where/how it runs; see below. |
| `changelog` | | array | Top-level (placed last); each `{ date, version, author, summary }`. Latest `date` = effective last-updated. Replaces `updated_at`. |

\* Required only within its parent object when that object is present.

### changelog

A **light-touch**, append-only history of notable changes. It is a **top-level** field placed
**last** in the file, since it grows unbounded and should not push the logic and threat context
down. Each entry is `{ date, version, author, summary }` — all four required within an entry. It
intentionally carries no `kind` enum and no per-deployment attachment: the affected language
variant or deployment platform/endpoint is named in the `summary` prose. There is no separate `updated_at`;
the **most recent entry's `date`** is the effective last-updated date, and each `version` ties a
change to the release it shipped in.

```yaml
changelog:
  - date: "2026-06-10"
    version: "0.1.0"
    author: Alex Rivera
    summary: Initial SPL logic created.
  - date: "2026-07-20"
    version: "0.3.0"
    author: Detection Engineering Team
    summary: Added KQL variant for sentinel-prod and tuned GrantedAccess values.
```

### Tactics enum

Validated against an **additive union** — forward-tolerant, values are added on new ATT&CK
releases and never removed. Current set (v18 ∪ v19):

`Reconnaissance, Resource Development, Initial Access, Execution, Persistence,
Privilege Escalation, Defense Evasion, Stealth, Defense Impairment, Credential Access,
Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact`

`Defense Evasion` is retained for back-compat and Mobile/ICS; `Stealth` and `Defense Impairment`
are v19 additions (v19 released 2026-04-28).

When a technique lists **no** `tactics`, applications should treat **all tactics valid for that
technique** as applicable. When `tactics` are listed, only those specific technique→tactic
mappings apply. This lets a detection scope a technique (e.g. `T1078` Valid Accounts) to a
single tactic when the logic only covers that use, while leaving the common case unconstrained.

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

Typed relationships. `type` (enum) and `target` (uuid or uri) are required; the type-specific fields
below are optional, and scoped by convention — not by validation — to the type they belong to.

Link items are **closed** (`additionalProperties: false`). `type` is a closed enum, so a new link
kind needs a schema change regardless and openness would buy no extensibility; closing instead
catches a misspelt `license` key, which would otherwise validate clean while silently dropping a
redistribution obligation.

| type | purpose | extra fields |
|------|---------|--------------|
| `derived_from` | Provenance to an imported source. | `source_format`, `source_id`, `source_version`, `license`, `modification` |
| `supersedes` / `superseded_by` | Version succession. | — |
| `related` | Loose association. | — |
| `part_of_strategy` | Membership in a strategy. | — |

#### derived_from

| Field | Type | Notes |
|-------|------|-------|
| `source_id` | string | The source's own identifier — the upstream Sigma/ESCU rule UUID. |
| `source_format` | string | Format translated from (`sigma`, `escu`, `splunk`, …). Open/extensible. |
| `source_version` | string | The source's own version: ESCU/Elastic integer, Sigma `modified` date, or a commit SHA. **Not** the import date. |
| `license` | string (uri) | URL of the licence the source is distributed under. |
| `modification` | string | Prominent notice of how the source was changed. |

`target` is a **permalink to the upstream rule on its default branch**, not a commit permalink: a
branch permalink is stable across syncs and changes only when the upstream path changes, whereas a
commit sha would rewrite every derived document on every sync. Record the exact commit a sync
translated from once, in a manifest, not in thousands of documents. An import from a customer's own
SIEM has no public URL and keeps an internal scheme (`splunk:<id>`).

`license` is a **URL, not an SPDX identifier**, because it doubles as the attribution hyperlink some
source licences require on redistribution — SigmaHQ's Detection Rule License 1.1 asks for "a URI or
hyperlink to the Rule set or explicit Rule". The trade-off is that a URL is not machine-comparable,
so licence-class filtering means string-matching URLs.

`modification` carries the changed-file notice that licences such as Apache-2.0 §4(b) require —
translating an upstream YAML rule into a UDLF document is a modification. There is no separate
`modified: true` flag: it would be true wherever it appeared, and the notice says more.

Both are **optional in the schema**, because one producer legitimately has neither: importing from a
customer's own SIEM has no upstream licence. Requiring them would make every SIEM-imported detection
invalid. Enforce them where the claim is actually true — a translator of public content should always
emit `license`, `target` and `modification`, and a build job that publishes such content should
assert all three are present.

Redistribution obligations follow the copy: a tool that copies a detection into another repository
must **propagate** the existing `derived_from` link rather than synthesise a bare one, since that
copy is itself a distribution event.

```yaml
links:
  - type: derived_from
    target: https://github.com/SigmaHQ/sigma/blob/master/rules/application/bitbucket/bitbucket_full_data_export_triggered.yml
    source_id: 195e1b9d-bfc2-4ffa-ab4e-35aef69815f8
    source_format: sigma
    license: https://github.com/SigmaHQ/Detection-Rule-License
    modification: Translated from Sigma YAML into UDLF v0.2.0; detection logic unchanged.
  - type: derived_from
    target: https://github.com/splunk/security_content/blob/develop/detections/cloud/o365_concurrent_sessions_from_different_ips.yml
    source_id: 58e034de-1f87-4812-9dc3-a4f68c7db930
    source_format: escu
    source_version: "14"
    license: https://www.apache.org/licenses/LICENSE-2.0
    modification: Translated from Splunk ESCU YAML into UDLF v0.2.0; detection logic unchanged.
```

Author attribution for the upstream rule stays in `metadata.authors`.

### deployments

Each entry binds the detection to a **platform** and, optionally, a named **endpoint**. Requires
`platform` and `mode`; `name` and `lifecycle` are optional (`lifecycle` inherits the top-level
value). Everything platform-specific lives in the free-form **`config`** block. Secrets and
connection details are **never** here — they resolve from the endpoint by the deployer/CI.

| Field | Required | Type | Notes |
|-------|:---:|------|-------|
| `name` | | string | Friendly name for a specific endpoint (`splunk-prod`, `splunk-staging`). Resolved to real infra/secrets. Omit when a platform has one endpoint. Listed first so entries read name-then-platform across multiple endpoints. |
| `platform` | ✓ | string | Deployment target and the **discriminator**. Known: `splunk`, `splunk-es`, `splunk-contentctl-v5-6`, `splunk-contentctl-ng`, `elastic`, `sentinel`. Selects the logic variant and **scopes the meaning of `config`**. Usually a product, but may name a delivery toolchain where that changes the shape of `config` — see [delivery paths](#when-a-platform-is-a-toolchain). Open/extensible — unknown values validate on the common fields only. |
| `mode` | ✓ | enum | `alert` \| `warranty` \| `monitoring` \| `disabled` (see [modes](#two-independent-axes-lifecycle-and-mode)). The **only** cross-vendor runtime axis. |
| `lifecycle` | | enum | Per-deployment stage; inherits top-level when omitted. |
| `config` | | object | **Free-form, platform-scoped** (`additionalProperties: true`). Holds all platform-specific deployment policy and vendor round-trip fidelity: `schedule`, `suppression`, `rba`, and vendor-only fields. The core schema validates **nothing** inside it. Optional [config sub-schemas](#config-sub-schemas-opt-in) describe the known shapes and can be applied as a separate pass. |

Only `platform`, `mode`, and the optional `name`/`lifecycle` are first-class — `mode` is the sole
cross-vendor runtime axis. Everything else a platform needs — `schedule`, `suppression`, Splunk ES
`rba`, and vendor round-trip fields — folds into **`config`**, a free-form block whose meaning is
set by the sibling `platform`. UDLF does **not** validate `config`, so vendor changes never force a
schema bump.

This makes import and authoring symmetric:

- **Import** from a SIEM export → dump the vendor-meaningful fields into `config` (skip pure display
  noise and renames). A slightly-lossy import is fine when the deployer can re-generate the dropped
  fields from source.
- **Authoring new** → omit `config` entirely. At deploy time, if the platform hard-requires a field
  that's blank, the **deployer** generates it or asks the user/AI.

There is no separate `actions` list — the `mode` already implies the action: on `splunk-es`,
`mode: alert` raises a notable **and** the risk annotation (from `config.rba`), while
`mode: monitoring` contributes risk only.

Deployment **mechanics** (endpoints, tokens, integration IDs) never appear — in `config` or
anywhere else. `config` is deployment **policy and fidelity**, not secrets.

#### When a `platform` is a toolchain

`platform` usually names a product, but its real job is to determine the shape of `config`. Where
two delivery paths to the same product produce genuinely different config, they get separate
`platform` values:

| `platform` | Target | How it gets there |
|---|---|---|
| `splunk` | Splunk Enterprise | Deployer builds a custom app and uploads it. Standard `savedsearches.conf` only — no ES features assumed. |
| `splunk-es` | Splunk Enterprise Security | Same build-and-upload path, plus ES notable events and Risk-Based Alerting. |
| `splunk-contentctl-v5-6` | Splunk Enterprise / ES | Deployer emits a **contentctl v5.6**-shaped detection and hands it to the contentctl pipeline, which validates, builds and tests the app itself. |
| `splunk-contentctl-ng` | Splunk Enterprise / ES | Same idea, next generation: the deployer emits an **ESCU 6.x**-shaped detection for **contentctl-ng**, the rewrite that succeeded contentctl 5.x. |

The split is not cosmetic. Under either contentctl value the config is not a superset of
`splunk-es` — it is differently shaped, because the toolchain owns the build. In both, `type`
(`TTP` | `Anomaly` | `Hunting` | `Correlation`) is the real discriminator, deciding what the
detection emits and gating whole blocks rather than merely labelling the detection.

The same detection can carry several of these at once — see
`examples/process-injection-multi-deployment.udlf.yaml`, which ships one detection to `splunk-es`
directly and to both contentctl pipelines as part of a content pack.

##### Naming: when the platform carries a version, and when it doesn't

The two contentctl values are **siblings, not versions of each other**, and they are named by
different rules on purpose.

`splunk-contentctl-v5-6` names a **frozen** format. contentctl's 5.x line ended at v5.6, so the
name can safely carry the tool minor: nothing will ever change underneath it, and a deployment
naming it asserts exactly that its config converts to a contentctl v5.6 detection.

`splunk-contentctl-ng` names a toolchain whose format is not fixed. There is no contentctl v6: the
tool that consumes the **ESCU 6.x** content format — the format `splunk/security_content` uses from
ESCU 6.0 onward — is a separate rewrite published as **`contentctl-ng`**. There is no version to
name, so the platform carries none and the sub-schema's semver identifies the format revision
instead: `config.schema: splunk-contentctl-ng::0.1.0` is what pins a block to the revision it was
authored against.

Generic Splunk ES delivery, where the deployer owns the build, stays on `splunk-es` and is
unaffected by any of this.

##### How the two contentctl shapes differ

Enough that a detection shipping down both pipelines needs a deployment for each, with genuinely
different config in them. The ng column is derived from `schemas/EventBasedDetection.schema.json`,
which `splunk/security_content` publishes as generated JSON Schema.

| Area | `splunk-contentctl-v5-6` | `splunk-contentctl-ng` |
|---|---|---|
| Tag block | nested under `tags:` (`tags.asset_type`, `tags.security_domain`, …) | flat, at the top level |
| Alerting | `rba: { message, risk_objects[], threat_objects[] }` | `finding` + `intermediate_findings` + `threat_objects` (the ES8 findings model) |
| Alert subject | notable title/description come from the matched deployment; `rba.risk_objects` is a **list** | `finding.title` is authored per detection, and `finding.entity` is **exactly one** — further scored entities belong in `intermediate_findings` |
| Risk message | one shared `rba.message` | one `message` **per** intermediate-finding entity |
| Schedule | not in the config — `type` matches a built-in ESCU **deployment**, which supplies it | a named `schedule`, or an inline `custom_schedule`; there are no deployments |
| Suppression | `tags.throttling.{fields, period}` | **no equivalent** — not authorable in the detection at all |
| Install state | `enabled_by_default` | no equivalent; `status` (from UDLF `lifecycle`) governs |
| Extra required field | — | `category` (application \| cloud \| endpoint \| network \| web) |
| Risk score | capped at 100 | unbounded; `0` is legal and means "alert without contributing risk" |
| `asset_type` | its own closed list | a **different** closed list — the two overlap but neither contains the other |

The `type` matrix is also stricter, and strict enough to encode in the schema rather than leave to
the build. TTP emits a finding plus optional intermediate findings; Anomaly emits intermediate
findings only; Correlation emits a finding only; Hunting emits neither and carries no threat
objects. Upstream enforces that in code; the `splunk-contentctl-ng` sub-schema enforces it in
`allOf`, so a mismatch surfaces at authoring time.

The sharpest asymmetry is **suppression**: contentctl-ng has no field for it, so a detection that
needs alert suppression can only express it on its `splunk-es` or `splunk-contentctl-v5-6`
deployment. A detection carrying both contentctl deployments therefore suppresses on one and not
the other.

#### Not every platform is a scheduled search

The Splunk-family and Sentinel shapes are all "run this query on a schedule". The EDR targets are
not, and their `config` shapes reflect that:

- **`defender-for-endpoint`** couples frequency to lookback — you pick `1H`/`3H`/`12H`/`24H`/`NRT`
  and MDE decides the window, so there is no separate lookback field.
- **`crowdstrike`** schedules with a start/end window rather than a cron, and classifies rules
  against a tactic vocabulary that mixes ATT&CK ids with proprietary `CST*` values.
- **`sentinel-one`** has no schedule at all — STAR rules evaluate continuously. A rule is either a
  single-event match or a correlation of ordered subqueries over a time window.

Two of them can also **act**, not just detect: `defender-for-endpoint.actions` can isolate a
device, quarantine a file or disable a user, and `sentinel-one.response` can network-quarantine an
endpoint. UDLF's `mode` enum describes detection behaviour only, so a deployment carrying response
actions is doing more than its `mode` conveys. Treat those blocks as deployment policy that
warrants the same review as any other change with blast radius.

#### Config sub-schemas (opt-in)

`config` stays free-form in the core schema, so a vendor change never forces a UDLF bump. The
known shapes are described by **separate, optional sub-schemas** that you apply as a second,
explicit pass when you want the block checked:

| `platform` | Sub-schema |
|---|---|
| `splunk` | `schemas/udlf/config/splunk/v0.2.0.json` |
| `splunk-es` | `schemas/udlf/config/splunk-es/v0.2.0.json` |
| `splunk-contentctl-v5-6` | `schemas/udlf/config/splunk-contentctl-v5-6/v0.1.0.json` |
| `splunk-contentctl-ng` | `schemas/udlf/config/splunk-contentctl-ng/v0.1.0.json` |
| `sentinel` | `schemas/udlf/config/sentinel/v0.1.0.json` |
| `defender-for-endpoint` | `schemas/udlf/config/defender-for-endpoint/v0.1.0.json` |
| `crowdstrike` | `schemas/udlf/config/crowdstrike/v0.1.0.json` |
| `sentinel-one` | `schemas/udlf/config/sentinel-one/v0.1.0.json` |

`elastic` remains unmodelled, so its `config` passes through unvalidated for now.

They are **not** `$ref`'d from the core schema. Core validation is unchanged whether or not they
exist, and a platform with no sub-schema is simply unvalidated rather than rejected — that is the
escape hatch working as intended.

Each carries its own semver line, versioned independently of UDLF core — hence sub-schemas at
`v0.1.0` and `v0.2.0` while the core schema is at `v0.2.2`. A block may declare which revision it was authored against:

```yaml
config:
  schema: splunk-es::0.2.0   # optional; pins the exact sub-schema revision
```

The pin is exact rather than compatible-within-major: pre-1.0 semver makes no compatibility
promise, so a block pinned to `0.1.0` keeps validating against `0.1.0` after a later revision
ships. `splunk` and `splunk-es` are the first with two revisions each, and all four stay served. Omit `schema` to validate against the highest revision available.

Where a platform name carries a **tool** version, the two numbers are unrelated axes and
`splunk-contentctl-v5-6::0.1.0` reads as both at once: the platform fixes the target format
(contentctl v5.6), while the `0.1.0` versions UDLF's mapping onto it. A fix to how UDLF maps a
field bumps the sub-schema; a genuinely different target is a new platform value rather than a
revision of this one.

Where the platform name carries **no** version, as `splunk-contentctl-ng` does not, the sub-schema
semver carries the whole burden: it versions both UDLF's mapping and the upstream format it maps
onto. That is the deliberate trade — see
[naming](#naming-when-the-platform-carries-a-version-and-when-it-doesnt) — and it is why a pin on
an ng block is load-bearing rather than decorative.

Because the sub-schemas are opt-in, they are **closed** (`additionalProperties: false`) — you only
run one when you want strictness, so an unrecognised key is a typo rather than vendor drift. Every
shape except the two contentctl ones provides an `advanced` map as the pressure valve for raw
vendor keys it does not model — raw `savedsearches.conf` keys in the case of the Splunk shapes.
`splunk-contentctl-v5-6` and `splunk-contentctl-ng` deliberately have no such escape hatch: the
toolchain's own models forbid extra keys at every level, so an unmodelled field would fail its
build anyway.

Every shape leaves out the same things, because UDLF already owns them elsewhere: the query
(it belongs in `detection_content`), maturity and runtime behaviour (`lifecycle` and `mode`),
authorship (`metadata.authors`), the set of target endpoints (one deployment entry each), and any
vendor-assigned rule id — UDLF is desired-state only, so reconciling against what is actually
deployed stays with the deployer. Plain ATT&CK restatements are dropped in favour of the top-level
`threat` block; **vendor-proprietary** taxonomies are modelled, because `threat` cannot express
them — CrowdStrike's `CSTA*` tactics ("AI Powered IOA", "Falcon OverWatch") and MDE's `category`
are not ATT&CK, and Sentinel spells its tactics its own way (`CommandAndControl`).

One deliberate exception to keeping logic out of `config`: a `sentinel-one` correlation rule's
`sub_queries` stay in the config block. They are structural parts of the rule definition rather
than a single logic blob, and no `detection_content` variant can currently express an ordered
multi-query correlation — see the correlation decision in the v0.3.0 roadmap.

Each sub-schema mirrors what *its own* deployer actually enforces, so they differ where the tools
differ. Three worth knowing about, all of which the schemas will catch:

- **Threat-object types.** Two vocabularies are in circulation for the same concept: the
  [Splunk RBA community list](https://splunk.github.io/rba/searches/threat_object_types/)
  (`ip`, `process_name`, `url_domain`, …) and contentctl's own (`ip_address`, `process`,
  `domain`, …). ES itself constrains neither — `threat_object_type` is a free string on the risk
  event — and contentctl writes its spelling verbatim into `savedsearches.conf`, so roughly a third
  of ESCU threat objects use a value absent from the RBA list. `splunk-es` therefore accepts
  **both**, since a live ES instance genuinely contains both; the two contentctl shapes accept only
  contentctl's, because that is what their builds enforce. Prefer the RBA spelling when authoring
  new content, and do not rewrite between the two on import — a detection carrying both
  deployments needs each spelling intact. Note that contentctl's own list already contains *both*
  `process` and `process_name` as distinct types, so the divergence is narrower than it looks: it
  is really only `ip` versus `ip_address` and `url_domain` versus `domain`.
- **Suppression windows.** Splunk accepts days; contentctl v5.6 accepts seconds, minutes and hours
  only, so one day must be written `86400s`, `1440m` or `24h`. contentctl-ng accepts no suppression
  at all — ESCU 6.x dropped `throttling` without a successor.
- **Where the risk message lives.** ES carries two shapes of risk annotation at once. In one, a
  single message describes the whole detection and lands in `action.risk.param._risk_message`; in
  the ES8 findings shape each risk object carries its own, serialised per entry into
  `action.risk.param._risk[*].risk_message`, and the alert subject moves into
  `action.notable.param._entities`. contentctl-ng emits only the second. Because `splunk-es` records
  what an instance returns rather than what one build tool accepts, it takes **both**: `rba.message`
  is optional, `rba.risk_objects[].risk_message` and `notable.entities` sit alongside it, and a
  block carrying risk objects must supply a message one way or the other. As with threat-object
  spellings, never rewrite between the shapes on import — what ES returns is what the detection
  actually deploys.
- **Where ES enforces nothing, `splunk-es` enforces nothing.** `risk_object_type` is free text on
  the risk event, so it is an open string rather than an enum: a live instance contains `N/A` for an
  entity with no applicable category, and occasionally a field name that someone put in the type
  slot. Both are recorded rather than rejected. An `rba` block carrying only a message is legal for
  the same reason — that is what ES returns when the risk action is enabled and `_risk` is empty.
  `threat_object_type` stays enumerated, because there the enum is a union of two *documented*
  vocabularies and earns its keep as authoring help.

Note also that `score` sits on each **risk object**, not on the `rba` block — Splunk ES scores each
entity independently, and both contentctl and the ES conf keys reflect that.

Fields UDLF already owns never appear in `config`. ATT&CK IDs and CVEs come from the top-level
`threat` block, implementation and false-positive prose from `detection_context`, tests from the
top-level `tests` array, and analytic-story membership from a [strategy](#the-strategy-object) —
contentctl's `analytic_story` is derived from strategy membership at build time, not authored here.

Other platforms (`elastic`, `sentinel`, …) get sub-schemas as coverage grows; until then their
`config` is carried through unvalidated.

##### Running the opt-in pass

`check-jsonschema` cannot dispatch on the sibling `platform` field, so the repo ships a small
runner:

```bash
./scripts/validate-config.py examples/*.udlf.yaml
./scripts/validate-config.py --strict examples/*.udlf.yaml   # also fail on unmodelled platforms
```

## The strategy object

A strategy is an analytic-story-style grouping that references detections by id and describes the
threat it addresses.

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/strategy/v0.2.0.json
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

changelog:                                        # top-level, last (same shape as a detection's)
  - date: "2026-06-01"
    version: "0.1.0"
    author: Detection Engineering Team
    summary: Initial strategy grouping the tamper-then-operate detections.
  - date: "2026-07-20"
    version: "0.2.0"
    author: Detection Engineering Team
    summary: Added the process-injection detection as a member.
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
| `changelog` | | array | Top-level (placed last); same shape as a detection's `changelog`. |

## The macro object

A macro is a named, reusable snippet of query logic. One document holds exactly one `language`; the
KQL equivalent of an SPL macro is a separate document reusing the same `name`.

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/macro/v0.1.0.json
id: 832ca4f6-6dc6-4043-9d90-f159169795e8
name: security_content_ctime                      # the token referenced from `requires`
title: Convert epoch time to a readable string
description: Converts an epoch timestamp field to an ISO-8601-style string in place.

metadata:
  created_at: "2026-07-31"
  version: "1.0.0"
  authors: [Detection Engineering Team]

language: spl                                     # spl | kql | cql
arguments:                                        # omit entirely for a zero-arg macro
  - name: field
definition: 'convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)'
```

### Argument rules differ by language

The three targets disagree about parameters, and the schema enforces the difference rather than
papering over it:

| `language` | `type` | `default` | Substitution token | Notes |
|---|:---:|:---:|---|---|
| `spl` | forbidden | forbidden | `$name$` | Splunk parameters are untyped and have no defaults. Arity is load-bearing: `[name(2)]` and `[name]` are different macros. |
| `kql` | **required** | allowed | bare identifier | Sentinel declares a typed signature (`functionParameters: 'argSpan: timespan'`) and the function cannot be created without it. Defaults must be scalar literals and come after non-defaulted parameters. |
| `cql` | forbidden | allowed | `?name` | LogScale parameters are untyped. Defaults map to `?{name=default}`, honoured in saved searches but ignored in the UI and dashboards. |

A `default` must be a scalar — neither target can express a composite one. The "defaulted parameters
last" rule cannot be stated in JSON Schema over an unbounded array, so `scripts/validate-macros.py`
enforces it, along with unique argument names and the requirement that each declared argument
actually appears at its substitution point in `definition`.

`definition` carries logic only. The surrounding platform object's mechanics — Sentinel's
`savedSearches` `category`, the LogScale repository or view, app or index placement — are the
deployer's concern, for the same reason a schedule lives in `deployments[].config`.

### Macro field reference

| Field | Required | Type | Notes |
|-------|:---:|------|-------|
| `id` | ✓ | string (uuid) | Unique identifier for this document. Each language variant has its own. |
| `name` | ✓ | string | The referenced token. `^[a-z][a-z0-9_]{2,63}$` — a safe intersection, since a Sentinel `functionAlias` must be a valid KQL identifier. |
| `title` | ✓ | string (1–256) | Maps to Sentinel's `displayName`. |
| `description` | | string | What it does and when to use it. |
| `metadata` | ✓ | object | Same shape/rules as a detection's `metadata`. |
| `language` | ✓ | enum | `spl`\|`kql`\|`cql`. Closed — no other supported platform has a macro primitive. |
| `arguments` | | array | Ordered `{ name, type?, default? }`. Substitution is positional. |
| `definition` | ✓ | string | The macro body. |
| `references` | | string[] (uri) | External reading. |
| `changelog` | | array | Placed last; same shape as a detection's `changelog`. |

## The lookup object

A lookup is a named reference dataset a detection matches against. It carries no `language`,
`platform` or `deployments` — reference data is language-neutral.

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/lookup/v0.1.0.json
id: 9f4c1a77-2b6e-4d08-8f31-c5a70e2d4b19
name: attacker_tools                              # the token referenced from `requires`
title: Known attacker tool names
description: Executable names of tools routinely abused during intrusions.

metadata:
  created_at: "2026-07-31"
  version: "1.0.0"
  authors: [Detection Engineering Team]

key: attacker_tool_names                          # the matched column; must be one of `columns`
match:
  type: exact                                     # exact | wildcard | regex | cidr (default exact)
  case_sensitive: false

columns:                                          # every column, in order
  - name: attacker_tool_names
    description: Executable name as it appears on disk.
  - name: description
    description: What the tool is used for, surfaced in the alert message.

data:                                             # external file...
  format: csv
  file: attacker-tools.csv                        # relative to this document
```

`data` is one of two shapes, never both. Use an external file for anything substantial; use inline
`rows` for a list short enough to stay reviewable in a single diff:

```yaml
data:
  rows:
    - { range: 203.0.113.0/24, site: london }
    - { range: 198.51.100.0/24, site: new-york }
```

### Match-type portability

`match.type` records author intent. It is **not** uniformly supported, and a deployer must reject
what its target cannot do:

| | `exact` | `wildcard` | `regex` | `cidr` |
|---|:---:|:---:|:---:|:---:|
| Splunk (csv lookup) | ✓ default | ✓ `WILDCARD()` | ✗ | ✓ `CIDR()` |
| Sentinel (watchlist) | ✓ SearchKey | ✗ | ✗ | ✗ |
| Google SecOps (reference list) | ✓ STRING | ✗ | ✓ REGEX | ✓ CIDR |
| Elastic (value list) | ✓ | ✗ | ✗ | ✓ via `ip_range` |
| CrowdStrike (lookup file) | ✓ default | ✓ `mode=glob` † | ✓ `mode=regex` | ✓ `mode=cidr` |
| Cortex XSIAM (lookup dataset) | ✓ join | via XQL | via XQL | via XQL |

† LogScale caps a glob-matched CSV at 20,000 rows.

SentinelOne has no lookup primitive at all: STAR rules match single events, so a deployer targeting
it must inline the values into the rule.

### Scope of v0.1.0

Lookups are **matching sets**. A lookup declares its columns and designates one as the matched
`key`; what a deployer does with the remaining columns is deliberately unmodelled. Enrichment tables
— Splunk kvstore, Google SecOps data tables, UDM entity-field mapping — are a later concern, as are
machine-populated datasets with no authored rows. Size and ingestion limits belong to the deployer,
since they differ by orders of magnitude between platforms (Sentinel caps a local watchlist upload
at 3.8 MB; Elastic value lists default to ~9 MB).

### Lookup field reference

| Field | Required | Type | Notes |
|-------|:---:|------|-------|
| `id` | ✓ | string (uuid) | Unique lookup identifier. |
| `name` | ✓ | string | The referenced token. `^[a-z][a-z0-9_]{2,63}$` — a Sentinel watchlist alias must be 3–64 characters, starting and ending alphanumeric. |
| `title` | ✓ | string (1–256) | Human-readable title. |
| `description` | | string | Contents, origin, and how it is maintained. |
| `metadata` | ✓ | object | Same shape/rules as a detection's `metadata`. |
| `key` | ✓ | string | The matched column. Must name one of `columns`. |
| `match` | | object | `{ type?, case_sensitive? }`. Omit for exact, case-insensitive. |
| `columns` | ✓ | array | `{ name, description? }`, in order. At least one. |
| `data` | ✓ | object | Exactly one of `{ format, file }` or `{ rows }`. |
| `references` | | string[] (uri) | External reading — the dataset's upstream source belongs here. |
| `changelog` | | array | Placed last; same shape as a detection's `changelog`. |

## Validation

```bash
# Detection examples
uvx check-jsonschema --schemafile schemas/udlf/v0.2.2.json examples/*.udlf.yaml

# Strategy examples
uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml

# Macro and lookup examples
uvx check-jsonschema --schemafile schemas/udlf/macro/v0.1.0.json examples/macros/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/lookup/v0.1.0.json examples/lookups/*.udlf.yaml
```

Macros and lookups each carry rules JSON Schema cannot express over a list of objects. It cannot
check that a lookup's `key` names a declared column, that its sibling CSV exists with a matching
header, or that a KQL macro's defaulted arguments come last. Those need a second pass:

```bash
./scripts/validate-macros.py examples/macros/*.udlf.yaml
./scripts/validate-lookups.py examples/lookups/*.udlf.yaml
```

The Sigma `$ref` is pinned to an immutable upstream tag
(`SigmaHQ/sigma-specification` `v2.1.0`); validating a `language: sigma` variant resolves it over
the network.

## Resources

- Sigma — https://github.com/SigmaHQ/sigma-specification
- CoreTIDE — https://github.com/OpenTideHQ/CoreTide
- YARA-L — https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview
- SPL — https://help.splunk.com/en/splunk-enterprise/search/search-manual
- Splunk contentctl — https://github.com/splunk/contentctl
- KQL — https://learn.microsoft.com/en-us/kusto/query/
- Sentinel watchlists — https://learn.microsoft.com/en-us/azure/sentinel/watchlists
- CQL / LogScale query functions — https://library.humio.com/data-analysis/syntax-function.html
- Google SecOps reference lists — https://docs.cloud.google.com/chronicle/docs/yara-l/reference-list-syntax
- Atomic Red Team — https://github.com/redcanaryco/atomic-red-team
- NOVA — https://github.com/fr0gger/nova-framework
