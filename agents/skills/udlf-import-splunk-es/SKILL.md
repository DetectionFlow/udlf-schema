---
name: udlf-import-splunk-es
description: Convert a Splunk Enterprise Security correlation search or savedsearches.conf stanza into a UDLF detection. Use when importing, migrating or onboarding existing Splunk ES content into a UDLF repo, or when asked what a savedsearch field maps to in UDLF.
---

# Importing a Splunk ES savedsearch into UDLF

## Read both schemas first

The [core schema](https://detectionflow.com/schemas/udlf/v0.2.0) and the
[`splunk-es` config sub-schema](https://detectionflow.com/schemas/udlf/config/splunk-es/v0.1.0).
The sub-schema is **closed** (`additionalProperties: false`), so every key you emit under `config`
is either a modelled field or goes in `advanced` — nothing else validates.

## The one rule that decides everything

UDLF's core describes *the detection*; `config` describes *how one platform runs it*. When a
savedsearch field could plausibly go in either, ask which one it is. The query is the detection —
it goes in `detection_content`, never in `config`, however Splunk stores it.

## Mapping

| savedsearches.conf | UDLF |
|---|---|
| `search` | `detection_content[]` → `{ language: spl, logic: … }` |
| `action.correlationsearch.label` (or stanza name) | `title` |
| `description` | `detection_context.description` |
| `action.notable.param.severity` | `detection_context.severity` — same five words, take it verbatim |
| `action.correlationsearch.annotations` → `mitre_attack` | `threat.attack[].technique` |
| `cron_schedule`, `dispatch.earliest_time`, `dispatch.latest_time`, `schedule_window` | `config.schedule` → `cron`, `lookback`, `latest_time`, `schedule_window` |
| `alert.suppress.fields`, `alert.suppress.period` | `config.suppression` → `fields`, `window` |
| `counttype` / `quantity` / `relation` | `config.threshold` |
| `action.notable.param.*` (`rule_title`, `rule_description`, `nes_fields`, `security_domain`) | `config.notable` |
| `action.risk.param._risk`, `_risk_message` | `config.rba` → `risk_objects`, `threat_objects`, `message` |
| `disabled`, `enableSched`, notable-vs-risk actions | `deployments[].mode` — not a `config` key |
| anything else worth keeping | `config.advanced` as the raw savedsearches.conf key |

Set `config.schema: splunk-es::0.1.0` so the block pins the revision it was authored against.

**Severity.** ES's notable severity is already UDLF's vocabulary. Splunk's numeric
`alert.severity` is a *different* scale — it grades search results, not risk. Don't map it
silently; if it is the only signal available, pick the closest value and say so in the changelog.

**RBA spellings are load-bearing.** `splunk-es` accepts both the Splunk RBA community
threat-object list and contentctl's (`process_name` vs `process`, and so on). Carry across
whatever the export says, verbatim. Never normalise between the two — a live ES instance contains
both, and rewriting one into the other changes what deploys.

**Tactics aren't in the export.** The annotation carries technique ids only. Derive tactics from a
cited ATT&CK version — never from memory — and record that version in `threat.attack_version`.

## Deriving `mode` and `lifecycle`

`mode` comes from what the search actually does: `disabled = 1` → `disabled`; a notable action →
`alert`; scheduled and enabled with risk annotation but no notable → `monitoring`. `warranty` is a
human decision about trust, never inferable from an export — don't guess it.

`lifecycle` is not in the export either. A search running in production is `live`; anything else
is a judgement call to raise with the user rather than invent.

## Drop these

Owner, app, ACL and sharing; search-head, index-cluster or deployment-server references; any
credential, token or endpoint; Splunk's own rule identifiers; `request.ui_dispatch_app` and
UI-state keys; and anything already restated elsewhere in UDLF. Record vendor provenance on a
`links` entry instead — `type: derived_from`, `source_format: splunk`, `source_id` the savedsearch
identifier, and `target` as `splunk:<id>` when there is no public URL.

## Finish

New file: fresh `uuid4`, `metadata.version: "1.0.0"`, and one `changelog` entry recording the
import — where it came from and any judgement you had to make (a guessed severity, an assumed
lifecycle). Then validate against the core schema and the `splunk-es` sub-schema.

An import is lossy in both directions. Where a field genuinely has no UDLF home and matters,
put it in `config.advanced` rather than dropping it silently — and tell the user what you did.
