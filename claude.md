# UDLF Schema Repository

## What This Is
This repository contains the JSON Schema and specification for UDLF (Universal Detection Lifecycle Format) - a vendor-neutral format for security detection rules that works across SIEM platforms.

## Key Files
- `schemas/udlf/v0.2.0.json` - Detection JSON Schema for validation (uses JSON Schema Draft 2020-12)
- `schemas/udlf/strategy/v0.2.0.json` - Strategy JSON Schema (analytic-story grouping of detections)
- `schemas/udlf/config/<platform>/v<version>.json` - Optional, opt-in sub-schemas for `deployments[].config`.
  Not `$ref`'d from the core schema; applied as a separate pass via `scripts/validate-config.py`
- `udlf-specification.md` - Human-readable specification document
- `examples/*.udlf.yaml` - Example detection files; `examples/strategies/*.udlf.yaml` - strategy files
- `references/` - Vendored copies of external schemas (Sigma). Not currently wired into validation.

## Important Conventions
- Detection files use `.udlf.yaml` extension; strategy files live under `examples/strategies/`
- The Sigma `$ref` points at an immutable upstream tag (SigmaHQ/sigma-specification `v2.1.0`), not `main`
- Schema ID follows pattern: `https://detectionflow.com/schemas/udlf/v{version}` (strategy under `.../udlf/strategy/v{version}`, config sub-schemas under `.../udlf/config/{platform}/v{version}`)
- **Every schema's repo path mirrors its `$id` path** (`schemas/udlf/v0.2.0.json` ⇄ `/schemas/udlf/v0.2.0`), so `schemas/` is served directly at the published URLs. Keep them in lockstep — a new version means a new file, not an edit to the old one, so superseded versions stay resolvable.
- Examples should include the yaml-language-server header for VS Code validation

## Common Tasks

### Modifying the Schema
- Edit `schemas/udlf/v0.2.0.json` for structural changes (v0.2.0 is unreleased, so it is still
  edited in place; once published, a change means copying to a new `v{next}.json` and updating `$id`)
- Update `udlf-specification.md` to reflect schema changes
- Test changes against example files in `examples/`
- Once changes have been completed and validated, ask if the schema version should be updated

### Adding Examples
- Use `.udlf.yaml` extension
- Include yaml-language-server header pointing to the schema
- Validate against schema before committing

### Validation
Validate examples with `check-jsonschema` (resolves the remote Sigma `$ref`):
- `uvx check-jsonschema --schemafile schemas/udlf/v0.2.0.json examples/*.udlf.yaml`
- `uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml`

`deployments[].config` is free-form to the core schema, so it needs a second, opt-in pass that
dispatches on the sibling `platform` (check-jsonschema cannot do this):
- `./scripts/validate-config.py examples/*.udlf.yaml`

## Schema Structure (v0.2)
- **No top-level `format`.** A detection carries `detection_content` as an **array** of logic
  variants, each `{ language, logic }`. `language` is the discriminator; `sigma` is a language
  whose `logic` is an embedded native Sigma object validated against the pinned SigmaHQ schema.
- **Two independent axes:** `lifecycle` (research → development → testing → live → decommissioned)
  is maturity; a deployment's `mode` (alert | warranty | monitoring | disabled) is runtime behavior.
- **`deployments`** is an array of `{ name?, platform, mode, lifecycle?, config? }`. `platform`
  (splunk|splunk-es|splunk-contentctl-v5-6|elastic|sentinel, extensible) is the discriminator — selects
  the logic variant and scopes the meaning of `config`; `name` (listed first) is a friendly endpoint
  resolved to infra/secrets by the deployer. Everything platform-specific (schedule, suppression,
  notable, rba, vendor round-trip fields) lives inside the free-form `config` object. `mode` governs
  notable vs risk-only; there is no separate `actions` list. Deploy-neutral **policy** only, never
  secrets/mechanics. Per-deployment `lifecycle` inherits the top-level when omitted.
- **Seven config sub-schemas ship today**: splunk, splunk-es, splunk-contentctl-v5-6, sentinel,
  defender-for-endpoint, crowdstrike, sentinel-one. `elastic` is unmodelled, so its config passes
  through unvalidated. Every shape leaves out what UDLF owns elsewhere: the query (it belongs in
  `detection_content`), lifecycle/mode, authorship, the target endpoint set, and vendor-assigned
  rule ids (UDLF is desired-state only). Plain ATT&CK restatements are dropped in favour of
  `threat`; proprietary taxonomies (CrowdStrike `CSTA*`, MDE `category`, Sentinel's tactic
  spelling) are modelled because `threat` can't express them.
- **`severity` is inherited by default and overridable everywhere.** `detection_context.severity` is
  the source of truth; every deployment derives from it unless `config.severity` says otherwise.
  The override is optional, sits at the top of each config, and always uses **UDLF's** vocabulary
  (`critical|high|medium|low|informational`) rather than the vendor's — an author never needs to
  know the platform spelling. The **deployer** translates and collapses: Splunk ES takes the five
  values verbatim, CrowdStrike title-cases, Splunk maps to the numeric `alert.severity`, Sentinel
  and MDE have no `Critical`, SentinelOne has no `Informational`. Sole exception:
  `splunk-contentctl-v5-6` has no override, because contentctl's `Deployment.alert_action.notable`
  carries only rule_title/rule_description/nes_fields and cannot author a per-detection severity.
- **Not every platform is a scheduled search.** MDE couples frequency to lookback via a fixed enum;
  CrowdStrike schedules with a start/end window; SentinelOne has no schedule at all. MDE `actions`
  and SentinelOne `response` can isolate/quarantine/disable — `mode` describes detection behaviour
  only, so those blocks carry blast radius `mode` does not convey.
- **`platform` can name a toolchain, not just a product**, where that changes the shape of `config`.
  `splunk` and `splunk-es` are built and uploaded as an app by the deployer; `splunk-contentctl-v5-6`
  hands a contentctl-shaped detection to the contentctl pipeline. The platform name carries the
  **tool** version where that tool's format is unstable across majors — `-v5-6` targets contentctl
  v5.6; a v6.3 path would be a sibling value (`splunk-contentctl-v6-3`), not a redefinition, and
  the trailing `::0.1.0` pin versions UDLF's mapping, not contentctl. The contentctl config is *not* a
  superset of splunk-es — its `type` (TTP|Anomaly|Hunting|Correlation) supplies the schedule via
  ESCU deployment matching, so it has no `schedule` block, and `rba` is forbidden on Hunting and
  Correlation.
- **Config sub-schemas are opt-in and closed.** They are never `$ref`'d from the core schema, so
  core validation is unchanged and an unmodelled platform is skipped rather than rejected. Each
  versions independently on its own semver line — `v0.1.0` while core is `v0.2.0` — and
  `config.schema: "splunk-es::0.1.0"` pins an exact revision (pre-1.0 promises no compatibility
  within a major, so the pin is exact, not compatible-within-major). Every shape offers an
  `advanced` map for raw vendor keys (savedsearches.conf keys, for the Splunk shapes) except
  `splunk-contentctl-v5-6`, which does not, because contentctl forbids extra keys itself. Each mirrors what *its own* deployer enforces, so they
  legitimately differ (e.g. suppression-window units). Exception: `splunk-es` threat-object types
  accept the **union** of the Splunk RBA community list and contentctl's, because ES constrains the
  value not at all and contentctl writes its own spelling verbatim into savedsearches.conf — so a
  live ES instance contains both. Never rewrite between the spellings; a detection with both
  deployments needs each intact.
- **Threat** tagging uses paired `attack: [{ technique, tactics }]` plus `software`/`groups`/`cve`
  and a free-form `custom_tags` dict.
- Optional blocks: `tests` (framework-based, extensible), `links` (typed relationships),
  `changelog` (top-level, append-only history: `{ date, version, author, summary }`).
- A **strategy** groups detections by id under a narrative (`schemas/udlf/strategy/v0.2.0.json`).
