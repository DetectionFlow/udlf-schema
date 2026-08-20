# UDLF Schema Repository

## What This Is
This repository contains the JSON Schema and specification for UDLF (Universal Detection Lifecycle Format) - a vendor-neutral format for security detection rules that works across SIEM platforms.

## Key Files
- `schemas/udlf/v0.2.2.json` - Detection JSON Schema for validation (uses JSON Schema Draft 2020-12)
- `schemas/udlf/strategy/v0.2.0.json` - Strategy JSON Schema (analytic-story grouping of detections)
- `schemas/udlf/config/<platform>/v<version>.json` - Optional, opt-in sub-schemas for `deployments[].config`.
  Not `$ref`'d from the core schema; applied as a separate pass via `scripts/validate-config.py`
- `udlf-specification.md` - Human-readable specification document
- `examples/*.udlf.yaml` - Example detection files; `examples/strategies/*.udlf.yaml` - strategy files
- `references/` - Vendored copies of external schemas (Sigma). Not currently wired into validation.

## Important Conventions
- Detection files use `.udlf.yaml` extension; strategy files live under `examples/strategies/`
- The Sigma `$ref` points at an immutable upstream tag (SigmaHQ/sigma-specification `v2.1.0`), not `main`
- Schema ID follows pattern: `https://detectionflow.com/schemas/udlf/v{version}.json` (strategy under `.../udlf/strategy/v{version}.json`, config sub-schemas under `.../udlf/config/{platform}/v{version}.json`). The `.json` suffix is deliberate — the web host serving detectionflow.com appends it to extensionless paths, so a bare `$id` does not resolve.
- **Every schema's repo path mirrors its `$id` path** (`schemas/udlf/v0.2.2.json` ⇄ `/schemas/udlf/v0.2.2.json`), so `schemas/` is served directly at the published URLs. Keep them in lockstep — a new version means a new file, not an edit to the old one, so superseded versions stay resolvable.
- Examples should include the yaml-language-server header for VS Code validation

## Common Tasks

### Modifying the Schema
- `schemas/udlf/v0.2.2.json` is the current detection schema; `v0.2.0.json` and `v0.2.1.json` are
  frozen and stay served. A structural change means copying to a new `v{next}.json`, updating `$id`/`title`, and
  repointing the examples + docs — not editing a published version in place.
- Update `udlf-specification.md` to reflect schema changes
- Test changes against example files in `examples/`
- Once changes have been completed and validated, ask if the schema version should be updated

### Adding Examples
- Use `.udlf.yaml` extension
- Include yaml-language-server header pointing to the schema
- Validate against schema before committing

### Validation
Validate examples with `check-jsonschema` (resolves the remote Sigma `$ref`):
- `uvx check-jsonschema --schemafile schemas/udlf/v0.2.2.json examples/*.udlf.yaml`
- `uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml`

`deployments[].config` is free-form to the core schema, so it needs a second, opt-in pass that
dispatches on the sibling `platform` (check-jsonschema cannot do this):
- `./scripts/validate-config.py examples/*.udlf.yaml`

## Schema Structure (v0.2)
- **No top-level `format`.** A detection carries `detection_content` as an **array** of logic
  variants, each `{ language, description?, logic }`. `language` is the discriminator; `sigma` is a
  language whose `logic` is an embedded native Sigma object validated against the pinned SigmaHQ
  schema. Variants may share a `language` (tstats vs raw-log SPL, per-client tuning); the optional
  `description` is a short human label for telling them apart — documentation only, never a
  deploy-time selector.
- **Two independent axes:** `lifecycle` (research → development → testing → live → decommissioned)
  is maturity; a deployment's `mode` (alert | warranty | monitoring | disabled) is runtime behavior.
- **`deployments`** is an array of `{ name?, platform, mode, lifecycle?, config? }`. `platform`
  (splunk|splunk-es|splunk-contentctl-v5-6|splunk-contentctl-ng|elastic|sentinel, extensible) is the
  discriminator — selects the logic variant and scopes the meaning of `config`; `name` (listed first) is a friendly endpoint
  resolved to infra/secrets by the deployer. Everything platform-specific (schedule, suppression,
  notable, rba, vendor round-trip fields) lives inside the free-form `config` object. `mode` governs
  notable vs risk-only; there is no separate `actions` list. Deploy-neutral **policy** only, never
  secrets/mechanics. Per-deployment `lifecycle` inherits the top-level when omitted.
- **Eight config sub-schemas ship today**: splunk, splunk-es, splunk-contentctl-v5-6,
  splunk-contentctl-ng, sentinel, defender-for-endpoint, crowdstrike, sentinel-one. `elastic` is
  unmodelled, so its config passes through unvalidated. Every shape leaves out what UDLF owns elsewhere: the query (it belongs in
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
  and MDE have no `Critical`, SentinelOne has no `Informational`. Sole exceptions:
  the two contentctl platforms have no override. contentctl v5.6's `Deployment.alert_action.notable`
  carries only rule_title/rule_description/nes_fields, and ESCU 6.x has no severity field at all —
  weight is an explicit integer `score` on each finding/intermediate-finding entity.
- **Not every platform is a scheduled search.** MDE couples frequency to lookback via a fixed enum;
  CrowdStrike schedules with a start/end window; SentinelOne has no schedule at all. MDE `actions`
  and SentinelOne `response` can isolate/quarantine/disable — `mode` describes detection behaviour
  only, so those blocks carry blast radius `mode` does not convey.
- **`platform` can name a toolchain, not just a product**, where that changes the shape of `config`.
  `splunk` and `splunk-es` are built and uploaded as an app by the deployer; the two contentctl
  values hand a contentctl-shaped detection to a build pipeline. They are **siblings, not versions
  of each other**, and are named by different rules: `splunk-contentctl-v5-6` names a *frozen*
  format (contentctl's 5.x line ended at v5.6), so the name safely carries the tool minor;
  `splunk-contentctl-ng` names a *live* toolchain — there is no contentctl v6, the successor is a
  rewrite published as `contentctl-ng` (1.0.2) consuming the ESCU 6.x format — so it carries no
  version and the sub-schema's own semver absorbs format drift. In both, `type`
  (TTP|Anomaly|Hunting|Correlation) is the discriminator and the config is *not* a superset of
  splunk-es. What differs: v5.6 matches `type` to a built-in ESCU **deployment** for its schedule
  (hence no `schedule` block) and forbids `rba` on Hunting/Correlation; ng has no deployments at
  all — scheduling is a named `schedule` or inline `custom_schedule` — and replaces `rba` with the
  ES8 findings model (`finding` + `intermediate_findings` + top-level `threat_objects`), with a
  strict per-`type` matrix the sub-schema enforces in `allOf`. ESCU 6.x also flattened the `tags`
  block, added a required `category`, dropped `enabled_by_default`, and **removed `throttling`
  outright** — suppression is only expressible on the splunk-es or v5.6 deployments.
- **Config sub-schemas are opt-in and closed.** They are never `$ref`'d from the core schema, so
  core validation is unchanged and an unmodelled platform is skipped rather than rejected. Each
  versions independently on its own semver line — `v0.1.0` while core is `v0.2.2` — and
  `config.schema: "splunk-es::0.2.0"` pins an exact revision (pre-1.0 promises no compatibility
  within a major, so the pin is exact, not compatible-within-major). Every shape offers an
  `advanced` map for raw vendor keys (savedsearches.conf keys, for the Splunk shapes) except the two
  contentctl shapes, which do not, because contentctl forbids extra keys itself. Each mirrors what
  *its own* deployer enforces, so they legitimately differ (e.g. suppression-window units).
  Exception: `splunk-es` threat-object types accept the **union** of the Splunk RBA community list
  and contentctl's, because ES constrains the value not at all and contentctl writes its own
  spelling verbatim into savedsearches.conf — so a live ES instance contains both. Never rewrite
  between the spellings; a detection with both deployments needs each intact.
- **Threat** tagging uses paired `attack: [{ technique, tactics }]` plus `software`/`groups`/`cve`
  and a free-form `custom_tags` dict.
- Optional blocks: `tests` (framework-based, extensible), `links` (typed relationships),
  `changelog` (top-level, append-only history: `{ date, version, author, summary }`).
- A **strategy** groups detections by id under a narrative (`schemas/udlf/strategy/v0.2.0.json`).
