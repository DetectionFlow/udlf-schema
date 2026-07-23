# UDLF Schema Repository

## What This Is
This repository contains the JSON Schema and specification for UDLF (Universal Detection Lifecycle Format) - a vendor-neutral format for security detection rules that works across SIEM platforms.

## Key Files
- `udlf-schema.json` - Detection JSON Schema for validation (uses JSON Schema Draft 2020-12)
- `udlf-strategy-schema.json` - Strategy JSON Schema (analytic-story grouping of detections)
- `udlf-specification.md` - Human-readable specification document
- `examples/*.udlf.yaml` - Example detection files; `examples/strategies/*.udlf.yaml` - strategy files
- `references/` - Vendored copies of external schemas (Sigma). Not currently wired into validation.

## Important Conventions
- Detection files use `.udlf.yaml` extension; strategy files live under `examples/strategies/`
- The Sigma `$ref` points at an immutable upstream tag (SigmaHQ/sigma-specification `v2.1.0`), not `main`
- Schema ID follows pattern: `https://detectionflow.com/schemas/udlf/v{version}` (strategy under `.../udlf/strategy/v{version}`)
- Examples should include the yaml-language-server header for VS Code validation

## Common Tasks

### Modifying the Schema
- Edit `udlf-schema.json` for structural changes
- Update `udlf-specification.md` to reflect schema changes
- Test changes against example files in `examples/`
- Once changes have been completed and validated, ask if the schema version should be updated

### Adding Examples
- Use `.udlf.yaml` extension
- Include yaml-language-server header pointing to the schema
- Validate against schema before committing

### Validation
Validate examples with `check-jsonschema` (resolves the remote Sigma `$ref`):
- `uvx check-jsonschema --schemafile udlf-schema.json examples/*.udlf.yaml`
- `uvx check-jsonschema --schemafile udlf-strategy-schema.json examples/strategies/*.udlf.yaml`

## Schema Structure (v0.2)
- **No top-level `format`.** A detection carries `detection_content` as an **array** of logic
  variants, each `{ language, logic }`. `language` is the discriminator; `sigma` is a language
  whose `logic` is an embedded native Sigma object validated against the pinned SigmaHQ schema.
- **Two independent axes:** `lifecycle` (research → development → testing → live → decommissioned)
  is maturity; a deployment's `mode` (alert | warranty | monitoring | disabled) is runtime behavior.
- **`deployments`** is an array of `{ name?, platform, mode, lifecycle?, schedule?, suppression?,
  rba? }`. `platform` (splunk|splunk-es|elastic|sentinel, extensible) is the discriminator —
  selects the variant + the shape of the Splunk-family config blocks; `name` (listed first) is a
  friendly endpoint resolved to infra/secrets by the deployer. `rba` is Splunk ES Risk-Based
  Alerting and is **required on every `splunk-es` deployment** (`mode` governs notable vs risk-only;
  no separate `actions` list). Deploy-neutral **policy** only (schedule/suppression/rba), never
  secrets/mechanics. Per-deployment `lifecycle` inherits the top-level when omitted.
- **Threat** tagging uses paired `attack: [{ technique, tactics }]` plus `software`/`groups`/`cve`
  and a free-form `custom_tags` dict.
- Optional blocks: `tests` (framework-based, extensible), `links` (typed relationships),
  `changelog` (top-level, append-only history: `{ date, version, author, summary }`).
- A **strategy** groups detections by id under a narrative (`udlf-strategy-schema.json`).
