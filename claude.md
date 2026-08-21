## Important Conventions
- The Sigma `$ref` points at an immutable upstream tag (SigmaHQ/sigma-specification `v2.1.0`), not `main`
- Schema ID follows pattern: `https://detectionflow.com/schemas/udlf/v{version}.json` (strategy under `.../udlf/strategy/v{version}.json`, config sub-schemas under `.../udlf/config/{platform}/v{version}.json`). The `.json` suffix is deliberate
- Every schema's repo path mirrors its `$id` path (`schemas/udlf/v0.3.0.json` ⇄ `/schemas/udlf/v0.3.0.json`)

## Schema Descriptions
- Description fields within schema documents should be short, tooltip-style, help text that aid human engineers and agents in quickly understanding the field purpose and usage.
- Long multi sentence should be avoided, detailed usage documentation should be in `udlf-specification.md` file **not** the schema json.
- Bad example: "Detection logic variants. Each entry is one language + its logic. A deployer selects the variant appropriate to a target (e.g. Splunk -> spl). Several entries may share a language (e.g. a tstats-accelerated SPL alongside a raw-log SPL, or one tuned per client); give those an optional 'description' so a human can tell them apart. For language 'sigma', 'logic' is an embedded native Sigma rule object validated against the pinned SigmaHQ schema; for every other language 'logic' is the raw query string."
- Good example: "Detection logic variants. Each entry is one language + logic. 'sigma' is an embeded sigma object"
- Descriptions reflect the current state and **must not** include changelog notes or future looking statements such as "Renamed from v0.2.0 'how_to_implement'" or "This may be more stuctured in future". Keep that for the `udlf-specification.md` document.

## Common Tasks

### Modifying the Schema
- `schemas/udlf/v0.3.0.json` is the current detection schema; `v0.2.0.json`, `v0.2.1.json` and
  `v0.2.2.json` are frozen and stay served. A structural change means copying to a new `v{next}.json`, updating `$id`/`title`, and
  repointing the examples + docs. Do not edit a published version in place, with the exception of changes to the wording of description fields which can an be made without version bumps
- Update `udlf-specification.md` to reflect schema changes
- Test changes against example files in `examples/`
- Once changes have been completed and validated, ask if the schema version should be updated

### Adding Examples
- Include yaml-language-server header pointing to the schema
- Validate against schema before committing

### Validation
Validate examples with `check-jsonschema` (resolves the remote Sigma `$ref`):
- `uvx check-jsonschema --schemafile schemas/udlf/v0.3.0.json examples/*.udlf.yaml`
- `uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml`

`deployments[].config` is free-form to the core schema, so it needs a second, opt-in pass that
dispatches on the sibling `platform` (check-jsonschema cannot do this):
- `./scripts/validate-config.py examples/*.udlf.yaml`