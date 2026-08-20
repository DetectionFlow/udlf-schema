# UDLF Schema

Universal Detection Lifecycle Format (UDLF) - A standardized schema for detection content across SIEM platforms.

## Overview

UDLF provides a vendor-neutral format for representing security detection rules, enabling:
- Consistent detection metadata across platforms
- MITRE ATT&CK mapping standardization
- Detection lifecycle management
- Cross-platform detection sharing

## Who it's for

| If you… | UDLF gives you… |
|---------|-----------------|
| **Use multiple detection formats in one repo** | SPL, KQL, Sigma, YARA-L and more coexist as `language` variants of a single detection. Existing Sigma rules embed and validate natively — no rewrite. |
| **Run multiple SIEMs / multistep detections that span platforms** | One detection holds per-platform logic variants and a `deployments` array targeting each SIEM independently. **Strategies** group the detections that work together into a single analytic story. |
| **Have a threat-hunting team using detection-as-code** | Ad-hoc hunts live as detections with **no `deployments` entry** (run on demand). As a hunt matures it moves along the `lifecycle` axis (`research → development → testing → live`), and an operationalised hunt becomes a scheduled, non-alerting deployment via `mode: monitoring` — all without leaving the format. |
| **Want to avoid branching your repo for warranty vs. live** | Runtime behavior is the `mode` field (`alert`, `warranty`, `monitoring`, `disabled`) and stage is `lifecycle` — both per-deployment. No parallel branches; a variant goes to warranty or live by changing a value. |
| **Use a SIEM natively but want DaC benefits** | Author directly in your platform's language (or wrap a Sigma rule) and get lifecycle, testing and deployment management around it. |
| **Are migrating a SIEM** | Carry logic variants for both the old and new platform in one detection; run the new platform's deployment in `warranty` while the old stays `live`, then flip when ready. |
| **Are building an internal SIEM** | A deploy-neutral source of truth with a schema to validate against; your deployer translates and pushes content to whatever backend you build. |

| File | Description |
|------|-------------|
| `schemas/udlf/v0.2.2.json` | JSON Schema for UDLF detections |
| `schemas/udlf/strategy/v0.2.0.json` | JSON Schema for UDLF strategies (grouping of detections) |
| `schemas/udlf/macro/v0.1.0.json` | JSON Schema for UDLF macros (reusable query snippets referenced by a detection's `requires`) |
| `schemas/udlf/lookup/v0.1.0.json` | JSON Schema for UDLF lookups (reference datasets referenced by a detection's `requires`) |
| `schemas/udlf/config/<platform>/v<version>.json` | Optional, opt-in sub-schemas for a deployment's `config` block (splunk, splunk-es, splunk-contentctl-v5-6, splunk-contentctl-ng, sentinel, defender-for-endpoint, crowdstrike, sentinel-one) |
| `udlf-specification.md` | Full specification document |

Each schema's path under `schemas/` mirrors its `$id` path, so the directory can be served
directly at the published URLs and superseded versions stay resolvable alongside current ones.

## Structure

```
├── schemas/                          # Served at the published $id URLs
│   └── udlf/
│       ├── v0.2.2.json               # Detection JSON Schema (current)
│       ├── v0.2.1.json               # Detection JSON Schema (superseded, still served)
│       ├── v0.2.0.json               # Detection JSON Schema (superseded, still served)
│       ├── strategy/
│       │   └── v0.2.0.json           # Strategy JSON Schema
│       └── config/                   # Opt-in per-platform deployment config sub-schemas
│           ├── splunk/v0.2.0.json
│           ├── splunk-es/v0.2.0.json
│           ├── splunk-contentctl-v5-6/v0.1.0.json
│           ├── splunk-contentctl-ng/v0.1.0.json
│           ├── sentinel/v0.1.0.json
│           ├── defender-for-endpoint/v0.1.0.json
│           ├── crowdstrike/v0.1.0.json
│           └── sentinel-one/v0.1.0.json
├── scripts/
│   └── validate-config.py            # Runs the opt-in config pass
├── udlf-specification.md             # Specification document
├── examples/                         # Example detection files
│   ├── powershell-download-cradle.udlf.yaml          # single SPL variant
│   ├── sigma-linked.udlf.yaml                        # embedded, validated Sigma rule
│   ├── process-injection-multi-deployment.udlf.yaml  # SPL + KQL, four deployments
│   └── strategies/                   # Example strategy files
│       └── defense-evasion-tampering.udlf.yaml       # strategy grouping
└── references/                       # Vendored external schemas (Sigma, etc.)
    ├── sigma-detection-rule-schema.json
    ├── sigma-correlation-rules-schema.json
    └── sigma-filters-schema.json
```

## Usage

### VS Code Validation

Add the matching header to your files:

```yaml
# detections (.udlf.yaml)
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.2.2.json

# strategies (examples/strategies/*.udlf.yaml)
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/strategy/v0.2.0.json

# macros (examples/macros/*.udlf.yaml)
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/macro/v0.1.0.json

# lookups (examples/lookups/*.udlf.yaml)
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/lookup/v0.1.0.json
```

### Programmatic Validation

Use `check-jsonschema`, which resolves the remote Sigma `$ref` used by `language: sigma` variants:

```bash
uvx check-jsonschema --schemafile schemas/udlf/v0.2.2.json examples/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/macro/v0.1.0.json examples/macros/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/lookup/v0.1.0.json examples/lookups/*.udlf.yaml
```

Macros and lookups each carry rules JSON Schema cannot express over a list — a
lookup's `key` naming a declared column and its sibling CSV matching `columns`, a
KQL macro's defaulted arguments coming last — so they need a second pass:

```bash
./scripts/validate-macros.py examples/macros/*.udlf.yaml
./scripts/validate-lookups.py examples/lookups/*.udlf.yaml
```

## Related Projects

- [DetectionFlow](https://www.detectionflow.com) - Detection engineering platform
- [udlf-template](https://github.com/DetectionFlow/udlf-template) - Template for UDLF detection repositories

## License

MIT
