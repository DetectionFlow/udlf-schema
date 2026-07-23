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
| **Are migrating a SIEM** | Carry logic variants for both the old and new platform in one detection; run the new target in `warranty` while the old stays `live`, then flip when ready. |
| **Are building an internal SIEM** | A deploy-neutral source of truth with a schema to validate against; your deployer translates and pushes content to whatever backend you build. |

| File | Description |
|------|-------------|
| `udlf-schema.json` | JSON Schema for UDLF detections |
| `udlf-strategy-schema.json` | JSON Schema for UDLF strategies (grouping of detections) |
| `udlf-specification.md` | Full specification document |

## Structure

```
├── udlf-schema.json                  # Detection JSON Schema
├── udlf-strategy-schema.json         # Strategy JSON Schema
├── udlf-specification.md             # Specification document
├── examples/                         # Example detection files
│   ├── powershell-download-cradle.udlf.yaml          # single SPL variant
│   ├── sigma-linked.udlf.yaml                        # embedded, validated Sigma rule
│   ├── process-injection-multi-deployment.udlf.yaml  # SPL + KQL, two deployments
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
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.2.0

# strategies (examples/strategies/*.udlf.yaml)
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/strategy/v0.2.0
```

### Programmatic Validation

Use `check-jsonschema`, which resolves the remote Sigma `$ref` used by `language: sigma` variants:

```bash
uvx check-jsonschema --schemafile udlf-schema.json examples/*.udlf.yaml
uvx check-jsonschema --schemafile udlf-strategy-schema.json examples/strategies/*.udlf.yaml
```

## Related Projects

- [DetectionFlow](https://www.detectionflow.com) - Detection engineering platform
- [udlf-template](https://github.com/DetectionFlow/udlf-template) - Template for UDLF detection repositories

## License

MIT
