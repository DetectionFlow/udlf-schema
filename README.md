# UDLF Schema

Universal Detection Lifecycle Format (UDLF) - A standardized schema for detection content across SIEM platforms.

## Overview

UDLF provides a vendor-neutral format for representing security detection rules, enabling:
- Consistent detection metadata across platforms
- MITRE ATT&CK mapping standardization
- Detection lifecycle management
- Cross-platform detection sharing

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
