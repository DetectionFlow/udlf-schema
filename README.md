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
| `udlf-schema.json` | JSON Schema for UDLF validation |
| `udlf-specification.md` | Full specification document |

## Structure

```
├── udlf-schema.json          # Main JSON Schema
├── udlf-specification.md     # Specification document
├── examples/                 # Example UDLF files
│   ├── powershell-download-cradle.udlf.yaml
│   └── sigma-linked.udlf.yaml
├── drafts/                   # Draft schemas for future versions
│   ├── udlf-content-draft.yaml
│   ├── udlf-deployment-draft.yaml
│   └── udlf-strategy-draft.yaml
└── references/               # Reference schemas (Sigma, etc.)
    ├── sigma-detection-rule-schema.json
    ├── sigma-correlation-rules-schema.json
    └── sigma-filters-schema.json
```

## Usage

### VS Code Validation

Add this header to your `.udlf.yaml` files:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/DetectionFlow/udlf-schema/main/udlf-schema.json
```

### Programmatic Validation

```python
import jsonschema
import yaml
import json

# Load schema
with open('udlf-schema.json') as f:
    schema = json.load(f)

# Validate a UDLF file
with open('detection.udlf.yaml') as f:
    detection = yaml.safe_load(f)

jsonschema.validate(detection, schema)
```

## Related Projects

- [DetectionFlow](https://github.com/DetectionFlow/detectionflow) - Detection engineering platform
- [udlf-template](https://github.com/DetectionFlow/udlf-template) - Template for UDLF detection repositories

## License

MIT
