# UDLF Schema Repository

## What This Is
This repository contains the JSON Schema and specification for UDLF (Universal Detection Lifecycle Format) - a vendor-neutral format for security detection rules that works across SIEM platforms.

## Key Files
- `udlf-schema.json` - Main JSON Schema for validation (uses JSON Schema Draft 2020-12)
- `udlf-specification.md` - Human-readable specification document
- `examples/*.udlf.yaml` - Example detection files demonstrating UDLF usage
- `references/` - External schema references (Sigma detection schemas)

## Important Conventions
- Detection files use `.udlf.yaml` extension
- Schema uses absolute URLs for external references (e.g., GitHub raw URLs for Sigma schemas)
- Schema ID follows pattern: `https://detectionflow.com/schemas/udlf/v{version}`
- Examples should include the yaml-language-server header for VS Code validation

## Common Tasks

### Modifying the Schema
- Edit `udlf-schema.json` for structural changes
- Update `udlf-specification.md` to reflect schema changes
- Test changes against example files in `examples/`

### Adding Examples
- Use `.udlf.yaml` extension
- Include yaml-language-server header pointing to the schema
- Validate against schema before committing

### Validation
The schema supports three formats:
- `format: udlf` - Generic UDLF with language + logic fields
- `format: sigma` - Native Sigma detection format (references external schema)
- `format: escu` - Splunk ESCU format

## Schema Structure
The schema defines lifecycle stages (research → development → testing → deployed → decommissioned), MITRE ATT&CK tagging, and detection metadata alongside the actual detection logic.
