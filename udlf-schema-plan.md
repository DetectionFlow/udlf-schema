# Plan: Create UDLF YAML Schema

## Summary
Create a proper JSON Schema for UDLF (Universal Detection Lifecycle Format) content that works:
1. **Standalone** - Can validate YAML files programmatically
2. **VS Code** - Provides autocomplete, validation, and hover docs via YAML extension
3. **DetectionFlow Platform** - Can be used with Python (jsonschema/Pydantic) or TypeScript (ajv)

## Approach: JSON Schema (Draft 2020-12)

**Why JSON Schema?**
- Industry standard for YAML/JSON validation
- Supported by VS Code YAML extension (redhat.vscode-yaml)
- Works with Python (`jsonschema`, `pydantic`), TypeScript (`ajv`), and many other languages
- Already used in codebase for Sigma rules (`docs/references/sigma-spec/json-schema/`)

## Files to Create/Modify

### 1. Create JSON Schema: `docs/udlf-schema.json`
Full JSON Schema with:
- All fields from current template
- Type definitions with enums for lifecycle, format, language
- Required vs optional field definitions
- Description fields for VS Code hover documentation
- Examples for autocomplete

### 2. Update VS Code settings: `.vscode/settings.json`
Add YAML schema association for `*.udlf.yaml` files:
```json
{
  "yaml.schemas": {
    "./docs/udlf-schema.json": ["*.udlf.yaml"]
  }
}
```

### 3. Create example: `docs/examples/example.udlf.yaml`
Create a complete example with schema reference:
```yaml
# yaml-language-server: $schema=../udlf-schema.json
id: 550e8400-e29b-41d4-a716-446655440000
name: Detect PowerShell Download Cradle
...
```

(Keep `docs/udlf-content-template.yaml` as user scratchpad)

## JSON Schema Structure

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://detectionflow.io/schemas/udlf/v1.0.0",
  "title": "UDLF Detection Content",
  "type": "object",
  "required": ["id", "name", "lifecycle", "format", "type"],
  "properties": {
    "id": {"type": "string", "format": "uuid"},
    "name": {"type": "string", "minLength": 1},
    "lifecycle": {"enum": ["research", "development", "testing", "deployed", "decommissioned"]},
    "format": {"enum": ["udlf", "sigma", "escu"]},
    "type": {"enum": ["embed", "link"]},
    "metadata": {
      "type": "object",
      "properties": {
        "created_at": {"type": "string", "format": "date-time"},
        "updated_at": {"type": "string", "format": "date-time"},
        "created_by": {"type": "string"}
      }
    },
    "tags": {
      "type": "object",
      "properties": {
        "att&ck": {"type": "array", "items": {"type": "string"}}
      }
    },
    "sigma": {"type": "object", "properties": {"source_url": {"type": "string", "format": "uri"}}},
    "escu": {"type": "object", "properties": {"source_url": {"type": "string", "format": "uri"}}},
    "udlf": {
      "type": "object",
      "properties": {
        "source_url": {"type": "string", "format": "uri"},
        "language": {"enum": ["spl", "kql", "yara", "yara-l", "python"]},
        "logic": {"type": "string"}
      }
    }
  }
}
```

## Future Enhancements (Not in scope)
- Pydantic model for Python validation
- TypeScript types generated from schema
- Schema hosted at public URL
