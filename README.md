# UDLF Schema

Universal Detection Lifecycle Format. A vendor-neutral schema for detection content across SIEM
platforms.

Existing formats describe one detection for one platform. Detection engineering rarely works that
way. The same threat-idea ends up as SPL on Splunk and KQL on Sentinel, at different maturity
stages, tuned differently per customer. UDLF holds all of that in one file, and keeps deployment
secrets out of it.

## Who it's for

| If you… | UDLF gives you… |
|---------|-----------------|
| **Keep several detection formats in one repo** | SPL, KQL, Sigma and YARA-L coexist as `language` variants of one detection. Sigma rules embed and validate natively, no rewrite. |
| **Run several SIEMs, or detections that span them** | Per-platform logic variants plus a `deployments` array targeting each SIEM independently. **Strategies** group the detections that work together into one analytic story. |
| **Have a hunting team doing detection-as-code** | Ad-hoc hunts are detections with no `deployments` entry. A hunt matures along `lifecycle` and graduates into a standing non-alerting deployment without leaving the format. |
| **Want to stop branching for staging vs. live** | `lifecycle` is the stage and `enabled` is the switch, both per deployment. A detection moves by changing a value, not a branch. |
| **Use one SIEM natively but want DaC** | Author in your platform's own language, or wrap an existing Sigma rule, and get lifecycle, testing and deployment management around it. |
| **Are migrating SIEM** | Carry both platforms' logic in one detection. Run the new one at `lifecycle: testing` while the old stays `live`, then flip. |
| **Are building an internal SIEM** | A deploy-neutral source of truth with a schema to validate against. Your deployer translates and pushes to whatever backend you built. |

## What a detection looks like

```yaml
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.3.1.json
id: a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d
title: Process Injection with Defensive Tooling Tampering
lifecycle: testing                     # research -> development -> testing -> live

metadata:
  created_at: "2026-06-10"
  version: "0.5.0"
  authors: [Alex Rivera]

detection_content:                     # one threat-idea, two query languages
  - language: spl
    logic: index=sysmon EventCode=8 GrantedAccess IN (0x1F0FFF, 0x1F1FFF) | ...
  - language: kql
    logic: DeviceEvents | where ActionType == "CreateRemoteThread" | ...

threat:
  attack:
    - technique: T1055
      tactics: [Defense Evasion, Privilege Escalation]

deployments:                           # ...shipped to two platforms
  - name: splunk-prod
    platform: splunk-es
    lifecycle: live                    # this deployment is ahead of the detection overall
    config:
      notable:                         # a `notable` block is what makes it alert
        rule_title: Process injection on $dest$
  - name: sentinel-prod
    platform: sentinel
    enabled: false                     # shipped, switched off while tuning
```

Full walkthrough in [`udlf-specification.md`](udlf-specification.md); runnable files in
[`examples/`](examples/).

## Quick start

Point your editor at the schema and you get completion and validation as you type:

```yaml
# detections
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/v0.3.1.json
# strategies
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/strategy/v0.2.0.json
# macros
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/macro/v0.1.1.json
# lookups
# yaml-language-server: $schema=https://detectionflow.com/schemas/udlf/lookup/v0.1.1.json
```

In CI, use `check-jsonschema`, which resolves the remote Sigma `$ref` that `language: sigma`
variants rely on:

```bash
uvx check-jsonschema --schemafile schemas/udlf/v0.3.1.json examples/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/strategy/v0.2.0.json examples/strategies/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/macro/v0.1.1.json examples/macros/*.udlf.yaml
uvx check-jsonschema --schemafile schemas/udlf/lookup/v0.1.1.json examples/lookups/*.udlf.yaml
```

Three things JSON Schema cannot check need a second pass. A deployment's `config` is validated by
platform, a lookup's `key` must name a declared column, and a KQL macro's defaulted arguments must
come last. The macro pass also checks that an SPL macro's `name` is its Splunk stanza name, `name(N)`
for N arguments:

```bash
./scripts/validate-config.py  --strict examples/*.udlf.yaml
./scripts/validate-lookups.py examples/lookups/*.udlf.yaml
./scripts/validate-macros.py  examples/macros/*.udlf.yaml
```

## Schemas

| File | What it describes |
|------|-------------------|
| `schemas/udlf/v0.3.1.json` | Detections. The main one. |
| `schemas/udlf/strategy/v0.2.0.json` | Strategies, which group detections under one narrative. |
| `schemas/udlf/macro/v0.1.1.json` | Macros, reusable query snippets a detection pulls in via `requires`. |
| `schemas/udlf/lookup/v0.1.1.json` | Lookups, reference datasets a detection matches against. |
| `schemas/udlf/config/<platform>/` | Optional, opt-in shapes for a deployment's `config` block. |

Nine platform config sub-schemas ship today: `splunk`, `splunk-es`, `splunk-contentctl-v5-6`,
`splunk-contentctl-ng`, `sentinel`, `defender-for-endpoint`, `crowdstrike`, `sentinel-one`, and
`udlf` for a target nothing else models. None is referenced from the core schema, so an unmodelled
platform passes through rather than failing.

Each schema's path under `schemas/` mirrors its `$id` path, so the directory is served directly at
the published URLs. Superseded versions stay resolvable, so pinned files keep validating.

## Repo layout

```
schemas/       Served at the published $id URLs. Current versions plus every superseded one.
examples/      Detections, and strategies/ macros/ lookups/ alongside them.
scripts/       The three second-pass validators.
```

## Related projects

- [DetectionFlow](https://www.detectionflow.com), a, AI-native detection engineering platform

## Licence

MIT
