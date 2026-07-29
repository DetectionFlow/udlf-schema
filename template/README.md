# UDLF Detections Repository

This repository contains detection rules in [Universal Detection Lifecycle Format (UDLF)](https://github.com/DetectionFlow/udlf-schema).

## Structure

```
└── detections/
    ├── endpoint/             # Endpoint detection rules
    ├── network/              # Network detection rules
    ├── application/          # Application/identity detection rules
    ├── cloud/                # clouddetection rules    
    └── other/                # Other detection rules
└── hunting/                  # UDLF files for hunting queries
└── detection-strategies/     # Detection strategy UDLF yaml
```

## Working with agents

If coding agents author or edit detections in this repo, copy the templates from
[`agents/`](../agents/) in the udlf-schema repo — an `AGENTS.md` with the guardrails agents need,
plus skills for authoring detections and importing from Splunk ES.

