# UDLF agent templates

Templates for running coding agents against a repository of UDLF detection content. They are
maintained here so they version alongside the schema, but they are meant to live in **your
detection repo**, not in this one.

```
agents/
├── AGENTS.md                      # prime directives + guardrails
└── skills/
    ├── udlf-author-detection/     # author or edit a detection
    └── udlf-import-splunk-es/     # Splunk ES savedsearch → UDLF
```

## Install

Copy into the root of your detection repository:

```sh
cp agents/AGENTS.md          /path/to/detection-repo/AGENTS.md
cp -r agents/skills/*        /path/to/detection-repo/.claude/skills/
```

`AGENTS.md` follows the [agents.md](https://agents.md) convention and is read by most coding
agents. The skills follow the [Agent Skills](https://agentskills.io) format; the path above is
where Claude Code discovers them — other harnesses differ.

Both are starting points. Extend them with your own conventions (directory layout, review
process, naming); keep the five rules in `AGENTS.md` intact, since the rest of the tooling
assumes them.
