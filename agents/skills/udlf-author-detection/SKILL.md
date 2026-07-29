---
name: udlf-author-detection
description: Author a new UDLF detection or edit an existing one. Use whenever creating, modifying, tuning or reviewing a *.udlf.yaml detection file — adding logic, changing severity or threat mapping, adjusting a deployment, or preparing a detection for review.
---

# Authoring a UDLF detection

## Read the schema first

Open the schema at the URL in the file's `yaml-language-server` header before you write anything.
It is the authoritative list of fields, which are required, and which values each enum accepts.
This skill deliberately does not restate it — a copy here would drift.

Also read a neighbouring detection in this repo for house style, and
[`udlf-specification.md`](https://github.com/DetectionFlow/udlf-schema/blob/main/udlf-specification.md)
when you need the reasoning behind a field rather than its shape.

## Order of work

Work outside-in, so the logic is written against a settled idea rather than the reverse:

1. **Identity** — fresh `uuid4`, a `title` that names the behaviour (not the tool), and the
   `lifecycle` stage the work actually starts at (usually `development`).
2. **Context** — `detection_context`: what it detects and why, what will falsely fire, what the
   analyst should do next, and the telemetry it assumes. Write these for the on-call analyst who
   meets the alert at 3am with none of your context.
3. **Threat** — `threat.attack` technique/tactic pairs, cited against a stated `attack_version`.
4. **Logic** — one `detection_content` entry per language. Each variant must express the *same*
   detection idea; if they diverge, they are two detections.
5. **Deployments** — where it runs, and at what `mode`. A detection with no `deployments` entry
   is a valid on-demand hunt; do not invent a deployment to fill the field.
6. **Tests and links**, where they earn their place.
7. **Version and changelog**, then validate.

## Self-review before proposing

- Does it validate? Core schema *and* the config sub-schema for each deployment's platform.
- Is the `id` new, and does every `links[].target` resolve to something real in this repo?
- Would the `false_positives` text survive contact with the actual environment, or is it a guess?
- Is every ATT&CK id one you verified, not one you recalled?
- Do all logic variants still agree after your edit — or did you touch one and leave the rest?
- Is `metadata.version` bumped and a changelog entry appended?
- Is there anything in `config` that a deployer should own instead?

## Anti-patterns

| Don't | Why |
|---|---|
| Put the query in `deployments[].config` | Logic lives in `detection_content`, once, regardless of how many platforms run it. |
| Use `mode: disabled` to mean "not finished" | That's `lifecycle`. `mode` is runtime behaviour on a live platform. |
| Set `config.severity` on every deployment | `detection_context.severity` is inherited by default. Only override where a platform genuinely differs, and always in UDLF's vocabulary — the deployer translates. |
| Restate ATT&CK in `threat.custom_tags` | `threat.attack` already carries it. `custom_tags` is for taxonomies UDLF can't express. |
| Invent a `language` or `mode` value | Both enums are closed. If a value is genuinely missing, that's a schema change, not a local one. |
| Copy an `id`, or a whole file, from an example | Examples exist to be read, not cloned. Fresh UUID, every time. |
| Paste a vendor rule id into `id` | UDLF ids are UDLF's. Vendor provenance belongs on a `links` entry. |
| Write logic you cannot explain | If you can't say which field carries the signal and why the threshold is where it is, don't propose it. |
