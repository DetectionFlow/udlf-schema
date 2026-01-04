# Universal Detection Lifecycle Format (UDLF) Specification v0.1

The Universal Detection Lifecycle Format (UDLF) is a YAML schema for managing the cybersecurity detection logic lifecycle at scale.

## Problem Statement

Modern Threat Detection, Investigation and Response functions are using detection-as-code to improve the speed and reliabiltiy of detections. Current detection-as-code formats (Sigma, Yara-L, etc) all offer benefits but focus on managing individual detections and do not cover the entire detection engineering lifecycle. Additionally, many organsiations use multiple formats adding complexity to the detection lifecycle.

Universal Detection Lifecycle Format provides a unifying layer that manages the full detection engineering lifecycle, supports complex security data architectures and empowers deection engineering team to maximise detection-as-code benefits.

## Goals

UDLF is intended to achive the following goals:
- Provide a YAML schema that supports the full detection engineering lifecycle. Research -> Development -> Testing -> Warranty -> Deployment -> Live -> Tuning -> Decommissions / Re-Engineering
- Allow for mixed DaC formats, or raw platform specific logic, to be used in combination
- Detection packs that can manage and deploy linked atomic detections to multiple detection platforms
- Support detection logic validation, false positive testing and attack simulation

## UDLF Components

###  Content YAML

An atomic detection logic

```YAML

```

#### Strategy YAML

Pack of related deployments configurarion, may contain embedded content or links

```YAML

```

#### Deployment YAML

Core configuration, deploys content to multiple destinations

```YAML

```

## Resources

Sigma
https://github.com/SigmaHQ/sigma-specification

CoreTIDE
https://github.com/OpenTideHQ/CoreTide

YARA-L
https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview

SPL
https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/search-overview/about-the-search-language

Splunk ContentCTL
https://github.com/splunk/contentctl

KQL
https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric

NOVA
https://github.com/fr0gger/nova-framework