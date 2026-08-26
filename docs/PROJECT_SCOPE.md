# Project Scope

## Overview

Agent Observatory is an experimental security and observability project for independently measuring the externally observable behavior of desktop AI applications.

The project focuses on what operating systems and network infrastructure can observe about AI-enabled software without relying solely on vendor-provided telemetry or self-reported agent logs.

## Research Question

The primary research question is:

> Can desktop AI applications be independently observed, characterized, and monitored using endpoint and network telemetry?

The project is especially interested in whether changes in application behavior can be detected over time through reproducible measurements.

## Initial Research Targets

The initial research environment includes:

- Claude Desktop / Cowork
- ChatGPT Desktop
- Gemini accessed through a desktop web browser

These targets represent different deployment models:

- native desktop AI application;
- agent-capable desktop application;
- browser-hosted AI service.

The project is not limited to these products.

Future profiles may include:

- Claude Code
- Codex
- GitHub Copilot
- Cursor
- local LLM runtimes
- MCP-enabled agents
- other desktop AI applications

## Observation Layers

Agent Observatory is designed around independently observable system behavior.

Initial observation layers include:

### Endpoint telemetry

- process discovery
- process trees
- process creation and termination
- command-line metadata
- local network sockets
- filesystem activity
- selected operating-system events

### Network telemetry

- connection flows
- source and destination addresses
- ports
- DNS activity
- TLS metadata
- traffic volume
- connection duration
- connection frequency

### Correlation

Endpoint and network observations may be correlated using attributes such as:

- timestamps
- process identifiers
- local ports
- remote addresses
- remote ports
- DNS resolution history

## Research Principles

### Observe behavior, not intent

Agent Observatory does not attempt to determine whether an AI model is malicious, deceptive, aligned, or acting with a particular intention.

The project measures externally observable behavior.

### Independent observation

Where practical, observations should come from infrastructure outside the monitored AI application.

Examples include:

- operating-system process telemetry;
- Windows event sources;
- an independent Linux network sensor;
- packet and flow analysis.

### Reproducibility

Experiments should document:

- environment;
- software versions;
- configuration;
- procedure;
- observations;
- limitations;
- conclusions.

### Least interference

Early experiments should be passive whenever possible.

The initial project stages prioritize:

1. observation;
2. baseline measurement;
3. correlation;
4. anomaly detection.

Automated blocking or active containment is outside the initial scope.

## Initial Laboratory

The initial laboratory contains:

- a Windows workstation running desktop AI applications;
- a Linux mini-PC acting as an independent network sensor;
- a dedicated Ethernet subnet between the systems;
- optional routing of workstation Internet traffic through the Linux sensor.

This allows experiments to operate in two modes:

### Normal mode

The workstation accesses the Internet directly.

Network visibility from the Linux sensor is partial.

### Lab mode

The workstation routes Internet traffic through the Linux sensor.

Network visibility is considered full for workstation egress through that route.

## Out of Scope

The initial project does not attempt to:

- infer AI consciousness or intent;
- inspect private model reasoning;
- bypass application security controls;
- defeat TLS encryption;
- intercept user credentials;
- exploit AI applications;
- perform malware analysis automatically;
- replace a full EDR, IDS, or SIEM platform.

These boundaries may evolve as the research develops.

## Project Status

Agent Observatory is currently in:

**Early research / pre-alpha**

The architecture is expected to change as experiments reveal what can and cannot be reliably observed.