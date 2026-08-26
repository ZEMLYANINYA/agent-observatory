# Agent Observatory

Independent endpoint and network observability for desktop AI agents.

> **Status:** early research / pre-alpha

Agent Observatory is an experimental security and observability project for independently measuring the externally observable behavior of desktop AI applications.

The project focuses on endpoint and network telemetry rather than attempting to infer model intent.

## Core principle

**We observe behavior. We do not infer intent.**

## Initial research targets

- Claude Desktop / Cowork
- ChatGPT Desktop
- Gemini in a desktop browser

## Planned observation layers

- process and process-tree activity
- network connections
- filesystem activity
- endpoint/network correlation
- behavioral baselines
- capability drift
- anomaly detection

## Research environment

The initial laboratory consists of:

- a Windows workstation running desktop AI clients;
- an independent Linux network sensor;
- a dedicated Ethernet subnet between the two systems;
- optional full-egress routing through the Linux sensor during controlled experiments.

## License

To be defined before the first public release.