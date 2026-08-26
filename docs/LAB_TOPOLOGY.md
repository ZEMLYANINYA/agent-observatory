# Laboratory Topology

## Purpose

This document describes the initial laboratory network used by Agent Observatory.

The laboratory is designed to provide two independent observation points:

1. endpoint telemetry collected on the Windows workstation;
2. network telemetry collected by a separate Linux sensor.

The Linux sensor can also act as the workstation's Internet gateway during controlled experiments.

## Systems

### Windows Workstation

Primary research endpoint.

Initial roles:

- runs desktop AI applications;
- runs the Agent Observatory endpoint sensor;
- produces process and operating-system telemetry;
- provides local socket information for network correlation.

Initial AI research targets include:

- Claude Desktop / Cowork;
- ChatGPT Desktop;
- Gemini through a desktop browser.

### Linux Sensor

Independent Linux mini-PC.

Initial roles:

- network observation;
- traffic capture during controlled experiments;
- flow metadata collection;
- DNS observation;
- TLS metadata observation;
- future Zeek integration;
- future Suricata integration;
- storage of independent network evidence.

The Linux sensor is physically connected to the Windows workstation through Ethernet.

## Dedicated Ethernet Network

The Windows workstation and Linux sensor communicate over a dedicated Ethernet subnet.

Conceptually:

```text
Windows Workstation
        |
        | Ethernet
        |
        v
   Linux Sensor