<div align="center">

# network-security-toolkit

### Unified Red/Blue Team Network Security Toolkit

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Poetry](https://img.shields.io/badge/Poetry-Package_Manager-60A5FA?style=flat-square&logo=poetry&logoColor=white)](https://python-poetry.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-9D1AF7?style=flat-square)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_Mapped-red?style=flat-square)](https://attack.mitre.org)
[![Authorized Use Only](https://img.shields.io/badge/Use-Authorized_Testing_Only-red?style=flat-square)]()

⚠️ **AUTHORIZED SECURITY TESTING ONLY** ⚠️ 

PathFinder is designed for use against networks you own or have explicit permission to test. Unauthorized use is illegal.


## Overview

</div>

This toolkit provides a unified approach to network security assessment by combining offensive and defensive perspectives:

## Components

| Component | Role | Description |
|-----------|------|-------------|
| `NetworkMapper` | Core library | Network discovery, topology mapping, path analysis, visualization |
| `PathFinder` | Red team | Attack path analysis, lateral movement detection, Shodan integration |
| `PathGuard` | Blue team | Defensive analysis, hardening recommendations, baseline change detection |

The yin-yang design philosophy enables security professionals to use the same codebase for both offensive security testing and defensive security improvements.

## Features

### NetworkMapper (Shared Core)
- Network topology discovery and mapping
- Host and service enumeration
- Path analysis between network nodes
- Standardized data structures with full JSON serialization
- Interactive HTML and dark-theme PNG visualization

### PathFinder (Red Team)
- Attack path mapping with CVSS-weighted graph traversal
- Shodan API integration for external attack surface discovery
- 15 vulnerability signatures across common services
- MITRE ATT&CK lateral movement technique mapping (T1021.001–T1563)
- Exfiltration channel identification with stealth scoring
- Stealth scanning with jitter, decoys, and randomized host ordering
- Attack visualization with criticality scoring

### PathGuard (Blue Team)
- Choke point analysis using betweenness, degree, and closeness centrality
- 13 hardening rules mapped to CIS Controls and NIST SP 800-53
- Baseline manager with CRITICAL/WARN/INFO change detection
- Vulnerability prioritization: CVSS × network position weighting
- 10 security control deployment guides (NGFW, IDS, WAF, PAM, EDR, SIEM, MFA, and more)
- Prioritized remediation roadmap generation

## Installation

### Using Poetry (recommended)

```bash
git clone https://github.com/Rootless-Ghost/network-security-toolkit.git
cd network-security-toolkit

# Install with Poetry (recommended)
poetry install
poetry shell
```
---

## Usage

```bash
# Discover and map a network
network-mapper discover 192.168.1.0/24 -s -o topo.json --html map.html

# Red team analysis (requires authorization confirmation)
pathfinder scan 192.168.1.0/24 --stealth -o topo.json
pathfinder analyze topo.json --html attack.html --report pf-report.json

# Blue team analysis
pathguard analyze topo.json --report pg-report.json
pathguard baseline --topology topo.json --save --name baseline-2026-04-15
pathguard remediate topo.json --report roadmap.json
```

## Requirements

- Python 3.x
- Poetry
- Nmap
- Optional: Shodan API key (PathFinder external recon)

---

## Project Structure

network-security-toolkit/
├── pyproject.toml          ← Poetry config, 3 CLI entry points
├── network_mapper/         ← Core shared library (6 modules)
├── pathfinder/             ← Red team tool (9 modules)
└── pathguard/              ← Blue team tool (8 modules)

---

## Requirements

- Python 3.x
- Poetry
- Nmap
- Optional: Shodan API key (PathFinder external recon)

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

`Python` `Red Team` `Blue Team` `Network Security` `MITRE ATT&CK` `Shodan` `CIS Controls` `NIST 800-53`

**Built by [Rootless-Ghost](https://github.com/Rootless-Ghost)**
