<div align="center">

# network-security-toolkit

> Unified red/blue team network security toolkit built on a shared core library. 
> PathFinder maps attack paths. PathGuard hardens defenses. NetworkMapper powers both.

⚠️ AUTHORIZED SECURITY TESTING ONLY ⚠️ 
PathFinder is designed for use against networks you own or have explicit permission to test. Unauthorized use is illegal.


## Overview

</div>

This toolkit provides a unified approach to network security assessment by combining offensive and defensive perspectives:

- **NetworkMapper**: Core shared library for network discovery, mapping, and visualization
- **PathFinder**: Red team tool for attack path analysis and vulnerability assessment
- **PathGuard**: Blue team tool for defensive security analysis and hardening recommendations

The yin-yang design philosophy enables security professionals to use the same codebase for both offensive security testing and defensive security improvements.

## Features

### Core Components (NetworkMapper)
- Network topology discovery and mapping
- Host and service enumeration
- Path analysis between network nodes
- Standardized data structures for network information
- Network visualization with interactive graphs

### Red Team Tool (PathFinder)
- Attack path mapping and analysis
- Shodan API integration for external attack surface discovery
- Vulnerable service identification
- Privilege escalation and lateral movement path detection
- Data exfiltration route identification
- Stealth scanning capabilities
- Attack visualization with criticality scoring

### Blue Team Tool (PathGuard)
- Defensive network analysis
- Security choke point identification
- Security hardening recommendations
- Network change detection through baseline comparison
- Vulnerability prioritization based on attack paths
- Security control placement suggestions
- Remediation recommendations with priority scoring

## Installation

### Using Poetry (recommended)

```bash
# Clone the repository
git clone https://github.com/Rootless-Ghost/network-security-toolkit.git
cd network-security-toolkit

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell
