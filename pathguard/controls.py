"""
Security control placement suggestions.
Recommends where to deploy specific controls (IDS, firewall, WAF, PAM, etc.)
based on network topology and identified choke points.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network_mapper.models import Host, NetworkTopology
from pathguard.choke_points import ChokePoint, ChokePointAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class SecurityControl:
    id: str
    name: str
    category: str          # network, endpoint, identity, data, monitoring
    description: str
    placement_rationale: str
    deployment_guide: str
    cost_level: str        # low / medium / high
    effectiveness: float   # 0–10


_CONTROLS: List[SecurityControl] = [
    SecurityControl(
        id="SC-001",
        name="Network Intrusion Detection System (IDS/IPS)",
        category="network",
        description="Monitors network traffic for known attack signatures and anomalies.",
        placement_rationale="Place at choke points and subnet boundaries to maximise visibility.",
        deployment_guide=(
            "1. Deploy sensors at identified choke points (high betweenness centrality nodes).\n"
            "2. Configure Snort/Suricata with updated community rule sets.\n"
            "3. Mirror traffic from core switches to IDS sensors (SPAN ports).\n"
            "4. Forward alerts to SIEM for correlation.\n"
            "5. Tune rules to reduce false positives before enabling IPS mode."
        ),
        cost_level="medium",
        effectiveness=8.5,
    ),
    SecurityControl(
        id="SC-002",
        name="Next-Generation Firewall (NGFW)",
        category="network",
        description="Stateful inspection with application-layer visibility and control.",
        placement_rationale="Place at network segment boundaries and internet egress points.",
        deployment_guide=(
            "1. Deploy at each identified network segment boundary.\n"
            "2. Implement default-deny inbound and outbound policies.\n"
            "3. Enable application-layer inspection (SSL inspection where feasible).\n"
            "4. Configure geo-blocking for regions without business justification.\n"
            "5. Log all allowed and denied connections to SIEM."
        ),
        cost_level="high",
        effectiveness=9.0,
    ),
    SecurityControl(
        id="SC-003",
        name="Web Application Firewall (WAF)",
        category="network",
        description="Protects HTTP/HTTPS services from injection, XSS, and OWASP Top 10.",
        placement_rationale="Deploy in front of all internet-facing web services.",
        deployment_guide=(
            "1. Place WAF in reverse-proxy mode in front of web servers.\n"
            "2. Enable OWASP Core Rule Set (ModSecurity CRS).\n"
            "3. Start in detection mode; tune rules before switching to prevention.\n"
            "4. Enable rate limiting for authentication endpoints.\n"
            "5. Configure DDoS protection and bot management."
        ),
        cost_level="medium",
        effectiveness=8.0,
    ),
    SecurityControl(
        id="SC-004",
        name="Privileged Access Management (PAM)",
        category="identity",
        description="Controls, audits, and records privileged account usage.",
        placement_rationale="Deploy between administrator workstations and critical servers.",
        deployment_guide=(
            "1. Inventory all privileged accounts and service accounts.\n"
            "2. Deploy a PAM solution (CyberArk, HashiCorp Vault, BeyondTrust).\n"
            "3. Rotate all privileged credentials through the vault.\n"
            "4. Require MFA for privileged account access.\n"
            "5. Enable session recording for all privileged sessions.\n"
            "6. Implement just-in-time (JIT) privilege access."
        ),
        cost_level="high",
        effectiveness=9.5,
    ),
    SecurityControl(
        id="SC-005",
        name="Network Access Control (NAC)",
        category="network",
        description="Enforces security policy before granting network access.",
        placement_rationale="Deploy at network edge and in critical VLANs.",
        deployment_guide=(
            "1. Implement 802.1X authentication on all managed switches.\n"
            "2. Define device compliance policies (patch level, AV, EDR).\n"
            "3. Place non-compliant devices in quarantine VLAN.\n"
            "4. Integrate with Active Directory or LDAP for user authentication.\n"
            "5. Log all NAC events to SIEM."
        ),
        cost_level="medium",
        effectiveness=8.0,
    ),
    SecurityControl(
        id="SC-006",
        name="Endpoint Detection and Response (EDR)",
        category="endpoint",
        description="Behavioural endpoint monitoring with threat hunting capabilities.",
        placement_rationale="Deploy on all hosts, prioritise choke point servers first.",
        deployment_guide=(
            "1. Deploy EDR agents on all managed endpoints (servers, workstations).\n"
            "2. Enable real-time behavioural monitoring and memory scanning.\n"
            "3. Configure automated containment for high-confidence detections.\n"
            "4. Integrate with SIEM and SOAR for automated response.\n"
            "5. Conduct regular threat hunting exercises using EDR telemetry."
        ),
        cost_level="high",
        effectiveness=9.0,
    ),
    SecurityControl(
        id="SC-007",
        name="Security Information and Event Management (SIEM)",
        category="monitoring",
        description="Centralised log collection, correlation, and alerting.",
        placement_rationale="Central collection from all network segments; collectors at segment boundaries.",
        deployment_guide=(
            "1. Deploy SIEM (Splunk, Elastic SIEM, Microsoft Sentinel).\n"
            "2. Collect logs from: firewalls, IDS, AD, endpoints, servers, applications.\n"
            "3. Implement use cases for: brute force, lateral movement, data exfil.\n"
            "4. Tune alert thresholds to manageable false positive rates.\n"
            "5. Establish a SOC process for alert triage and investigation."
        ),
        cost_level="high",
        effectiveness=9.5,
    ),
    SecurityControl(
        id="SC-008",
        name="DNS Filtering / RPZ",
        category="network",
        description="Blocks malicious domains at the DNS resolver level.",
        placement_rationale="Deploy at internal DNS resolvers and egress points.",
        deployment_guide=(
            "1. Subscribe to threat intelligence DNS block lists (Cisco Umbrella, Quad9).\n"
            "2. Configure Response Policy Zones (RPZ) on internal DNS servers.\n"
            "3. Force all DNS through controlled resolvers; block UDP 53 to external IPs.\n"
            "4. Log all DNS queries for threat hunting.\n"
            "5. Alert on DNS queries matching C2 patterns (long subdomain, high entropy)."
        ),
        cost_level="low",
        effectiveness=7.5,
    ),
    SecurityControl(
        id="SC-009",
        name="Deception Technology (Honeypots/Honeytokens)",
        category="monitoring",
        description="Early-warning traps that detect attackers inside the network.",
        placement_rationale="Deploy near critical assets and in flat network segments.",
        deployment_guide=(
            "1. Deploy honeypot hosts mimicking internal systems (Active Directory, file servers).\n"
            "2. Place honeytokens (fake credentials, files) on real endpoints.\n"
            "3. Any access to decoys triggers a high-confidence alert.\n"
            "4. Integrate honeytoken alerts with SIEM for immediate response.\n"
            "5. Rotate honeytokens regularly to maintain effectiveness."
        ),
        cost_level="low",
        effectiveness=8.5,
    ),
    SecurityControl(
        id="SC-010",
        name="Multi-Factor Authentication (MFA)",
        category="identity",
        description="Requires additional proof of identity beyond passwords.",
        placement_rationale="Deploy on all remote access, VPN, admin panels, and critical services.",
        deployment_guide=(
            "1. Enforce MFA for: VPN, RDP, SSH admin access, web admin panels, email.\n"
            "2. Prefer hardware tokens (FIDO2/WebAuthn) or TOTP over SMS.\n"
            "3. Integrate with identity provider (Azure AD, Okta, Duo).\n"
            "4. Implement adaptive MFA based on risk signals (location, device).\n"
            "5. Audit MFA bypass methods and remove where possible."
        ),
        cost_level="medium",
        effectiveness=9.5,
    ),
]


@dataclass
class ControlPlacement:
    control: SecurityControl
    recommended_hosts: List[str]
    rationale: str
    priority_score: float  # 0–10

    def to_dict(self) -> dict:
        return {
            "control_id": self.control.id,
            "control_name": self.control.name,
            "category": self.control.category,
            "priority_score": round(self.priority_score, 1),
            "recommended_hosts": self.recommended_hosts,
            "rationale": self.rationale,
            "cost_level": self.control.cost_level,
            "effectiveness": self.control.effectiveness,
            "deployment_guide": self.control.deployment_guide,
        }


class SecurityControlAdvisor:
    """
    Recommends specific security controls and their optimal placement
    based on network topology analysis, choke points, and exposed services.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._choke_analyzer = ChokePointAnalyzer(topology)

    def recommend(self, top_n: int = 10) -> List[ControlPlacement]:
        """Generate ranked security control placement recommendations."""
        choke_points = self._choke_analyzer.identify_choke_points(top_n=10)
        choke_ips = [cp.ip for cp in choke_points]
        critical_ips = [cp.ip for cp in choke_points if cp.is_articulation]

        placements: List[ControlPlacement] = []

        # IDS/IPS at choke points
        if choke_ips:
            placements.append(ControlPlacement(
                control=_get_control("SC-001"),
                recommended_hosts=choke_ips[:5],
                rationale=f"Choke points carry traffic from all network segments. "
                          f"Monitoring here provides maximum visibility.",
                priority_score=9.0,
            ))

        # NGFW at segment boundaries
        egress_candidates = self._identify_egress_candidates()
        if egress_candidates:
            placements.append(ControlPlacement(
                control=_get_control("SC-002"),
                recommended_hosts=egress_candidates,
                rationale="Segment boundary and internet egress points require stateful inspection "
                          "to prevent lateral movement and data exfiltration.",
                priority_score=9.5,
            ))

        # WAF for HTTP/HTTPS services
        web_hosts = self._hosts_with_ports([80, 443, 8080, 8443])
        if web_hosts:
            placements.append(ControlPlacement(
                control=_get_control("SC-003"),
                recommended_hosts=web_hosts[:5],
                rationale="Web services are exposed to untrusted clients and require "
                          "application-layer protection against OWASP Top 10 attacks.",
                priority_score=8.0,
            ))

        # PAM for hosts with management interfaces
        admin_hosts = self._hosts_with_ports([22, 3389, 5900, 5985])
        if admin_hosts:
            placements.append(ControlPlacement(
                control=_get_control("SC-004"),
                recommended_hosts=admin_hosts[:8],
                rationale="Hosts with remote management interfaces are primary lateral movement "
                          "targets. PAM limits credential theft impact.",
                priority_score=9.5,
            ))

        # EDR on all choke points
        if choke_ips:
            placements.append(ControlPlacement(
                control=_get_control("SC-006"),
                recommended_hosts=choke_ips,
                rationale="Critical infrastructure nodes require behavioural monitoring "
                          "to detect living-off-the-land attacks.",
                priority_score=9.0,
            ))

        # SIEM — always recommended
        all_hosts = [h.ip for h in self.topology.get_live_hosts()]
        placements.append(ControlPlacement(
            control=_get_control("SC-007"),
            recommended_hosts=all_hosts[:3],  # Show first 3 as log sources
            rationale="Centralised logging is a prerequisite for all other monitoring controls.",
            priority_score=10.0,
        ))

        # MFA — always recommended
        remote_hosts = self._hosts_with_ports([22, 3389, 443, 8443])
        if remote_hosts:
            placements.append(ControlPlacement(
                control=_get_control("SC-010"),
                recommended_hosts=remote_hosts[:5],
                rationale="All remote access paths must require MFA to prevent credential-based attacks.",
                priority_score=9.5,
            ))

        # Honeypots
        placements.append(ControlPlacement(
            control=_get_control("SC-009"),
            recommended_hosts=critical_ips[:3] if critical_ips else choke_ips[:3],
            rationale="Deploy decoys near critical assets to detect attackers already inside the network.",
            priority_score=8.0,
        ))

        # DNS filtering
        dns_hosts = self._hosts_with_ports([53])
        placements.append(ControlPlacement(
            control=_get_control("SC-008"),
            recommended_hosts=dns_hosts or choke_ips[:2],
            rationale="DNS filtering blocks C2 callbacks and malware download domains at resolution time.",
            priority_score=7.5,
        ))

        placements.sort(key=lambda p: p.priority_score, reverse=True)
        return placements[:top_n]

    def _identify_egress_candidates(self) -> List[str]:
        egress_ports = {80, 443, 8080, 8443, 53, 25}
        return [
            h.ip for h in self.topology.get_live_hosts()
            if {s.port for s in h.get_open_services()} & egress_ports
        ]

    def _hosts_with_ports(self, ports: List[int]) -> List[str]:
        port_set = set(ports)
        return [
            h.ip for h in self.topology.get_live_hosts()
            if {s.port for s in h.get_open_services()} & port_set
        ]


def _get_control(control_id: str) -> SecurityControl:
    for ctrl in _CONTROLS:
        if ctrl.id == control_id:
            return ctrl
    raise KeyError(f"Unknown control ID: {control_id}")
