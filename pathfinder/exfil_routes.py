"""
Data exfiltration route identification.
Identifies paths from internal hosts to internet-facing egress points
and the protocols/services that could be abused for data exfiltration.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from network_mapper.models import Host, NetworkTopology
from network_mapper.path_analysis import PathAnalyzer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exfiltration channel definitions
# ---------------------------------------------------------------------------

@dataclass
class ExfilChannel:
    id: str
    name: str
    description: str
    protocol: str
    typical_ports: List[int]
    stealth_rating: float    # 0–10; higher = harder to detect
    bandwidth: str           # low / medium / high
    detection_notes: str = ""


_CHANNELS: List[ExfilChannel] = [
    ExfilChannel(
        id="DNS-TUNNEL",
        name="DNS Tunneling",
        description="Encode data in DNS queries/responses. Hard to detect without DPI.",
        protocol="DNS",
        typical_ports=[53],
        stealth_rating=9.0,
        bandwidth="low",
        detection_notes="Monitor for long/high-entropy DNS names and abnormal query rates.",
    ),
    ExfilChannel(
        id="HTTPS-C2",
        name="HTTPS / TLS Exfiltration",
        description="Exfil via HTTPS to attacker-controlled server. Blends with normal traffic.",
        protocol="HTTPS",
        typical_ports=[443, 8443],
        stealth_rating=8.5,
        bandwidth="high",
        detection_notes="SSL inspection or JA3 fingerprinting may reveal C2 traffic.",
    ),
    ExfilChannel(
        id="HTTP-PLAIN",
        name="HTTP POST Exfiltration",
        description="Exfil via plain HTTP. Detectable with DPI but common in poorly segmented networks.",
        protocol="HTTP",
        typical_ports=[80, 8080],
        stealth_rating=5.0,
        bandwidth="high",
        detection_notes="Network DLP or web proxy inspection can detect unusual HTTP POSTs.",
    ),
    ExfilChannel(
        id="FTP-EXFIL",
        name="FTP Exfiltration",
        description="Use FTP to transfer files to external server.",
        protocol="FTP",
        typical_ports=[21],
        stealth_rating=3.0,
        bandwidth="high",
        detection_notes="FTP traffic should be blocked at perimeter. Easy to detect.",
    ),
    ExfilChannel(
        id="SMTP-EXFIL",
        name="Email / SMTP Exfiltration",
        description="Email data to external attacker-controlled address.",
        protocol="SMTP",
        typical_ports=[25, 465, 587],
        stealth_rating=4.0,
        bandwidth="medium",
        detection_notes="Block outbound port 25. DLP on email content.",
    ),
    ExfilChannel(
        id="ICMP-TUNNEL",
        name="ICMP Tunneling",
        description="Encode data in ICMP echo packets. Allowed by many firewalls.",
        protocol="ICMP",
        typical_ports=[],
        stealth_rating=7.5,
        bandwidth="low",
        detection_notes="Monitor abnormal ICMP packet sizes/frequencies.",
    ),
    ExfilChannel(
        id="SMB-EXFIL",
        name="SMB / File Share Exfiltration",
        description="Copy files to external-facing SMB share.",
        protocol="SMB",
        typical_ports=[445],
        stealth_rating=4.0,
        bandwidth="high",
        detection_notes="Block outbound SMB at perimeter (port 445). UEBA on file access patterns.",
    ),
    ExfilChannel(
        id="SSH-SCP",
        name="SSH / SCP Exfiltration",
        description="Use SCP or SSH tunnel to exfiltrate data.",
        protocol="SSH",
        typical_ports=[22],
        stealth_rating=7.0,
        bandwidth="high",
        detection_notes="Unusual outbound SSH connections. Inspect SSH session metadata.",
    ),
]


@dataclass
class ExfilRoute:
    source_ip: str
    egress_ip: str
    path_nodes: List[str]
    channels: List[ExfilChannel]
    stealth_score: float      # Average stealth across channels
    risk_score: float         # Overall risk to data

    @property
    def hop_count(self) -> int:
        return max(0, len(self.path_nodes) - 1)

    @property
    def best_channel(self) -> Optional[ExfilChannel]:
        return max(self.channels, key=lambda c: c.stealth_rating) if self.channels else None

    def to_dict(self) -> dict:
        return {
            "source": self.source_ip,
            "egress": self.egress_ip,
            "route": " -> ".join(self.path_nodes),
            "hops": self.hop_count,
            "stealth_score": round(self.stealth_score, 1),
            "risk_score": round(self.risk_score, 1),
            "available_channels": [
                {"id": c.id, "name": c.name, "stealth": c.stealth_rating}
                for c in sorted(self.channels, key=lambda c: c.stealth_rating, reverse=True)
            ],
        }


class ExfilRouteAnalyzer:
    """
    Identifies data exfiltration routes from internal source hosts
    to internet-facing egress points in the network topology.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._analyzer = PathAnalyzer(topology)

    def identify_egress_points(self) -> List[str]:
        """
        Identify hosts likely to have internet egress:
        - hosts running HTTP/HTTPS/DNS
        - hosts tagged as gateways
        - hosts at subnet boundaries
        """
        egress_ips: List[str] = []
        egress_ports = {53, 80, 443, 8080, 8443, 3128}
        for host in self.topology.get_live_hosts():
            host_ports = {s.port for s in host.get_open_services()}
            if host_ports & egress_ports:
                egress_ips.append(host.ip)
            elif "gateway" in host.tags or "router" in host.tags:
                egress_ips.append(host.ip)
        return list(set(egress_ips))

    def find_exfil_routes(
        self,
        source_ip: str,
        egress_points: Optional[List[str]] = None,
    ) -> List[ExfilRoute]:
        """Find all exfiltration routes from source to egress points."""
        if egress_points is None:
            egress_points = self.identify_egress_points()

        routes: List[ExfilRoute] = []
        for egress_ip in egress_points:
            if egress_ip == source_ip:
                continue
            path = self._analyzer.shortest_path(source_ip, egress_ip)
            if path is None:
                continue
            channels = self._available_channels_via(egress_ip)
            if not channels:
                continue
            stealth = sum(c.stealth_rating for c in channels) / len(channels)
            risk = min(10.0, stealth * len(channels) * 0.3)
            routes.append(ExfilRoute(
                source_ip=source_ip,
                egress_ip=egress_ip,
                path_nodes=path.nodes,
                channels=channels,
                stealth_score=stealth,
                risk_score=risk,
            ))

        routes.sort(key=lambda r: r.stealth_score, reverse=True)
        return routes

    def analyze_all_sources(self) -> Dict[str, List[ExfilRoute]]:
        """Find exfil routes from every live host to every egress point."""
        egress_points = self.identify_egress_points()
        results: Dict[str, List[ExfilRoute]] = {}
        for host in self.topology.get_live_hosts():
            routes = self.find_exfil_routes(host.ip, egress_points)
            if routes:
                results[host.ip] = routes
        return results

    def _available_channels_via(self, egress_ip: str) -> List[ExfilChannel]:
        """Determine which exfil channels are available through an egress host."""
        host = self.topology.get_host(egress_ip)
        if not host:
            return []
        open_ports = {s.port for s in host.get_open_services()}
        available = []
        for channel in _CHANNELS:
            # ICMP and DNS always considered available unless proven blocked
            if not channel.typical_ports:
                available.append(channel)
                continue
            if any(p in open_ports for p in channel.typical_ports):
                available.append(channel)
        return available
