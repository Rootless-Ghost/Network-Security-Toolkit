"""
Lateral movement and privilege escalation path detection.
Models how an attacker pivots from a foothold to higher-value targets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from network_mapper.models import Host, NetworkTopology
from pathfinder.vuln_scanner import VulnFinding, VulnScanner

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False


# ---------------------------------------------------------------------------
# Movement technique definitions
# ---------------------------------------------------------------------------

@dataclass
class MovementTechnique:
    id: str           # MITRE ATT&CK ID
    name: str
    description: str
    required_services: List[str] = field(default_factory=list)  # service names
    required_ports: List[int] = field(default_factory=list)
    privilege_gain: float = 0.0   # 0–10; higher = more privilege gained


_TECHNIQUES: List[MovementTechnique] = [
    MovementTechnique(
        id="T1021.001",
        name="Remote Desktop Protocol (RDP)",
        description="Lateral movement via RDP using stolen or default credentials.",
        required_services=["ms-wbt-server"],
        required_ports=[3389],
        privilege_gain=8.0,
    ),
    MovementTechnique(
        id="T1021.002",
        name="SMB / Windows Admin Shares",
        description="Lateral movement via SMB admin shares (C$, ADMIN$, IPC$).",
        required_services=["microsoft-ds", "netbios-ssn"],
        required_ports=[445, 139],
        privilege_gain=9.0,
    ),
    MovementTechnique(
        id="T1021.004",
        name="SSH",
        description="Lateral movement via SSH using captured keys or credentials.",
        required_services=["ssh"],
        required_ports=[22],
        privilege_gain=7.0,
    ),
    MovementTechnique(
        id="T1021.006",
        name="Windows Remote Management (WinRM)",
        description="Lateral movement via WinRM/PowerShell Remoting.",
        required_services=["wsman", "winrm"],
        required_ports=[5985, 5986],
        privilege_gain=8.5,
    ),
    MovementTechnique(
        id="T1210",
        name="Exploitation of Remote Services",
        description="Exploit vulnerable services (e.g. EternalBlue, BlueKeep).",
        required_services=["microsoft-ds", "ms-wbt-server"],
        required_ports=[445, 3389],
        privilege_gain=10.0,
    ),
    MovementTechnique(
        id="T1072",
        name="Software Deployment Tools",
        description="Lateral movement via remote admin tools (SCCM, Ansible, Puppet).",
        required_ports=[8443, 8080, 9090],
        privilege_gain=9.0,
    ),
    MovementTechnique(
        id="T1563",
        name="Remote Service Session Hijacking",
        description="Hijack existing remote sessions (VNC, RDP).",
        required_services=["vnc", "ms-wbt-server"],
        required_ports=[5900, 3389],
        privilege_gain=9.0,
    ),
    MovementTechnique(
        id="T1570",
        name="Lateral Tool Transfer",
        description="Transfer attack tools via FTP, SMB, or HTTP servers.",
        required_services=["ftp", "microsoft-ds", "http"],
        required_ports=[21, 445, 80, 8080],
        privilege_gain=4.0,
    ),
]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@dataclass
class LateralMovementStep:
    source_ip: str
    target_ip: str
    technique: MovementTechnique
    confidence: float  # 0–1; based on how many required services are present


@dataclass
class PrivescPath:
    steps: List[LateralMovementStep]
    total_privilege_gain: float
    entry_ip: str
    final_ip: str

    @property
    def hop_count(self) -> int:
        return len(self.steps)

    def to_dict(self) -> dict:
        return {
            "entry": self.entry_ip,
            "destination": self.final_ip,
            "hops": self.hop_count,
            "total_privilege_gain": round(self.total_privilege_gain, 1),
            "steps": [
                {
                    "from": s.source_ip,
                    "to": s.target_ip,
                    "technique": s.technique.name,
                    "mitre_id": s.technique.id,
                    "confidence": round(s.confidence, 2),
                    "privilege_gain": s.technique.privilege_gain,
                }
                for s in self.steps
            ],
        }


class LateralMovementAnalyzer:
    """
    Identifies feasible lateral movement paths from a compromised foothold.
    Models movement as a BFS over the network graph, selecting techniques
    applicable to each hop based on available services.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._scanner = VulnScanner()

    def analyze_from(
        self,
        entry_point: str,
        max_hops: int = 4,
    ) -> List[PrivescPath]:
        """
        Explore all reachable hosts from entry_point via lateral movement.
        Returns paths ordered by total privilege gain.
        """
        paths: List[PrivescPath] = []
        visited: Set[str] = set()
        self._dfs(entry_point, entry_point, [], 0.0, max_hops, visited, paths)
        paths.sort(key=lambda p: p.total_privilege_gain, reverse=True)
        return paths

    def techniques_for_host(self, host: Host) -> List[Tuple[MovementTechnique, float]]:
        """
        Return applicable movement techniques for a host with confidence scores.
        """
        results = []
        open_ports = {s.port for s in host.get_open_services()}
        open_services = {s.name.lower() for s in host.get_open_services()}

        for tech in _TECHNIQUES:
            port_match = any(p in open_ports for p in tech.required_ports)
            svc_match = any(s in open_services for s in tech.required_services)

            if not tech.required_ports and not tech.required_services:
                continue
            if port_match or svc_match:
                # Confidence: fraction of required indicators matched
                total_indicators = len(tech.required_ports) + len(tech.required_services)
                matched = sum(1 for p in tech.required_ports if p in open_ports) + \
                          sum(1 for s in tech.required_services if s in open_services)
                confidence = matched / max(total_indicators, 1)
                results.append((tech, confidence))

        return results

    def get_adjacent_targets(self, source_ip: str) -> List[str]:
        """Return IPs directly adjacent to source in the topology."""
        adjacents = []
        for edge in self.topology.edges:
            if edge.source == source_ip:
                adjacents.append(edge.target)
            elif edge.target == source_ip:
                adjacents.append(edge.source)
        return list(set(adjacents))

    # ------------------------------------------------------------------
    # Internal DFS
    # ------------------------------------------------------------------

    def _dfs(
        self,
        entry: str,
        current: str,
        steps: List[LateralMovementStep],
        total_gain: float,
        hops_left: int,
        visited: Set[str],
        results: List[PrivescPath],
    ) -> None:
        if hops_left == 0:
            return

        visited = visited | {current}
        for neighbor_ip in self.get_adjacent_targets(current):
            if neighbor_ip in visited:
                continue
            neighbor = self.topology.get_host(neighbor_ip)
            if not neighbor:
                continue
            techniques = self.techniques_for_host(neighbor)
            for tech, confidence in techniques:
                step = LateralMovementStep(
                    source_ip=current,
                    target_ip=neighbor_ip,
                    technique=tech,
                    confidence=confidence,
                )
                new_steps = steps + [step]
                new_gain = total_gain + tech.privilege_gain * confidence
                results.append(PrivescPath(
                    steps=new_steps,
                    total_privilege_gain=new_gain,
                    entry_ip=entry,
                    final_ip=neighbor_ip,
                ))
                self._dfs(entry, neighbor_ip, new_steps, new_gain, hops_left - 1, visited, results)
