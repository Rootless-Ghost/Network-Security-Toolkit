"""
Vulnerability prioritization based on attack paths.
Combines CVSS scores with network position (choke points, reachability)
to produce context-aware remediation priorities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from network_mapper.models import NetworkTopology
from network_mapper.path_analysis import PathAnalyzer
from pathfinder.vuln_scanner import VulnFinding, VulnScanner
from pathguard.choke_points import ChokePoint, ChokePointAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class PrioritizedFinding:
    finding: VulnFinding
    base_cvss: float
    position_multiplier: float   # > 1.0 if host is a choke point / critical node
    is_choke_point: bool
    is_articulation: bool
    composite_score: float       # base_cvss * position_multiplier
    exploitation_likelihood: str  # LIKELY, POSSIBLE, UNLIKELY

    @property
    def priority_label(self) -> str:
        if self.composite_score >= 9.0:
            return "P1 — Critical"
        elif self.composite_score >= 7.0:
            return "P2 — High"
        elif self.composite_score >= 5.0:
            return "P3 — Medium"
        elif self.composite_score >= 3.0:
            return "P4 — Low"
        return "P5 — Informational"

    def to_dict(self) -> dict:
        return {
            "priority": self.priority_label,
            "composite_score": round(self.composite_score, 2),
            "host": self.finding.host_ip,
            "port": self.finding.service.port,
            "service": self.finding.service.name,
            "vuln_id": self.finding.signature.id,
            "vuln_name": self.finding.signature.name,
            "base_cvss": self.base_cvss,
            "position_multiplier": round(self.position_multiplier, 2),
            "is_choke_point": self.is_choke_point,
            "is_articulation": self.is_articulation,
            "exploitation_likelihood": self.exploitation_likelihood,
            "cve": self.finding.signature.cve,
            "remediation": self.finding.signature.remediation,
        }


class VulnPrioritizer:
    """
    Prioritizes vulnerability findings by combining CVSS scores with
    network topology context (centrality, choke points, attack paths).

    A CVSS 9.8 on an isolated endpoint is less urgent than a CVSS 7.0
    on a network choke point that all attack paths must traverse.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._path_analyzer = PathAnalyzer(topology)
        self._choke_analyzer = ChokePointAnalyzer(topology)
        self._vuln_scanner = VulnScanner()

        # Compute centrality once
        self._betweenness = self._path_analyzer.betweenness_centrality()
        self._choke_points: Dict[str, ChokePoint] = {}
        for cp in self._choke_analyzer.identify_choke_points(top_n=100):
            self._choke_points[cp.ip] = cp

    def prioritize(self, findings: Optional[List[VulnFinding]] = None) -> List[PrioritizedFinding]:
        """
        Prioritize findings. If none supplied, scans the topology first.
        Returns findings sorted by composite score (highest first).
        """
        if findings is None:
            findings = self._vuln_scanner.scan_topology(self.topology)

        prioritized = [self._score(f) for f in findings]
        prioritized.sort(key=lambda pf: pf.composite_score, reverse=True)
        return prioritized

    def top_priorities(self, n: int = 20) -> List[PrioritizedFinding]:
        return self.prioritize()[:n]

    def by_host(self) -> Dict[str, List[PrioritizedFinding]]:
        """Group prioritized findings by host IP."""
        all_pf = self.prioritize()
        result: Dict[str, List[PrioritizedFinding]] = {}
        for pf in all_pf:
            result.setdefault(pf.finding.host_ip, []).append(pf)
        return result

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score(self, finding: VulnFinding) -> PrioritizedFinding:
        ip = finding.host_ip
        base_cvss = finding.cvss

        # Position multiplier based on betweenness centrality
        betweenness = self._betweenness.get(ip, 0.0)
        cp = self._choke_points.get(ip)
        is_choke = cp is not None and cp.composite_score > 0.2
        is_articulation = cp.is_articulation if cp else False

        # Build multiplier: 1.0 = no boost, 2.0 = max boost for choke points
        position_multiplier = 1.0 + (betweenness * 1.5)
        if is_articulation:
            position_multiplier += 0.5

        composite = min(10.0, base_cvss * position_multiplier)

        # Likelihood based on available public exploits and service exposure
        if base_cvss >= 9.0 and is_choke:
            likelihood = "LIKELY"
        elif base_cvss >= 7.0:
            likelihood = "POSSIBLE"
        else:
            likelihood = "UNLIKELY"

        return PrioritizedFinding(
            finding=finding,
            base_cvss=base_cvss,
            position_multiplier=position_multiplier,
            is_choke_point=is_choke,
            is_articulation=is_articulation,
            composite_score=composite,
            exploitation_likelihood=likelihood,
        )
