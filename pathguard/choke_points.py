"""
Security choke point identification.
Uses graph-theoretic centrality to identify network nodes that are
critical for both attacker movement and defensive control placement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from network_mapper.models import Host, NetworkTopology
from network_mapper.path_analysis import PathAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class ChokePoint:
    ip: str
    betweenness: float        # 0–1; fraction of all shortest paths passing through
    degree: float             # 0–1; fraction of possible connections
    closeness: float          # 0–1; average closeness to all other nodes
    is_articulation: bool     # True if removing this node disconnects the graph
    composite_score: float    # Weighted combination of all metrics
    host: Optional[Host] = None

    @property
    def criticality_label(self) -> str:
        if self.composite_score >= 0.7:
            return "CRITICAL"
        elif self.composite_score >= 0.4:
            return "HIGH"
        elif self.composite_score >= 0.2:
            return "MEDIUM"
        return "LOW"

    @property
    def description(self) -> str:
        parts = []
        if self.is_articulation:
            parts.append("single point of failure")
        if self.betweenness > 0.5:
            parts.append("high-traffic relay")
        if self.degree > 0.5:
            parts.append("highly connected hub")
        return "; ".join(parts) if parts else "moderately critical junction"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.host.hostname if self.host else "",
            "betweenness": round(self.betweenness, 4),
            "degree": round(self.degree, 4),
            "closeness": round(self.closeness, 4),
            "is_articulation": self.is_articulation,
            "composite_score": round(self.composite_score, 4),
            "criticality": self.criticality_label,
            "description": self.description,
            "open_ports": len(self.host.get_open_services()) if self.host else 0,
            "tags": self.host.tags if self.host else [],
        }


class ChokePointAnalyzer:
    """
    Identifies network choke points using betweenness centrality,
    articulation point analysis, and composite scoring.
    These nodes are priority targets for defensive control placement.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._path_analyzer = PathAnalyzer(topology)

    def identify_choke_points(self, top_n: int = 20) -> List[ChokePoint]:
        """Return the top-N choke points ordered by composite score."""
        betweenness = self._path_analyzer.betweenness_centrality()
        degree = self._path_analyzer.degree_centrality()
        closeness = self._path_analyzer.closeness_centrality()
        articulation = set(self._path_analyzer.identify_critical_nodes())

        choke_points: List[ChokePoint] = []
        for ip in self.topology.hosts:
            b = betweenness.get(ip, 0.0)
            d = degree.get(ip, 0.0)
            c = closeness.get(ip, 0.0)
            is_art = ip in articulation

            # Weighted composite: betweenness is most important
            composite = (b * 0.5) + (d * 0.2) + (c * 0.2) + (0.1 if is_art else 0.0)

            cp = ChokePoint(
                ip=ip,
                betweenness=b,
                degree=d,
                closeness=c,
                is_articulation=is_art,
                composite_score=composite,
                host=self.topology.get_host(ip),
            )
            choke_points.append(cp)

        choke_points.sort(key=lambda cp: cp.composite_score, reverse=True)
        return choke_points[:top_n]

    def get_monitoring_priorities(self) -> List[ChokePoint]:
        """Return choke points ordered by monitoring importance."""
        all_cp = self.identify_choke_points(top_n=50)
        # Prioritise articulation points, then high betweenness
        return sorted(all_cp, key=lambda cp: (cp.is_articulation, cp.betweenness), reverse=True)

    def get_segmentation_points(self) -> List[Tuple[str, str]]:
        """
        Suggest network segmentation cuts: pairs of nodes whose edge removal
        would most significantly reduce attacker lateral movement options.
        """
        try:
            import networkx as nx
            G = self._path_analyzer.to_networkx()
            cuts = []
            for u, v in nx.bridges(G):
                cuts.append((u, v))
            return cuts
        except Exception:
            return []

    def summarize(self) -> dict:
        choke_points = self.identify_choke_points()
        critical = [cp for cp in choke_points if cp.criticality_label == "CRITICAL"]
        articulation = [cp for cp in choke_points if cp.is_articulation]
        return {
            "total_analyzed": len(self.topology.hosts),
            "choke_points_found": len(choke_points),
            "critical": len(critical),
            "articulation_points": len(articulation),
            "top_3": [cp.to_dict() for cp in choke_points[:3]],
        }
