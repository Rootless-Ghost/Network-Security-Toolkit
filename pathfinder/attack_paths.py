"""
Attack path mapping and analysis.
Builds a weighted attack graph where edge weights represent exploitation difficulty,
then finds the easiest (lowest-cost) paths from an attacker entry point to targets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from network_mapper.models import Host, NetworkPath, NetworkTopology
from network_mapper.path_analysis import PathAnalyzer
from pathfinder.vuln_scanner import VulnFinding, VulnScanner

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False


# CVSS → difficulty inversion: low CVSS = hard to exploit; high CVSS = easy
def _cvss_to_difficulty(cvss: float) -> float:
    """Convert a CVSS score (0–10) into an edge weight (higher = harder to cross)."""
    return max(0.1, 10.0 - cvss)


@dataclass
class AttackNode:
    ip: str
    risk_score: float = 0.0
    vulnerabilities: List[str] = field(default_factory=list)
    is_entry: bool = False
    is_target: bool = False


@dataclass
class AttackPath:
    nodes: List[str]
    edges: List[Tuple[str, str, float]]  # (src, dst, weight)
    total_difficulty: float = 0.0
    criticality_score: float = 0.0
    findings_on_path: List[VulnFinding] = field(default_factory=list)

    @property
    def hop_count(self) -> int:
        return max(0, len(self.nodes) - 1)

    @property
    def severity_label(self) -> str:
        if self.criticality_score >= 8.0:
            return "CRITICAL"
        elif self.criticality_score >= 6.0:
            return "HIGH"
        elif self.criticality_score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "path": " -> ".join(self.nodes),
            "hops": self.hop_count,
            "difficulty": round(self.total_difficulty, 2),
            "criticality": round(self.criticality_score, 2),
            "severity": self.severity_label,
            "vulnerabilities": [f.to_dict() for f in self.findings_on_path],
        }


class AttackPathFinder:
    """
    Builds an attack graph from vulnerability findings and network topology,
    then identifies the easiest attack paths from entry points to targets.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._scanner = VulnScanner()
        self._findings: Dict[str, List[VulnFinding]] = {}
        self._host_scores: Dict[str, float] = {}
        self._attack_graph: Optional["nx.DiGraph"] = None

        if NX_AVAILABLE:
            self._build_attack_graph()

    def _build_attack_graph(self) -> None:
        """
        Construct a directed attack graph.
        Nodes: hosts. Edges: weighted by exploitation difficulty (lower = easier).
        """
        self._attack_graph = nx.DiGraph()

        # Score all hosts
        for host in self.topology.get_live_hosts():
            findings = self._scanner.scan_host(host)
            self._findings[host.ip] = findings
            score = self._scanner.score_host(host)
            self._host_scores[host.ip] = score
            self._attack_graph.add_node(
                host.ip,
                risk_score=score,
                vuln_count=len(findings),
                hostname=host.hostname,
            )

        # Build directed edges based on subnet adjacency + service reachability
        for edge in self.topology.edges:
            src_score = self._host_scores.get(edge.source, 0.0)
            dst_score = self._host_scores.get(edge.target, 0.0)

            # Forward: attacker moving src → dst (difficulty based on dst vulns)
            fwd_weight = _cvss_to_difficulty(dst_score) if dst_score > 0 else 5.0
            self._attack_graph.add_edge(edge.source, edge.target, weight=fwd_weight)

            # Reverse: attacker moving dst → src
            rev_weight = _cvss_to_difficulty(src_score) if src_score > 0 else 5.0
            self._attack_graph.add_edge(edge.target, edge.source, weight=rev_weight)

    def find_attack_paths(
        self,
        entry_point: str,
        targets: Optional[List[str]] = None,
        max_hops: int = 6,
        max_paths: int = 10,
    ) -> List[AttackPath]:
        """
        Find all feasible attack paths from an entry point to target(s).
        If no targets specified, returns paths to the highest-value hosts.
        """
        if not NX_AVAILABLE:
            raise RuntimeError("networkx is required for attack path analysis.")

        if entry_point not in self._attack_graph:
            logger.warning("Entry point %s not found in attack graph.", entry_point)
            return []

        if targets is None:
            targets = self._identify_high_value_targets(exclude=entry_point)

        all_paths: List[AttackPath] = []
        for target in targets:
            if target == entry_point:
                continue
            paths = self._enumerate_paths(entry_point, target, max_hops)
            all_paths.extend(paths)

        # Sort by criticality (highest first)
        all_paths.sort(key=lambda p: p.criticality_score, reverse=True)
        return all_paths[:max_paths]

    def easiest_path(self, entry_point: str, target: str) -> Optional[AttackPath]:
        """Find the single lowest-difficulty attack path between two hosts."""
        if not NX_AVAILABLE:
            return None
        try:
            nodes = nx.shortest_path(
                self._attack_graph, entry_point, target, weight="weight"
            )
            return self._nodes_to_attack_path(nodes)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def all_reachable_from(self, entry_point: str) -> List[Tuple[str, float]]:
        """Return all hosts reachable from entry_point with their difficulty scores."""
        if not NX_AVAILABLE:
            return []
        try:
            lengths = nx.single_source_dijkstra_path_length(
                self._attack_graph, entry_point, weight="weight"
            )
            return sorted(lengths.items(), key=lambda x: x[1])
        except nx.NodeNotFound:
            return []

    def get_findings(self, ip: str) -> List[VulnFinding]:
        return self._findings.get(ip, [])

    def get_all_findings(self) -> List[VulnFinding]:
        all_findings = []
        for findings in self._findings.values():
            all_findings.extend(findings)
        return sorted(all_findings, key=lambda f: f.cvss, reverse=True)

    def host_risk_scores(self) -> Dict[str, float]:
        return dict(self._host_scores)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _enumerate_paths(
        self, source: str, target: str, max_hops: int
    ) -> List[AttackPath]:
        paths = []
        try:
            for nodes in nx.all_simple_paths(
                self._attack_graph, source, target, cutoff=max_hops
            ):
                ap = self._nodes_to_attack_path(nodes)
                paths.append(ap)
        except (nx.NodeNotFound, nx.NetworkXError):
            pass
        return paths

    def _nodes_to_attack_path(self, nodes: List[str]) -> AttackPath:
        edges = []
        total_diff = 0.0
        findings_on_path: List[VulnFinding] = []

        for i in range(len(nodes) - 1):
            src, dst = nodes[i], nodes[i + 1]
            w = self._attack_graph[src][dst].get("weight", 5.0) if self._attack_graph.has_edge(src, dst) else 5.0
            edges.append((src, dst, w))
            total_diff += w
            findings_on_path.extend(self._findings.get(dst, []))

        # Criticality: inverse of difficulty, boosted by vulnerabilities on path
        raw_crit = 10.0 - min(total_diff / max(len(nodes), 1), 10.0)
        bonus = min(2.0, len(findings_on_path) * 0.2)
        criticality = min(10.0, raw_crit + bonus)

        return AttackPath(
            nodes=list(nodes),
            edges=edges,
            total_difficulty=total_diff,
            criticality_score=criticality,
            findings_on_path=findings_on_path,
        )

    def _identify_high_value_targets(self, exclude: str) -> List[str]:
        """Identify hosts most worth attacking based on risk score."""
        scored = [
            (ip, score)
            for ip, score in self._host_scores.items()
            if ip != exclude and score > 0
        ]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [ip for ip, _ in scored[:10]]
