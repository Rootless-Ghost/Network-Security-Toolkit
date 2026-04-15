"""
Path analysis between network nodes.
Uses NetworkX for graph-based shortest-path and reachability analysis.
"""

from __future__ import annotations

import logging
from typing import Dict, Generator, List, Optional, Tuple

from network_mapper.models import NetworkEdge, NetworkPath, NetworkTopology

logger = logging.getLogger(__name__)

try:
    import networkx as nx

    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False
    logger.error("networkx is required for path analysis. Install with: pip install networkx")


class PathAnalyzer:
    """
    Converts a NetworkTopology into a NetworkX graph and provides
    shortest-path, reachability, and centrality analysis.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology
        self._graph: Optional["nx.Graph"] = None
        self._digraph: Optional["nx.DiGraph"] = None
        if NX_AVAILABLE:
            self._build_graphs()

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def _build_graphs(self) -> None:
        self._graph = nx.Graph()
        self._digraph = nx.DiGraph()

        for ip, host in self.topology.hosts.items():
            attrs = {
                "hostname": host.hostname,
                "os": host.os_info,
                "status": host.status.value,
                "service_count": len(host.get_open_services()),
                "tags": ",".join(host.tags),
            }
            self._graph.add_node(ip, **attrs)
            self._digraph.add_node(ip, **attrs)

        for edge in self.topology.edges:
            self._graph.add_edge(edge.source, edge.target, weight=edge.weight)
            self._digraph.add_edge(edge.source, edge.target, weight=edge.weight)

    def rebuild(self) -> None:
        """Rebuild the internal graphs from the current topology state."""
        if NX_AVAILABLE:
            self._build_graphs()

    # ------------------------------------------------------------------
    # Path queries
    # ------------------------------------------------------------------

    def shortest_path(self, source: str, target: str) -> Optional[NetworkPath]:
        """Return the shortest unweighted path between two hosts."""
        self._require_nx()
        try:
            nodes = nx.shortest_path(self._graph, source, target)
            return self._nodes_to_path(nodes)
        except (nx.NetworkXNoPath, nx.NodeNotFound) as exc:
            logger.debug("No path from %s to %s: %s", source, target, exc)
            return None

    def shortest_weighted_path(self, source: str, target: str) -> Optional[NetworkPath]:
        """Return the lowest-weight path between two hosts."""
        self._require_nx()
        try:
            nodes = nx.shortest_path(self._graph, source, target, weight="weight")
            cost = nx.shortest_path_length(self._graph, source, target, weight="weight")
            path = self._nodes_to_path(nodes)
            path.total_cost = cost
            return path
        except (nx.NetworkXNoPath, nx.NodeNotFound) as exc:
            logger.debug("No weighted path from %s to %s: %s", source, target, exc)
            return None

    def all_simple_paths(
        self, source: str, target: str, max_hops: int = 6
    ) -> List[NetworkPath]:
        """Return all simple paths up to max_hops between two hosts."""
        self._require_nx()
        paths = []
        try:
            for nodes in nx.all_simple_paths(self._graph, source, target, cutoff=max_hops):
                paths.append(self._nodes_to_path(nodes))
        except (nx.NodeNotFound, nx.NetworkXError) as exc:
            logger.debug("Path enumeration failed: %s", exc)
        return paths

    def reachable_from(self, source: str) -> List[str]:
        """Return all hosts reachable from source."""
        self._require_nx()
        try:
            return list(nx.descendants(self._graph, source))
        except nx.NodeNotFound:
            return []

    def is_reachable(self, source: str, target: str) -> bool:
        """Check if target is reachable from source."""
        self._require_nx()
        try:
            return nx.has_path(self._graph, source, target)
        except nx.NodeNotFound:
            return False

    # ------------------------------------------------------------------
    # Centrality and topology metrics
    # ------------------------------------------------------------------

    def betweenness_centrality(self) -> Dict[str, float]:
        """
        Compute betweenness centrality for all nodes.
        High-centrality nodes are potential choke points.
        """
        self._require_nx()
        return nx.betweenness_centrality(self._graph, normalized=True, weight="weight")

    def degree_centrality(self) -> Dict[str, float]:
        """Compute degree centrality — how connected each node is."""
        self._require_nx()
        return nx.degree_centrality(self._graph)

    def closeness_centrality(self) -> Dict[str, float]:
        """Compute closeness centrality — how close each node is to all others."""
        self._require_nx()
        return nx.closeness_centrality(self._graph)

    def identify_choke_points(self, top_n: int = 5) -> List[Tuple[str, float]]:
        """
        Return the top-N nodes by betweenness centrality.
        These are the most critical paths in the network.
        """
        bc = self.betweenness_centrality()
        ranked = sorted(bc.items(), key=lambda x: x[1], reverse=True)
        return ranked[:top_n]

    def identify_critical_nodes(self) -> List[str]:
        """
        Return nodes whose removal disconnects the graph (articulation points).
        These are single points of failure / high-value targets.
        """
        self._require_nx()
        try:
            return list(nx.articulation_points(self._graph))
        except Exception:
            return []

    def connected_components(self) -> List[List[str]]:
        """Return lists of hosts that form connected sub-networks."""
        self._require_nx()
        return [list(c) for c in nx.connected_components(self._graph)]

    def network_diameter(self) -> Optional[int]:
        """Return the diameter (longest shortest path) of the graph."""
        self._require_nx()
        try:
            if nx.is_connected(self._graph):
                return nx.diameter(self._graph)
        except Exception:
            pass
        return None

    def average_path_length(self) -> Optional[float]:
        """Return the average shortest path length."""
        self._require_nx()
        try:
            if nx.is_connected(self._graph):
                return nx.average_shortest_path_length(self._graph)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Graph export
    # ------------------------------------------------------------------

    def to_networkx(self) -> "nx.Graph":
        """Return the underlying NetworkX graph for external use."""
        self._require_nx()
        return self._graph

    def to_digraph(self) -> "nx.DiGraph":
        """Return the directed version of the graph."""
        self._require_nx()
        return self._digraph

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _nodes_to_path(self, nodes: List[str]) -> NetworkPath:
        edges = []
        for i in range(len(nodes) - 1):
            src, dst = nodes[i], nodes[i + 1]
            weight = self._graph[src][dst].get("weight", 1.0) if self._graph.has_edge(src, dst) else 1.0
            edges.append(NetworkEdge(source=src, target=dst, weight=weight))
        total_cost = sum(e.weight for e in edges)
        return NetworkPath(nodes=list(nodes), edges=edges, total_cost=total_cost)

    def _require_nx(self) -> None:
        if not NX_AVAILABLE:
            raise RuntimeError("networkx is required. Install with: pip install networkx")
        if self._graph is None:
            self._build_graphs()
