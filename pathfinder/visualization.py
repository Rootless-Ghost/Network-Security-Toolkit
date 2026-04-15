"""
Attack visualization with criticality scoring.
Generates attack-path graphs with colour-coded risk levels.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

from network_mapper.models import NetworkTopology
from pathfinder.attack_paths import AttackPath

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import LinearSegmentedColormap

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from pyvis.network import Network as PyvisNetwork
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False


# Risk level colours
_CRIT_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
}

_NODE_BASE_COLOR = "#3498db"
_ENTRY_COLOR = "#9b59b6"
_TARGET_COLOR = "#e74c3c"


class AttackVisualizer:
    """
    Renders attack path graphs for PathFinder analysis results.
    Nodes are sized/coloured by risk score; edges show criticality.
    """

    def __init__(
        self,
        topology: NetworkTopology,
        risk_scores: Optional[Dict[str, float]] = None,
    ):
        self.topology = topology
        self.risk_scores = risk_scores or {}

    # ------------------------------------------------------------------
    # Static PNG
    # ------------------------------------------------------------------

    def save_attack_graph(
        self,
        attack_paths: List[AttackPath],
        output_path: str = "attack_paths.png",
        entry_point: Optional[str] = None,
        title: str = "Attack Path Analysis",
        figsize: Tuple[int, int] = (18, 13),
    ) -> str:
        if not MATPLOTLIB_AVAILABLE:
            raise RuntimeError("matplotlib is required: pip install matplotlib")

        G = self._build_attack_nx_graph(attack_paths)
        if len(G.nodes) == 0:
            logger.warning("No attack paths to visualise.")
            return output_path

        fig, ax = plt.subplots(figsize=figsize, facecolor="#0d1117")
        ax.set_facecolor("#0d1117")

        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)

        # Draw edges coloured by criticality
        for u, v, data in G.edges(data=True):
            crit = data.get("criticality", 5.0)
            color = self._crit_to_color(crit)
            nx.draw_networkx_edges(
                G, pos, edgelist=[(u, v)], ax=ax,
                edge_color=[color], width=2.5, alpha=0.75,
                arrows=True, arrowsize=15,
                connectionstyle="arc3,rad=0.1",
            )

        # Draw nodes
        for node in G.nodes():
            risk = self.risk_scores.get(node, 0.0)
            if node == entry_point:
                color = _ENTRY_COLOR
            elif G.nodes[node].get("is_target"):
                color = _TARGET_COLOR
            else:
                color = self._risk_to_color(risk)
            size = 600 + risk * 80

            nx.draw_networkx_nodes(
                G, pos, nodelist=[node], ax=ax,
                node_color=[color], node_size=size, alpha=0.9,
            )

        labels = {n: self._node_label(n) for n in G.nodes()}
        nx.draw_networkx_labels(G, pos, labels=labels, ax=ax, font_size=7, font_color="#e2e8f0")

        # Edge labels: criticality score
        edge_labels = {
            (u, v): f"{data.get('criticality', 0):.1f}"
            for u, v, data in G.edges(data=True)
        }
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax,
                                      font_size=6, font_color="#f39c12")

        # Legend
        patches = [
            mpatches.Patch(color=_ENTRY_COLOR, label="Entry Point"),
            mpatches.Patch(color=_TARGET_COLOR, label="Target"),
            mpatches.Patch(color=_CRIT_COLORS["CRITICAL"], label="Critical Path"),
            mpatches.Patch(color=_CRIT_COLORS["HIGH"], label="High Path"),
            mpatches.Patch(color=_CRIT_COLORS["MEDIUM"], label="Medium Path"),
            mpatches.Patch(color=_CRIT_COLORS["LOW"], label="Low Path"),
        ]
        ax.legend(handles=patches, loc="upper left", facecolor="#1a202c", labelcolor="white", fontsize=8)
        ax.set_title(title, color="#e2e8f0", fontsize=14, pad=15)
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close(fig)
        logger.info("Attack graph saved to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Interactive HTML
    # ------------------------------------------------------------------

    def save_interactive_attack_graph(
        self,
        attack_paths: List[AttackPath],
        output_path: str = "attack_paths.html",
        entry_point: Optional[str] = None,
        title: str = "Attack Path Analysis — Interactive",
    ) -> str:
        if not PYVIS_AVAILABLE:
            raise RuntimeError("pyvis is required: pip install pyvis")

        net = PyvisNetwork(
            height="750px",
            width="100%",
            bgcolor="#0d1117",
            font_color="#e2e8f0",
            directed=True,
        )
        net.set_options("""
        {
          "physics": {
            "barnesHut": {"gravitationalConstant": -8000, "springLength": 200},
            "stabilization": {"iterations": 150}
          },
          "edges": {"smooth": {"type": "curvedCW", "roundness": 0.1}, "arrows": {"to": {"enabled": true}}},
          "interaction": {"tooltipDelay": 100}
        }
        """)

        added_nodes = set()
        added_edges = set()

        for ap in attack_paths:
            crit_color = _CRIT_COLORS.get(ap.severity_label, "#bdc3c7")
            for i, node_ip in enumerate(ap.nodes):
                if node_ip not in added_nodes:
                    risk = self.risk_scores.get(node_ip, 0.0)
                    if node_ip == entry_point:
                        color, label = _ENTRY_COLOR, f"ENTRY\n{node_ip}"
                    elif i == len(ap.nodes) - 1:
                        color, label = _TARGET_COLOR, f"TARGET\n{node_ip}"
                    else:
                        color, label = self._risk_to_color(risk), node_ip
                    size = 20 + risk * 3
                    tooltip = self._build_node_tooltip(node_ip, risk, ap)
                    net.add_node(node_ip, label=label, color=color, size=size, title=tooltip)
                    added_nodes.add(node_ip)

            for src, dst, diff in ap.edges:
                edge_key = (src, dst)
                if edge_key not in added_edges:
                    net.add_edge(
                        src, dst,
                        color=crit_color,
                        title=f"Difficulty: {diff:.1f} | Criticality: {ap.criticality_score:.1f}",
                        width=2,
                    )
                    added_edges.add(edge_key)

        net.write_html(output_path)
        logger.info("Interactive attack graph saved to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_attack_nx_graph(self, attack_paths: List[AttackPath]) -> "nx.DiGraph":
        G = nx.DiGraph()
        for ap in attack_paths:
            for node in ap.nodes:
                G.add_node(node)
            for src, dst, diff in ap.edges:
                if G.has_edge(src, dst):
                    # Keep highest-criticality edge label
                    existing_crit = G[src][dst].get("criticality", 0)
                    if ap.criticality_score > existing_crit:
                        G[src][dst]["criticality"] = ap.criticality_score
                        G[src][dst]["difficulty"] = diff
                else:
                    G.add_edge(src, dst, criticality=ap.criticality_score, difficulty=diff)
        return G

    def _node_label(self, ip: str) -> str:
        host = self.topology.hosts.get(ip)
        if host and host.hostname:
            return f"{ip}\n{host.hostname[:15]}"
        return ip

    def _build_node_tooltip(self, ip: str, risk: float, ap: AttackPath) -> str:
        host = self.topology.hosts.get(ip)
        lines = [f"<b>{ip}</b>", f"Risk score: {risk:.1f}/10"]
        if host:
            if host.hostname:
                lines.append(f"Hostname: {host.hostname}")
            open_svcs = host.get_open_services()
            if open_svcs:
                lines.append(f"Open ports: {len(open_svcs)}")
        lines.append(f"Path criticality: {ap.criticality_score:.1f}")
        return "<br>".join(lines)

    @staticmethod
    def _crit_to_color(score: float) -> str:
        if score >= 8.0:
            return _CRIT_COLORS["CRITICAL"]
        elif score >= 6.0:
            return _CRIT_COLORS["HIGH"]
        elif score >= 4.0:
            return _CRIT_COLORS["MEDIUM"]
        return _CRIT_COLORS["LOW"]

    @staticmethod
    def _risk_to_color(score: float) -> str:
        if score >= 8.0:
            return "#e74c3c"
        elif score >= 6.0:
            return "#e67e22"
        elif score >= 4.0:
            return "#f1c40f"
        return _NODE_BASE_COLOR
