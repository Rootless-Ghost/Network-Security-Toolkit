"""
Network visualization — static (matplotlib) and interactive (pyvis) graphs.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional, Tuple

from network_mapper.models import Host, HostStatus, NetworkTopology

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from pyvis.network import Network as PyvisNetwork

    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False


# Node colour scheme
_STATUS_COLORS = {
    HostStatus.UP: "#2ecc71",
    HostStatus.DOWN: "#e74c3c",
    HostStatus.UNKNOWN: "#95a5a6",
}

_SERVICE_RISK_COLORS: Dict[str, str] = {
    "telnet": "#e74c3c",
    "ftp": "#e67e22",
    "smb": "#e67e22",
    "rdp": "#e67e22",
    "vnc": "#e74c3c",
    "http": "#3498db",
    "https": "#2ecc71",
    "ssh": "#2ecc71",
    "unknown": "#bdc3c7",
}


class NetworkVisualizer:
    """
    Generates static PNG and interactive HTML graphs from a NetworkTopology.
    """

    def __init__(self, topology: NetworkTopology):
        self.topology = topology

    # ------------------------------------------------------------------
    # Static matplotlib graph
    # ------------------------------------------------------------------

    def save_static(
        self,
        output_path: str = "network_map.png",
        title: str = "Network Topology",
        figsize: Tuple[int, int] = (16, 12),
        show_labels: bool = True,
    ) -> str:
        """Save a static PNG network graph. Returns the output path."""
        if not MATPLOTLIB_AVAILABLE:
            raise RuntimeError("matplotlib is required: pip install matplotlib")

        G = self._build_nx_graph()
        if len(G.nodes) == 0:
            logger.warning("No hosts to visualise")
            return output_path

        fig, ax = plt.subplots(figsize=figsize, facecolor="#0d1117")
        ax.set_facecolor("#0d1117")

        pos = self._layout(G)
        node_colors = [self._node_color(n) for n in G.nodes()]
        node_sizes = [self._node_size(n) for n in G.nodes()]

        nx.draw_networkx_edges(
            G, pos, ax=ax, alpha=0.4, edge_color="#4a5568", width=1.2
        )
        nx.draw_networkx_nodes(
            G, pos, ax=ax,
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.9,
        )
        if show_labels:
            labels = {n: self._node_label(n) for n in G.nodes()}
            nx.draw_networkx_labels(
                G, pos, labels=labels, ax=ax,
                font_size=7, font_color="#e2e8f0",
            )

        # Legend
        patches = [
            mpatches.Patch(color="#2ecc71", label="Host UP"),
            mpatches.Patch(color="#e74c3c", label="Host DOWN"),
            mpatches.Patch(color="#95a5a6", label="Unknown"),
        ]
        ax.legend(handles=patches, loc="upper left", facecolor="#1a202c", labelcolor="white")
        ax.set_title(title, color="#e2e8f0", fontsize=14, pad=15)
        ax.axis("off")

        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close(fig)
        logger.info("Static graph saved to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Interactive pyvis graph
    # ------------------------------------------------------------------

    def save_interactive(
        self,
        output_path: str = "network_map.html",
        title: str = "Network Topology — Interactive",
    ) -> str:
        """Save an interactive HTML network graph. Returns the output path."""
        if not PYVIS_AVAILABLE:
            raise RuntimeError("pyvis is required: pip install pyvis")

        net = PyvisNetwork(
            height="750px",
            width="100%",
            bgcolor="#0d1117",
            font_color="#e2e8f0",
            notebook=False,
            directed=False,
        )
        net.set_options("""
        {
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -80,
              "centralGravity": 0.01,
              "springLength": 120
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 100}
          },
          "edges": {"color": {"color": "#4a5568"}, "smooth": false},
          "interaction": {"tooltipDelay": 100}
        }
        """)

        for ip, host in self.topology.hosts.items():
            color = _STATUS_COLORS.get(host.status, "#95a5a6")
            services = host.get_open_services()
            tooltip = self._build_tooltip(host)
            size = 15 + len(services) * 2

            net.add_node(
                ip,
                label=self._node_label(ip),
                title=tooltip,
                color=color,
                size=min(size, 40),
            )

        for edge in self.topology.edges:
            if edge.source in self.topology.hosts and edge.target in self.topology.hosts:
                net.add_edge(edge.source, edge.target, weight=edge.weight)

        net.write_html(output_path)
        logger.info("Interactive graph saved to %s", output_path)
        return output_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_nx_graph(self) -> "nx.Graph":
        G = nx.Graph()
        for ip, host in self.topology.hosts.items():
            G.add_node(ip, host=host)
        for edge in self.topology.edges:
            if edge.source in self.topology.hosts and edge.target in self.topology.hosts:
                G.add_edge(edge.source, edge.target, weight=edge.weight)
        return G

    def _layout(self, G: "nx.Graph") -> Dict:
        if len(G.nodes) <= 1:
            return {n: (0, 0) for n in G.nodes}
        try:
            return nx.spring_layout(G, k=2, iterations=50, seed=42)
        except Exception:
            return nx.random_layout(G, seed=42)

    def _node_color(self, ip: str) -> str:
        host = self.topology.hosts.get(ip)
        if not host:
            return "#95a5a6"
        if host.status == HostStatus.DOWN:
            return "#e74c3c"
        # Colour by most notable open service
        svc_names = {s.name.lower() for s in host.get_open_services()}
        for svc, color in _SERVICE_RISK_COLORS.items():
            if svc in svc_names:
                return color
        return "#2ecc71" if host.status == HostStatus.UP else "#95a5a6"

    def _node_size(self, ip: str) -> int:
        host = self.topology.hosts.get(ip)
        if not host:
            return 300
        return 300 + len(host.get_open_services()) * 50

    def _node_label(self, ip: str) -> str:
        host = self.topology.hosts.get(ip)
        if host and host.hostname:
            return f"{ip}\n{host.hostname}"
        return ip

    def _build_tooltip(self, host: Host) -> str:
        lines = [f"<b>{host.ip}</b>"]
        if host.hostname:
            lines.append(f"Hostname: {host.hostname}")
        if host.os_info:
            lines.append(f"OS: {host.os_info}")
        lines.append(f"Status: {host.status.value}")
        open_svcs = host.get_open_services()
        if open_svcs:
            lines.append(f"Open ports: {len(open_svcs)}")
            for svc in sorted(open_svcs, key=lambda s: s.port)[:8]:
                banner = svc.banner or svc.name
                lines.append(f"  {svc.port}/{svc.protocol}: {banner}")
        if host.tags:
            lines.append(f"Tags: {', '.join(host.tags)}")
        return "<br>".join(lines)
