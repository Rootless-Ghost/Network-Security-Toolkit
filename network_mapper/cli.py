#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetworkMapper CLI — network topology discovery and mapping.
"""

import argparse
import json
import logging
import sys

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _progress(msg: str) -> None:
    console.print(msg, style="cyan")


def cmd_discover(args: argparse.Namespace) -> int:
    from network_mapper.discovery import NetworkDiscovery
    from network_mapper.enumeration import ServiceEnumerator

    disc = NetworkDiscovery(
        targets=args.targets,
        timeout=args.timeout,
        max_workers=args.threads,
        progress_callback=_progress,
    )

    if args.services:
        topology = disc.discover_with_services(ports=args.ports)
    else:
        topology = disc.discover()

    if args.tag:
        enumerator = ServiceEnumerator(timeout=args.timeout)
        enumerator.tag_dangerous_services(topology)

    # Output
    _print_topology_summary(topology)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(topology.to_json())
        console.print(f"\n[green]Topology saved to {args.output}[/green]")

    if args.png:
        from network_mapper.visualization import NetworkVisualizer
        viz = NetworkVisualizer(topology)
        viz.save_static(args.png)
        console.print(f"[green]Static graph saved to {args.png}[/green]")

    if args.html:
        from network_mapper.visualization import NetworkVisualizer
        viz = NetworkVisualizer(topology)
        viz.save_interactive(args.html)
        console.print(f"[green]Interactive graph saved to {args.html}[/green]")

    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    from network_mapper.path_analysis import PathAnalyzer
    from network_mapper.models import NetworkTopology

    with open(args.topology) as fh:
        topology = NetworkTopology.from_json(fh.read())

    analyzer = PathAnalyzer(topology)

    if args.source and args.target:
        path = (
            analyzer.shortest_weighted_path(args.source, args.target)
            if args.weighted
            else analyzer.shortest_path(args.source, args.target)
        )
        if path:
            console.print(f"\n[bold green]Path: {args.source} → {args.target}[/bold green]")
            console.print(f"  Hops : {path.hop_count}")
            console.print(f"  Cost : {path.total_cost:.2f}")
            console.print(f"  Route: {' → '.join(path.nodes)}")
        else:
            console.print(f"[red]No path found from {args.source} to {args.target}[/red]")
        return 0

    if args.choke_points:
        points = analyzer.identify_choke_points(top_n=args.top)
        table = Table(title="Choke Points (by betweenness centrality)", box=box.SIMPLE)
        table.add_column("Host", style="cyan")
        table.add_column("Centrality Score", justify="right")
        for ip, score in points:
            table.add_row(ip, f"{score:.4f}")
        console.print(table)
        return 0

    if args.critical:
        nodes = analyzer.identify_critical_nodes()
        console.print(f"\n[bold]Critical nodes (articulation points):[/bold]")
        for n in nodes:
            console.print(f"  [red]{n}[/red]")
        return 0

    # Default: print connectivity summary
    components = analyzer.connected_components()
    console.print(f"\n[bold]Connected components:[/bold] {len(components)}")
    for i, comp in enumerate(components, 1):
        console.print(f"  Component {i}: {', '.join(comp)}")
    return 0


def cmd_visualize(args: argparse.Namespace) -> int:
    from network_mapper.visualization import NetworkVisualizer
    from network_mapper.models import NetworkTopology

    with open(args.topology) as fh:
        topology = NetworkTopology.from_json(fh.read())

    viz = NetworkVisualizer(topology)

    if args.format in ("png", "both"):
        out = args.output if args.output and not args.output.endswith(".html") else "network_map.png"
        viz.save_static(out, title=args.title)
        console.print(f"[green]Static PNG saved to {out}[/green]")

    if args.format in ("html", "both"):
        out = args.output if args.output and args.output.endswith(".html") else "network_map.html"
        viz.save_interactive(out, title=args.title)
        console.print(f"[green]Interactive HTML saved to {out}[/green]")

    return 0


def _print_topology_summary(topology) -> None:
    from network_mapper.enumeration import ServiceEnumerator

    summary = ServiceEnumerator.summarize(topology)

    console.print(f"\n[bold cyan]Network Topology Summary[/bold cyan]")
    console.print(f"  Total hosts  : {summary['total_hosts']}")
    console.print(f"  Live hosts   : {summary['live_hosts']}")
    console.print(f"  Open ports   : {summary['total_open_ports']}")
    console.print(f"  Network edges: {topology.edge_count()}")

    if summary["top_services"]:
        table = Table(title="Top Services", box=box.SIMPLE)
        table.add_column("Service", style="cyan")
        table.add_column("Count", justify="right")
        for name, count in summary["top_services"]:
            table.add_row(name, str(count))
        console.print(table)

    if topology.get_live_hosts():
        table = Table(title="Discovered Hosts", box=box.SIMPLE)
        table.add_column("IP", style="cyan")
        table.add_column("Hostname")
        table.add_column("OS")
        table.add_column("Open Ports")
        table.add_column("Tags")
        for host in sorted(topology.get_live_hosts(), key=lambda h: h.ip):
            ports = ", ".join(str(s.port) for s in host.get_open_services()[:8])
            if len(host.get_open_services()) > 8:
                ports += f" +{len(host.get_open_services()) - 8}"
            table.add_row(
                host.ip,
                host.hostname or "—",
                host.os_info[:30] or "—",
                ports or "—",
                ", ".join(host.tags) or "—",
            )
        console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network-mapper",
        description="NetworkMapper — network topology discovery and mapping",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    # discover
    p_disc = sub.add_parser("discover", help="Discover hosts and services on a network")
    p_disc.add_argument("targets", nargs="+", help="IP, CIDR range, or hostname (e.g. 192.168.1.0/24)")
    p_disc.add_argument("-s", "--services", action="store_true", help="Also enumerate services (nmap -sV)")
    p_disc.add_argument("-p", "--ports", default="", help="Port spec (e.g. 22,80,443 or 1-1024)")
    p_disc.add_argument("--tag", action="store_true", help="Tag dangerous services")
    p_disc.add_argument("-t", "--timeout", type=float, default=2.0, help="Connection timeout (seconds)")
    p_disc.add_argument("--threads", type=int, default=50, help="Worker threads")
    p_disc.add_argument("-o", "--output", help="Save topology JSON to file")
    p_disc.add_argument("--png", help="Save static PNG graph")
    p_disc.add_argument("--html", help="Save interactive HTML graph")
    p_disc.set_defaults(func=cmd_discover)

    # paths
    p_paths = sub.add_parser("paths", help="Analyse paths within a saved topology")
    p_paths.add_argument("topology", help="Topology JSON file (from 'discover -o')")
    p_paths.add_argument("--source", help="Source IP for path query")
    p_paths.add_argument("--target", help="Target IP for path query")
    p_paths.add_argument("--weighted", action="store_true", help="Use weighted (cost) path")
    p_paths.add_argument("--choke-points", action="store_true", help="Identify network choke points")
    p_paths.add_argument("--critical", action="store_true", help="Identify critical (articulation) nodes")
    p_paths.add_argument("--top", type=int, default=10, help="Number of results to show")
    p_paths.set_defaults(func=cmd_paths)

    # visualize
    p_viz = sub.add_parser("visualize", help="Generate network graphs from a saved topology")
    p_viz.add_argument("topology", help="Topology JSON file")
    p_viz.add_argument("-f", "--format", choices=["png", "html", "both"], default="both")
    p_viz.add_argument("-o", "--output", help="Output file path")
    p_viz.add_argument("--title", default="Network Topology")
    p_viz.set_defaults(func=cmd_visualize)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    try:
        rc = args.func(args)
        sys.exit(rc or 0)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"[red]Error: {exc}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
