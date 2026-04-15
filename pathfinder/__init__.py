"""
PathFinder — Red team attack path analysis tool built on NetworkMapper.
"""

from pathfinder.attack_paths import AttackPathFinder
from pathfinder.shodan_client import ShodanClient
from pathfinder.vuln_scanner import VulnScanner
from pathfinder.lateral_movement import LateralMovementAnalyzer
from pathfinder.exfil_routes import ExfilRouteAnalyzer
from pathfinder.stealth import StealthScanner
from pathfinder.visualization import AttackVisualizer

__version__ = "1.0.0"
__all__ = [
    "AttackPathFinder",
    "ShodanClient",
    "VulnScanner",
    "LateralMovementAnalyzer",
    "ExfilRouteAnalyzer",
    "StealthScanner",
    "AttackVisualizer",
]
