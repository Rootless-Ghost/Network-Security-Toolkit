"""
PathGuard — Blue team defensive network analysis built on NetworkMapper.
"""

from pathguard.choke_points import ChokePointAnalyzer
from pathguard.hardening import HardeningAdvisor
from pathguard.baseline import BaselineManager
from pathguard.vuln_priority import VulnPrioritizer
from pathguard.controls import SecurityControlAdvisor
from pathguard.remediation import RemediationPlanner

__version__ = "1.0.0"
__all__ = [
    "ChokePointAnalyzer",
    "HardeningAdvisor",
    "BaselineManager",
    "VulnPrioritizer",
    "SecurityControlAdvisor",
    "RemediationPlanner",
]
