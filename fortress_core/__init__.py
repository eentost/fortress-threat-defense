"""Fortress Core Threat Detection Engine

Core module for threat detection and analysis based on OpenClaw kill chain methodology.
"""

__version__ = "1.0.0"
__author__ = "Fortress Security Team"

from fortress_core.threat_detector import ThreatDetector
from fortress_core.threat_rules import ThreatRules

__all__ = [
    'ThreatDetector',
    'ThreatRules',
]
