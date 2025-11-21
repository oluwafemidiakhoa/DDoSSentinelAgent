"""
DDoS Sentinel Agent - A secure autonomous security agent built with SafeDeepAgent.

This module provides DDoS detection capabilities using Aisuru-like traffic pattern
analysis, wrapped in the SafeDeepAgent framework for secure, supervised, and
auditable AI behavior.
"""

__version__ = "0.1.0"
__author__ = "Oluwafemi Idiakhoa"

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.detection.engine import DDoSDetectionEngine
from ddos_sentinel.data.simulator import TrafficSimulator

__all__ = [
    "DDoSSentinelAgent",
    "DDoSDetectionEngine",
    "TrafficSimulator",
]
