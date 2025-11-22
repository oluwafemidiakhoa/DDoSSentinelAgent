"""
DDoS Sentinel Agent - A secure autonomous security agent built with SafeDeepAgent.

This module provides multi-agent security mesh capabilities for comprehensive
threat detection across network, DNS, and supply chain domains, wrapped in the
SafeDeepAgent framework for secure, supervised, and auditable AI behavior.
"""

__version__ = "0.2.0"
__author__ = "Oluwafemi Idiakhoa"

# Core multi-agent mesh
from ddos_sentinel.mesh.orchestrator import SecurityMeshOrchestrator

# Domain-specific agents
from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.dns.agent import DNSIntegrityAgent, DNSObservation
from ddos_sentinel.supply_chain.agent import SupplyChainGuardianAgent, SupplyChainObservation

# Core types
from ddos_sentinel.core.types import (
    Severity,
    Indicator,
    AnalysisResult,
    MitigationAction,
    MitigationPlan
)

# Detection and simulation
from ddos_sentinel.detection.engine import DDoSDetectionEngine
from ddos_sentinel.data.simulator import TrafficSimulator

__all__ = [
    # Mesh orchestration
    "SecurityMeshOrchestrator",

    # Domain agents
    "DDoSSentinelAgent",
    "DNSIntegrityAgent",
    "SupplyChainGuardianAgent",

    # Observations
    "DNSObservation",
    "SupplyChainObservation",

    # Core types
    "Severity",
    "Indicator",
    "AnalysisResult",
    "MitigationAction",
    "MitigationPlan",

    # Detection & simulation
    "DDoSDetectionEngine",
    "TrafficSimulator",
]
