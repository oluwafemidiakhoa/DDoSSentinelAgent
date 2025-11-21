"""
Multi-agent security mesh orchestration.

Coordinates multiple domain-specific security agents to provide
comprehensive threat detection and mitigation across:
- Network (DDoS)
- DNS (popularity manipulation)
- Supply chain (firmware compromise)
"""

from ddos_sentinel.mesh.orchestrator import SecurityMeshOrchestrator

__all__ = ['SecurityMeshOrchestrator']
