"""
Base security agent interface for the multi-agent security mesh.

All security agents (network, DNS, supply chain, etc.) implement this interface
to provide consistent analysis and mitigation capabilities.
"""

from typing import Protocol, Any
from ddos_sentinel.core.types import AnalysisResult, MitigationPlan


class BaseSecurityAgent(Protocol):
    """
    Protocol defining the interface for all security agents in the mesh.

    All domain-specific agents (DDoSSentinelAgent, DNSIntegrityAgent,
    SupplyChainGuardianAgent, etc.) should implement this interface.

    This enables the SecurityMeshOrchestrator to work with any agent type
    in a consistent, type-safe manner.
    """

    name: str  # Human-readable agent name (e.g., "DDoS Sentinel Agent")
    domain: str  # Security domain (e.g., "network", "dns", "supply_chain")

    def analyze(self, observation: Any) -> AnalysisResult:
        """
        Analyze an observation and detect threats in this domain.

        Args:
            observation: Domain-specific observation data
                - For network domain: List[TrafficPacket] or traffic metrics
                - For DNS domain: DNSObservation with query stats
                - For supply chain: SupplyChainObservation with release info
                - etc.

        Returns:
            AnalysisResult with detection findings, severity, and indicators

        Note:
            This method should be routed through SafeDeepAgent.execute_safe_action()
            to ensure security validation, audit logging, and supervision.
        """
        ...

    def propose_mitigation(self, analysis: AnalysisResult) -> MitigationPlan:
        """
        Propose mitigation actions based on an analysis result.

        Args:
            analysis: The AnalysisResult from analyze()

        Returns:
            MitigationPlan with immediate and follow-up actions

        Note:
            This method should also be routed through SafeDeepAgent for
            security validation and audit logging.
        """
        ...


def validate_agent(agent: Any) -> bool:
    """
    Validate that an object implements the BaseSecurityAgent interface.

    Args:
        agent: Object to validate

    Returns:
        True if the agent implements the required interface

    Raises:
        TypeError: If the agent is missing required attributes or methods
    """
    required_attrs = ['name', 'domain']
    required_methods = ['analyze', 'propose_mitigation']

    for attr in required_attrs:
        if not hasattr(agent, attr):
            raise TypeError(f"Agent missing required attribute: {attr}")

    for method in required_methods:
        if not hasattr(agent, method) or not callable(getattr(agent, method)):
            raise TypeError(f"Agent missing required method: {method}")

    return True
