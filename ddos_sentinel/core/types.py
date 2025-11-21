"""
Core types shared across all security agents in the mesh.

These types provide a common interface for threat detection, analysis,
and mitigation across different security domains (network, DNS, supply chain, etc.).
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List
from datetime import datetime


class Severity(Enum):
    """Threat severity levels used across all agents."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        """Enable severity comparison."""
        order = [Severity.NONE, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        """Enable severity comparison."""
        return self == other or self < other

    def __gt__(self, other):
        """Enable severity comparison."""
        return not self <= other

    def __ge__(self, other):
        """Enable severity comparison."""
        return self == other or self > other


@dataclass
class Indicator:
    """
    A security indicator of compromise (IoC) or suspicious activity.

    Indicators can represent various types of evidence:
    - IP addresses
    - Domain names
    - ASN numbers
    - Firmware versions
    - File hashes
    - etc.
    """
    type: str  # e.g., "ip", "domain", "asn", "firmware_version", "signing_key"
    value: str  # The actual indicator value
    details: Dict[str, Any] = field(default_factory=dict)  # Additional context

    def __str__(self):
        """String representation for logging."""
        return f"{self.type}:{self.value}"


@dataclass
class AnalysisResult:
    """
    Result of a security analysis by a domain-specific agent.

    This is the primary output format for all security agents,
    providing a standardized way to communicate threats.
    """
    domain: str  # e.g., "network", "dns", "supply_chain"
    attack_detected: bool
    severity: Severity
    confidence: float  # 0.0 to 1.0
    indicators: List[Indicator] = field(default_factory=list)
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: Dict[str, Any] = field(default_factory=dict)  # Domain-specific metrics

    def __post_init__(self):
        """Validate the analysis result."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")


@dataclass
class MitigationAction:
    """
    A specific mitigation action that can be taken to address a threat.

    Actions are domain-specific but follow a common structure for
    orchestration and audit logging.
    """
    description: str  # Human-readable description
    target: str  # What this action targets (IP, domain, service, etc.)
    action_type: str  # e.g., "rate_limit", "block", "notify", "rollback", "flag"
    parameters: Dict[str, Any] = field(default_factory=dict)  # Action-specific parameters
    priority: int = 0  # Higher = more urgent (0-10 scale)

    def __str__(self):
        """String representation for display."""
        return f"[{self.action_type}] {self.description} (target: {self.target})"


@dataclass
class MitigationPlan:
    """
    A comprehensive mitigation plan for addressing detected threats.

    Plans can be domain-specific or global (for the entire mesh).
    """
    domain: str  # Which domain this plan addresses (or "mesh" for global)
    severity: Severity  # Overall severity of the threat
    immediate_actions: List[MitigationAction] = field(default_factory=list)
    follow_up_actions: List[MitigationAction] = field(default_factory=list)
    estimated_impact: str = ""  # Human-readable impact description
    recommended_response_time: str = ""  # e.g., "< 5 minutes"
    timestamp: datetime = field(default_factory=datetime.now)

    def all_actions(self) -> List[MitigationAction]:
        """Get all actions (immediate + follow-up) in priority order."""
        all_actions = self.immediate_actions + self.follow_up_actions
        return sorted(all_actions, key=lambda a: a.priority, reverse=True)

    def action_count(self) -> int:
        """Total number of actions in this plan."""
        return len(self.immediate_actions) + len(self.follow_up_actions)
