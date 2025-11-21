"""
Supply chain security and firmware guardian module.

Detects supply chain compromises including:
- Suspicious firmware releases (TotoLink-style attacks)
- Abnormal signing keys
- Rapid mass deployments
- Post-release anomalous behavior
"""

from ddos_sentinel.supply_chain.agent import (
    SupplyChainGuardianAgent,
    SupplyChainObservation
)

__all__ = ['SupplyChainGuardianAgent', 'SupplyChainObservation']
