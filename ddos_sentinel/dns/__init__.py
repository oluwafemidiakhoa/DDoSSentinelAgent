"""
DNS integrity and abuse detection module.

Detects DNS-based attacks including:
- DNS popularity manipulation (Aisuru-style rank abuse)
- DNS resolver abuse
- Suspicious query patterns
"""

from ddos_sentinel.dns.agent import DNSIntegrityAgent, DNSObservation

__all__ = ['DNSIntegrityAgent', 'DNSObservation']
