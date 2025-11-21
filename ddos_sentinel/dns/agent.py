"""
DNS Integrity Agent - Detect DNS-based abuse and manipulation.

This agent detects DNS popularity manipulation and resolver abuse,
such as Aisuru-style attacks that spam resolvers like Cloudflare 1.1.1.1
to artificially inflate domain popularity rankings.
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import structlog

from safedeepagent.core.safe_agent import SafeDeepAgent, SafeConfig
from ddos_sentinel.core.types import (
    Severity,
    Indicator,
    AnalysisResult,
    MitigationAction,
    MitigationPlan
)

logger = structlog.get_logger(__name__)


@dataclass
class DNSObservation:
    """
    Observation data for DNS traffic analysis.

    Represents DNS query patterns and metrics for a specific domain
    or set of domains over a time window.
    """
    domain: str  # Domain being queried
    qps: float  # Queries per second
    unique_client_ips: int  # Number of unique client IPs making queries
    asn_distribution: Dict[str, int]  # ASN -> count mapping
    query_types: Dict[str, int]  # Query type (A, AAAA, etc.) -> count
    http_traffic_ratio: float = 0.0  # Ratio of HTTP traffic to DNS queries (0-1)
    timestamp: float = 0.0  # Observation timestamp
    additional_metrics: Dict[str, Any] = field(default_factory=dict)


class DNSIntegrityAgent:
    """
    DNS Integrity Agent for detecting DNS-based attacks and manipulation.

    Detects:
    - DNS popularity manipulation (spam queries to inflate rankings)
    - DNS resolver abuse (targeting specific resolvers)
    - Anomalous query patterns
    - Bot-driven DNS queries with no corresponding application traffic

    Implements BaseSecurityAgent interface for multi-agent mesh integration.
    """

    # BaseSecurityAgent interface attributes
    name: str = "DNS Integrity Agent"
    domain: str = "dns"

    def __init__(
        self,
        safe_config: Optional[SafeConfig] = None,
        sensitivity: float = 0.8,
        baseline_qps: float = 100.0
    ):
        """
        Initialize the DNS Integrity Agent.

        Args:
            safe_config: SafeDeepAgent security configuration
            sensitivity: Detection sensitivity (0.0 to 1.0)
            baseline_qps: Expected baseline QPS for normal operations
        """
        if safe_config is None:
            safe_config = self._create_default_safe_config()

        self.safe_agent = SafeDeepAgent(safe_config=safe_config)
        self.sensitivity = sensitivity
        self.baseline_qps = baseline_qps

        # Detection thresholds (Aisuru-style DNS abuse)
        self.thresholds = {
            "qps_warning": 1000,  # Queries/sec warning threshold
            "qps_critical": 5000,  # Queries/sec critical threshold
            "unique_ips_suspicious": 500,  # Suspicious number of unique client IPs
            "unique_ips_critical": 2000,  # Critical botnet indicator
            "asn_concentration": 0.7,  # 70%+ from single ASN is suspicious
            "http_ratio_low": 0.1,  # Low HTTP traffic compared to DNS (10%)
        }

        logger.info(
            "DNS Integrity Agent initialized",
            sensitivity=sensitivity,
            baseline_qps=baseline_qps
        )

    def _create_default_safe_config(self) -> SafeConfig:
        """Create default SafeConfig with all 12 foundations enabled."""
        return SafeConfig(
            enable_action_validation=True,
            enable_memory_firewalls=True,
            enable_provenance_tracking=True,
            enable_sandboxing=True,
            enable_behavioral_monitoring=True,
            enable_meta_supervision=True,
            enable_audit_logging=True,
            enable_purpose_binding=True,
            enable_intent_tracking=True,
            enable_deception_detection=True,
            enable_risk_adaptation=True,
            enable_human_governance=True
        )

    def analyze(self, observation: DNSObservation) -> AnalysisResult:
        """
        Analyze DNS observation for abuse and manipulation.

        Args:
            observation: DNSObservation with query metrics

        Returns:
            AnalysisResult with detection findings
        """
        logger.info(
            "Executing DNS analyze action",
            domain=observation.domain,
            qps=observation.qps
        )

        # Execute through SafeDeepAgent framework
        result = self.safe_agent.execute_safe_action({
            'tool': 'dns_analyze',
            'parameters': {
                'domain': observation.domain,
                'qps': observation.qps,
                'timestamp': observation.timestamp
            }
        })

        if not result.allowed:
            logger.error(
                "DNS analysis blocked by security layer",
                blocked_by=result.blocked_by
            )
            return AnalysisResult(
                domain=self.domain,
                attack_detected=False,
                severity=Severity.NONE,
                confidence=0.0,
                notes=f"Analysis blocked: {result.reason}"
            )

        # Perform detection checks
        indicators = []
        threat_scores = []
        notes_parts = []

        # Check 1: Excessive QPS (popularity manipulation)
        qps_severity, qps_confidence, qps_note = self._check_excessive_qps(observation)
        if qps_severity != Severity.NONE:
            indicators.append(Indicator(
                type="dns_abuse",
                value=f"excessive_qps_{observation.domain}",
                details={"qps": observation.qps, "severity": qps_severity.value}
            ))
            threat_scores.append(qps_confidence)
            notes_parts.append(qps_note)

        # Check 2: Botnet pattern (many unique IPs)
        botnet_severity, botnet_confidence, botnet_note = self._check_botnet_pattern(
            observation
        )
        if botnet_severity != Severity.NONE:
            indicators.append(Indicator(
                type="dns_botnet",
                value=f"botnet_queries_{observation.domain}",
                details={
                    "unique_ips": observation.unique_client_ips,
                    "severity": botnet_severity.value
                }
            ))
            threat_scores.append(botnet_confidence)
            notes_parts.append(botnet_note)

        # Check 3: ASN concentration (coordinated attack)
        asn_severity, asn_confidence, asn_note = self._check_asn_concentration(
            observation
        )
        if asn_severity != Severity.NONE:
            indicators.append(Indicator(
                type="dns_asn_abuse",
                value=f"asn_concentration_{observation.domain}",
                details={
                    "asn_distribution": observation.asn_distribution,
                    "severity": asn_severity.value
                }
            ))
            threat_scores.append(asn_confidence)
            notes_parts.append(asn_note)

        # Check 4: Low HTTP traffic ratio (fake queries)
        http_severity, http_confidence, http_note = self._check_http_traffic_ratio(
            observation
        )
        if http_severity != Severity.NONE:
            indicators.append(Indicator(
                type="dns_fake_traffic",
                value=f"low_http_ratio_{observation.domain}",
                details={
                    "http_ratio": observation.http_traffic_ratio,
                    "severity": http_severity.value
                }
            ))
            threat_scores.append(http_confidence)
            notes_parts.append(http_note)

        # Determine overall severity and confidence
        attack_detected = len(indicators) > 0
        if attack_detected:
            overall_severity = max(
                [qps_severity, botnet_severity, asn_severity, http_severity]
            )
            avg_confidence = sum(threat_scores) / len(threat_scores)
        else:
            overall_severity = Severity.NONE
            avg_confidence = 0.0

        notes = "\n".join(notes_parts) if notes_parts else "No DNS abuse detected"

        logger.info(
            "DNS analysis completed",
            attack_detected=attack_detected,
            severity=overall_severity.value,
            confidence=avg_confidence
        )

        return AnalysisResult(
            domain=self.domain,
            attack_detected=attack_detected,
            severity=overall_severity,
            confidence=avg_confidence,
            indicators=indicators,
            notes=notes,
            metrics={
                "qps": observation.qps,
                "unique_client_ips": observation.unique_client_ips,
                "http_traffic_ratio": observation.http_traffic_ratio
            }
        )

    def propose_mitigation(self, analysis: AnalysisResult) -> MitigationPlan:
        """
        Propose mitigation plan for DNS abuse.

        Args:
            analysis: The AnalysisResult from analyze()

        Returns:
            MitigationPlan with immediate and follow-up actions
        """
        logger.info(
            "Executing DNS propose_mitigation action",
            severity=analysis.severity.value
        )

        result = self.safe_agent.execute_safe_action({
            'tool': 'dns_mitigate',
            'parameters': {
                'severity': analysis.severity.value
            }
        })

        if not result.allowed:
            return MitigationPlan(
                domain=self.domain,
                severity=analysis.severity,
                estimated_impact="Mitigation blocked by security layer",
                recommended_response_time="N/A"
            )

        if not analysis.attack_detected:
            return MitigationPlan(
                domain=self.domain,
                severity=Severity.NONE,
                estimated_impact="No impact",
                recommended_response_time="N/A"
            )

        # Generate mitigation actions based on severity and indicators
        immediate_actions = []
        follow_up_actions = []

        if analysis.severity in [Severity.CRITICAL, Severity.HIGH]:
            immediate_actions = [
                MitigationAction(
                    description="Rate limit DNS queries for affected domains",
                    target="dns_resolver",
                    action_type="rate_limit",
                    parameters={"max_qps": 1000, "per_client": True},
                    priority=10
                ),
                MitigationAction(
                    description="Flag domain in popularity rankings as suspicious",
                    target="ranking_system",
                    action_type="flag",
                    parameters={"reason": "suspected_manipulation"},
                    priority=9
                )
            ]

        # Add indicator-specific actions
        for indicator in analysis.indicators:
            if indicator.type == "dns_botnet":
                follow_up_actions.append(MitigationAction(
                    description="Implement client IP reputation filtering",
                    target="dns_resolver",
                    action_type="filter",
                    parameters={"filter_type": "ip_reputation"},
                    priority=7
                ))
            elif indicator.type == "dns_asn_abuse":
                follow_up_actions.append(MitigationAction(
                    description="Block or rate-limit queries from suspicious ASNs",
                    target="dns_resolver",
                    action_type="rate_limit",
                    parameters={"scope": "asn"},
                    priority=7
                ))
            elif indicator.type == "dns_fake_traffic":
                follow_up_actions.append(MitigationAction(
                    description="Lower DNS rank for domain with suspicious query patterns",
                    target="ranking_system",
                    action_type="lower_dns_rank",
                    parameters={"penalty_factor": 0.5},
                    priority=6
                ))

        # General follow-up actions
        follow_up_actions.extend([
            MitigationAction(
                description="Monitor domain for continued abuse patterns",
                target="monitoring_system",
                action_type="monitor",
                parameters={"duration_hours": 24},
                priority=5
            ),
            MitigationAction(
                description="Notify domain owner of suspected manipulation",
                target="domain_owner",
                action_type="notify",
                priority=3
            ),
            MitigationAction(
                description="Update DNS abuse detection signatures",
                target="detection_system",
                action_type="update_signatures",
                priority=2
            )
        ])

        # Deduplicate
        seen = set()
        deduplicated_follow_up = []
        for action in follow_up_actions:
            key = (action.description, action.target)
            if key not in seen:
                seen.add(key)
                deduplicated_follow_up.append(action)

        # Estimate impact
        impact_map = {
            Severity.CRITICAL: "Domain ranking severely compromised, resolver abuse ongoing",
            Severity.HIGH: "Significant DNS abuse, ranking manipulation likely",
            Severity.MEDIUM: "Moderate DNS query anomalies detected",
            Severity.LOW: "Minor DNS irregularities",
            Severity.NONE: "No impact"
        }

        response_time_map = {
            Severity.CRITICAL: "Immediate (< 5 minutes)",
            Severity.HIGH: "Urgent (< 15 minutes)",
            Severity.MEDIUM: "Priority (< 1 hour)",
            Severity.LOW: "Standard (< 4 hours)",
            Severity.NONE: "N/A"
        }

        mitigation_plan = MitigationPlan(
            domain=self.domain,
            severity=analysis.severity,
            immediate_actions=immediate_actions,
            follow_up_actions=deduplicated_follow_up,
            estimated_impact=impact_map[analysis.severity],
            recommended_response_time=response_time_map[analysis.severity]
        )

        logger.info(
            "DNS mitigation plan generated",
            action_count=mitigation_plan.action_count()
        )

        return mitigation_plan

    def _check_excessive_qps(
        self,
        observation: DNSObservation
    ) -> tuple[Severity, float, str]:
        """Check for excessive queries per second."""
        qps = observation.qps

        if qps >= self.thresholds["qps_critical"]:
            return (
                Severity.CRITICAL,
                0.95,
                f"CRITICAL: Excessive QPS detected ({qps:.0f} qps) - "
                f"possible rank manipulation"
            )
        elif qps >= self.thresholds["qps_warning"]:
            deviation = qps / self.baseline_qps
            return (
                Severity.HIGH,
                0.80,
                f"HIGH: Elevated QPS ({qps:.0f} qps, {deviation:.1f}x baseline) - "
                f"suspicious activity"
            )
        elif qps > self.baseline_qps * 3:
            return (
                Severity.MEDIUM,
                0.65,
                f"MEDIUM: QPS above baseline ({qps:.0f} qps vs {self.baseline_qps:.0f})"
            )

        return (Severity.NONE, 0.0, "")

    def _check_botnet_pattern(
        self,
        observation: DNSObservation
    ) -> tuple[Severity, float, str]:
        """Check for botnet-driven DNS queries."""
        unique_ips = observation.unique_client_ips

        if unique_ips >= self.thresholds["unique_ips_critical"]:
            return (
                Severity.CRITICAL,
                0.90,
                f"CRITICAL: Botnet pattern detected ({unique_ips:,} unique client IPs)"
            )
        elif unique_ips >= self.thresholds["unique_ips_suspicious"]:
            return (
                Severity.HIGH,
                0.75,
                f"HIGH: Suspicious distributed query pattern ({unique_ips:,} unique IPs)"
            )

        return (Severity.NONE, 0.0, "")

    def _check_asn_concentration(
        self,
        observation: DNSObservation
    ) -> tuple[Severity, float, str]:
        """Check for ASN concentration (coordinated attack)."""
        if not observation.asn_distribution:
            return (Severity.NONE, 0.0, "")

        total_queries = sum(observation.asn_distribution.values())
        if total_queries == 0:
            return (Severity.NONE, 0.0, "")

        # Find max ASN concentration
        max_asn_count = max(observation.asn_distribution.values())
        max_concentration = max_asn_count / total_queries

        if max_concentration >= self.thresholds["asn_concentration"]:
            top_asn = max(
                observation.asn_distribution.items(),
                key=lambda x: x[1]
            )[0]
            return (
                Severity.HIGH,
                0.85,
                f"HIGH: ASN concentration detected ({max_concentration:.1%} "
                f"from ASN {top_asn})"
            )

        return (Severity.NONE, 0.0, "")

    def _check_http_traffic_ratio(
        self,
        observation: DNSObservation
    ) -> tuple[Severity, float, str]:
        """Check for low HTTP traffic ratio (fake DNS queries)."""
        ratio = observation.http_traffic_ratio

        # Low HTTP traffic compared to DNS queries suggests fake/bot queries
        if ratio < self.thresholds["http_ratio_low"] and observation.qps > 100:
            return (
                Severity.MEDIUM,
                0.70,
                f"MEDIUM: Low HTTP/DNS ratio ({ratio:.1%}) - possible fake queries"
            )

        return (Severity.NONE, 0.0, "")
