"""
Supply Chain Guardian Agent - Detect firmware and release compromises.

This agent monitors firmware/software releases and detects anomalies
that could indicate supply chain attacks, similar to the TotoLink
router compromise that was used in the Aisuru DDoS campaign.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime
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
class SupplyChainObservation:
    """
    Observation data for supply chain / firmware release analysis.

    Represents metrics about a software/firmware release event.
    """
    release_id: str  # Unique release identifier
    version: str  # Version string
    signing_key_id: str  # Cryptographic signing key identifier
    build_host: str  # Build server/host identifier
    rollout_speed: float  # Devices updated per hour
    total_devices_updated: int  # Total devices updated so far
    deployment_duration_hours: float  # How long has this been rolling out
    post_release_traffic_multiplier: float = 1.0  # Traffic increase after update
    is_known_signing_key: bool = True  # Whether signing key is recognized
    build_host_reputation: str = "trusted"  # "trusted", "unknown", "suspicious"
    device_behavior_anomalies: int = 0  # Count of devices showing anomalous behavior
    timestamp: float = 0.0
    additional_metrics: Dict[str, Any] = field(default_factory=dict)


class SupplyChainGuardianAgent:
    """
    Supply Chain Guardian Agent for detecting firmware and release compromises.

    Detects:
    - Suspicious firmware releases (unknown signing keys)
    - Rapid mass deployments (worm-like behavior)
    - Abnormal build sources
    - Post-release anomalous device behavior
    - TotoLink-style router compromises

    Implements BaseSecurityAgent interface for multi-agent mesh integration.
    """

    # BaseSecurityAgent interface attributes
    name: str = "Supply Chain Guardian Agent"
    domain: str = "supply_chain"

    def __init__(
        self,
        safe_config: Optional[SafeConfig] = None,
        sensitivity: float = 0.8,
        normal_rollout_speed: float = 1000.0  # devices/hour
    ):
        """
        Initialize the Supply Chain Guardian Agent.

        Args:
            safe_config: SafeDeepAgent security configuration
            sensitivity: Detection sensitivity (0.0 to 1.0)
            normal_rollout_speed: Expected normal rollout speed (devices/hour)
        """
        if safe_config is None:
            safe_config = self._create_default_safe_config()

        self.safe_agent = SafeDeepAgent(safe_config=safe_config)
        self.sensitivity = sensitivity
        self.normal_rollout_speed = normal_rollout_speed

        # Detection thresholds
        self.thresholds = {
            "rollout_speed_warning": 5000,  # devices/hour
            "rollout_speed_critical": 20000,  # devices/hour (worm-like)
            "traffic_multiplier_suspicious": 5.0,  # 5x traffic increase
            "traffic_multiplier_critical": 10.0,  # 10x traffic increase
            "behavior_anomaly_threshold": 100,  # devices showing anomalies
            "rapid_deployment_hours": 2.0,  # Suspiciously fast deployment
        }

        logger.info(
            "Supply Chain Guardian Agent initialized",
            sensitivity=sensitivity,
            normal_rollout_speed=normal_rollout_speed
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

    def analyze(self, observation: SupplyChainObservation) -> AnalysisResult:
        """
        Analyze supply chain observation for compromises and anomalies.

        Args:
            observation: SupplyChainObservation with release metrics

        Returns:
            AnalysisResult with detection findings
        """
        logger.info(
            "Executing supply chain analyze action",
            release_id=observation.release_id,
            version=observation.version
        )

        # Execute through SafeDeepAgent framework
        result = self.safe_agent.execute_safe_action({
            'tool': 'supply_chain_analyze',
            'parameters': {
                'release_id': observation.release_id,
                'version': observation.version,
                'timestamp': observation.timestamp
            }
        })

        if not result.allowed:
            logger.error(
                "Supply chain analysis blocked by security layer",
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

        # Check 1: Unknown or suspicious signing key
        key_severity, key_confidence, key_note = self._check_signing_key(observation)
        if key_severity != Severity.NONE:
            indicators.append(Indicator(
                type="signing_key",
                value=observation.signing_key_id,
                details={
                    "is_known": observation.is_known_signing_key,
                    "severity": key_severity.value
                }
            ))
            threat_scores.append(key_confidence)
            notes_parts.append(key_note)

        # Check 2: Rapid/abnormal rollout speed
        rollout_severity, rollout_confidence, rollout_note = self._check_rollout_speed(
            observation
        )
        if rollout_severity != Severity.NONE:
            indicators.append(Indicator(
                type="rollout_anomaly",
                value=f"rapid_deployment_{observation.release_id}",
                details={
                    "rollout_speed": observation.rollout_speed,
                    "severity": rollout_severity.value
                }
            ))
            threat_scores.append(rollout_confidence)
            notes_parts.append(rollout_note)

        # Check 3: Suspicious build host
        build_severity, build_confidence, build_note = self._check_build_host(
            observation
        )
        if build_severity != Severity.NONE:
            indicators.append(Indicator(
                type="build_host",
                value=observation.build_host,
                details={
                    "reputation": observation.build_host_reputation,
                    "severity": build_severity.value
                }
            ))
            threat_scores.append(build_confidence)
            notes_parts.append(build_note)

        # Check 4: Post-release traffic anomalies
        traffic_severity, traffic_confidence, traffic_note = self._check_post_release_traffic(
            observation
        )
        if traffic_severity != Severity.NONE:
            indicators.append(Indicator(
                type="post_release_anomaly",
                value=f"traffic_spike_{observation.release_id}",
                details={
                    "traffic_multiplier": observation.post_release_traffic_multiplier,
                    "severity": traffic_severity.value
                }
            ))
            threat_scores.append(traffic_confidence)
            notes_parts.append(traffic_note)

        # Check 5: Device behavior anomalies
        behavior_severity, behavior_confidence, behavior_note = self._check_device_behavior(
            observation
        )
        if behavior_severity != Severity.NONE:
            indicators.append(Indicator(
                type="device_behavior",
                value=f"anomalous_devices_{observation.release_id}",
                details={
                    "anomaly_count": observation.device_behavior_anomalies,
                    "severity": behavior_severity.value
                }
            ))
            threat_scores.append(behavior_confidence)
            notes_parts.append(behavior_note)

        # Determine overall severity and confidence
        attack_detected = len(indicators) > 0
        if attack_detected:
            # Multiple indicators = higher severity
            individual_severities = [
                key_severity, rollout_severity, build_severity,
                traffic_severity, behavior_severity
            ]
            overall_severity = max(individual_severities)

            # Boost severity if multiple critical indicators
            critical_count = sum(1 for s in individual_severities if s == Severity.CRITICAL)
            high_count = sum(1 for s in individual_severities if s == Severity.HIGH)

            if critical_count >= 2 or (critical_count >= 1 and high_count >= 2):
                overall_severity = Severity.CRITICAL

            avg_confidence = sum(threat_scores) / len(threat_scores)
        else:
            overall_severity = Severity.NONE
            avg_confidence = 0.0

        notes = "\n".join(notes_parts) if notes_parts else "No supply chain threats detected"

        logger.info(
            "Supply chain analysis completed",
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
                "release_id": observation.release_id,
                "rollout_speed": observation.rollout_speed,
                "devices_updated": observation.total_devices_updated,
                "traffic_multiplier": observation.post_release_traffic_multiplier
            }
        )

    def propose_mitigation(self, analysis: AnalysisResult) -> MitigationPlan:
        """
        Propose mitigation plan for supply chain threats.

        Args:
            analysis: The AnalysisResult from analyze()

        Returns:
            MitigationPlan with immediate and follow-up actions
        """
        logger.info(
            "Executing supply chain propose_mitigation action",
            severity=analysis.severity.value
        )

        result = self.safe_agent.execute_safe_action({
            'tool': 'supply_chain_mitigate',
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

        # Generate mitigation actions
        immediate_actions = []
        follow_up_actions = []

        # Critical/High severity actions
        if analysis.severity in [Severity.CRITICAL, Severity.HIGH]:
            release_id = analysis.metrics.get("release_id", "unknown")
            immediate_actions = [
                MitigationAction(
                    description="Halt firmware rollout immediately",
                    target=release_id,
                    action_type="halt_rollout",
                    priority=10
                ),
                MitigationAction(
                    description="Quarantine devices with suspicious release",
                    target=release_id,
                    action_type="quarantine",
                    priority=9
                ),
                MitigationAction(
                    description="Notify security team and incident response",
                    target="security_team",
                    action_type="notify",
                    parameters={"urgency": "critical"},
                    priority=9
                )
            ]

        # Indicator-specific actions
        for indicator in analysis.indicators:
            if indicator.type == "signing_key":
                immediate_actions.append(MitigationAction(
                    description=f"Revoke signing key: {indicator.value}",
                    target=indicator.value,
                    action_type="revoke_key",
                    priority=10
                ))
                follow_up_actions.append(MitigationAction(
                    description="Audit all releases signed with this key",
                    target=indicator.value,
                    action_type="audit",
                    priority=7
                ))

            elif indicator.type == "rollout_anomaly":
                immediate_actions.append(MitigationAction(
                    description="Throttle rollout to safe speed",
                    target=indicator.value,
                    action_type="throttle",
                    parameters={"max_speed": self.normal_rollout_speed},
                    priority=8
                ))

            elif indicator.type == "build_host" and "suspicious" in str(indicator.details):
                follow_up_actions.append(MitigationAction(
                    description=f"Investigate build host: {indicator.value}",
                    target=indicator.value,
                    action_type="investigate",
                    priority=7
                ))
                follow_up_actions.append(MitigationAction(
                    description="Rebuild from trusted build environment",
                    target=analysis.metrics.get("release_id", "unknown"),
                    action_type="rebuild",
                    priority=6
                ))

            elif indicator.type == "post_release_anomaly":
                immediate_actions.append(MitigationAction(
                    description="Roll back to previous stable release",
                    target=analysis.metrics.get("release_id", "unknown"),
                    action_type="rollback",
                    priority=9
                ))

            elif indicator.type == "device_behavior":
                follow_up_actions.append(MitigationAction(
                    description="Isolate devices exhibiting anomalous behavior",
                    target="anomalous_devices",
                    action_type="isolate",
                    priority=7
                ))

        # General follow-up actions
        follow_up_actions.extend([
            MitigationAction(
                description="Conduct forensic analysis of compromised release",
                target=analysis.metrics.get("release_id", "unknown"),
                action_type="forensics",
                priority=6
            ),
            MitigationAction(
                description="Review and strengthen signing key management",
                target="key_management_system",
                action_type="review",
                priority=5
            ),
            MitigationAction(
                description="Implement additional build integrity checks",
                target="build_pipeline",
                action_type="enhance",
                priority=4
            ),
            MitigationAction(
                description="Update supply chain security policies",
                target="security_policies",
                action_type="update",
                priority=3
            )
        ])

        # Deduplicate
        seen = set()
        deduplicated_immediate = []
        for action in immediate_actions:
            key = (action.description, action.target)
            if key not in seen:
                seen.add(key)
                deduplicated_immediate.append(action)

        seen = set()
        deduplicated_follow_up = []
        for action in follow_up_actions:
            key = (action.description, action.target)
            if key not in seen:
                seen.add(key)
                deduplicated_follow_up.append(action)

        # Estimate impact
        impact_map = {
            Severity.CRITICAL: "Supply chain compromise, widespread device infection likely",
            Severity.HIGH: "Suspicious firmware release, potential compromise",
            Severity.MEDIUM: "Anomalous release patterns detected",
            Severity.LOW: "Minor supply chain irregularities",
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
            immediate_actions=deduplicated_immediate,
            follow_up_actions=deduplicated_follow_up,
            estimated_impact=impact_map[analysis.severity],
            recommended_response_time=response_time_map[analysis.severity]
        )

        logger.info(
            "Supply chain mitigation plan generated",
            action_count=mitigation_plan.action_count()
        )

        return mitigation_plan

    def _check_signing_key(
        self,
        observation: SupplyChainObservation
    ) -> tuple[Severity, float, str]:
        """Check for unknown or suspicious signing keys."""
        if not observation.is_known_signing_key:
            return (
                Severity.CRITICAL,
                0.95,
                f"CRITICAL: Unknown signing key detected ({observation.signing_key_id}) - "
                f"possible supply chain compromise"
            )
        return (Severity.NONE, 0.0, "")

    def _check_rollout_speed(
        self,
        observation: SupplyChainObservation
    ) -> tuple[Severity, float, str]:
        """Check for abnormally rapid rollout (worm-like behavior)."""
        speed = observation.rollout_speed

        # Very rapid rollout in short time = worm-like
        if (speed >= self.thresholds["rollout_speed_critical"] and
            observation.deployment_duration_hours < self.thresholds["rapid_deployment_hours"]):
            return (
                Severity.CRITICAL,
                0.90,
                f"CRITICAL: Worm-like rollout detected ({speed:.0f} devices/hour, "
                f"{observation.deployment_duration_hours:.1f} hours) - possible automated compromise"
            )
        elif speed >= self.thresholds["rollout_speed_warning"]:
            return (
                Severity.HIGH,
                0.80,
                f"HIGH: Abnormally rapid rollout ({speed:.0f} devices/hour)"
            )
        elif speed > self.normal_rollout_speed * 3:
            return (
                Severity.MEDIUM,
                0.65,
                f"MEDIUM: Elevated rollout speed ({speed:.0f} devices/hour)"
            )

        return (Severity.NONE, 0.0, "")

    def _check_build_host(
        self,
        observation: SupplyChainObservation
    ) -> tuple[Severity, float, str]:
        """Check for suspicious build hosts."""
        reputation = observation.build_host_reputation

        if reputation == "suspicious":
            return (
                Severity.HIGH,
                0.85,
                f"HIGH: Suspicious build host ({observation.build_host})"
            )
        elif reputation == "unknown":
            return (
                Severity.MEDIUM,
                0.70,
                f"MEDIUM: Unknown build host ({observation.build_host})"
            )

        return (Severity.NONE, 0.0, "")

    def _check_post_release_traffic(
        self,
        observation: SupplyChainObservation
    ) -> tuple[Severity, float, str]:
        """Check for abnormal traffic patterns after release."""
        multiplier = observation.post_release_traffic_multiplier

        if multiplier >= self.thresholds["traffic_multiplier_critical"]:
            return (
                Severity.CRITICAL,
                0.90,
                f"CRITICAL: Massive traffic increase post-release "
                f"({multiplier:.1f}x) - possible DDoS payload"
            )
        elif multiplier >= self.thresholds["traffic_multiplier_suspicious"]:
            return (
                Severity.HIGH,
                0.80,
                f"HIGH: Significant traffic increase post-release ({multiplier:.1f}x)"
            )

        return (Severity.NONE, 0.0, "")

    def _check_device_behavior(
        self,
        observation: SupplyChainObservation
    ) -> tuple[Severity, float, str]:
        """Check for devices exhibiting anomalous behavior post-update."""
        anomaly_count = observation.device_behavior_anomalies

        if anomaly_count >= self.thresholds["behavior_anomaly_threshold"]:
            percentage = (anomaly_count / max(observation.total_devices_updated, 1)) * 100
            return (
                Severity.HIGH,
                0.85,
                f"HIGH: {anomaly_count} devices showing anomalous behavior "
                f"({percentage:.1f}% of updated devices)"
            )

        return (Severity.NONE, 0.0, "")
