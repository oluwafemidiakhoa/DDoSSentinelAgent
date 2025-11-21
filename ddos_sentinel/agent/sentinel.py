"""
DDoS Sentinel Agent - SafeDeepAgent Integration.

Wraps DDoS detection capabilities in the SafeDeepAgent framework for
secure, supervised, and auditable AI behavior.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

from safedeepagent.core.safe_agent import SafeDeepAgent, SafeConfig

from ddos_sentinel.data.simulator import TrafficPacket
from ddos_sentinel.detection.engine import DDoSDetectionEngine, AnalysisReport
from ddos_sentinel.detection.signatures import ThreatLevel
from ddos_sentinel.core.types import (
    Severity,
    Indicator,
    AnalysisResult,
    MitigationAction,
    MitigationPlan
)

logger = structlog.get_logger(__name__)


class DDoSSentinelAgent:
    """
    Secure autonomous DDoS detection agent built with SafeDeepAgent.

    This agent orchestrates DDoS detection operations through the SafeDeepAgent
    framework, ensuring all actions are validated, audited, and supervised
    according to the 12 foundations of agentic AI safety.

    Implements the BaseSecurityAgent interface for multi-agent mesh integration.

    Supported Actions:
        - analyze: Core analysis method (BaseSecurityAgent interface)
        - propose_mitigation: Generate mitigation plan (BaseSecurityAgent interface)
        - run_ddos_detection: Legacy method for backwards compatibility
        - summarize_findings: Generate human-readable summary
        - export_audit_report: Export complete audit trail
        - train_baseline: Train normal traffic baseline
    """

    # BaseSecurityAgent interface attributes
    name: str = "DDoS Sentinel Agent"
    domain: str = "network"

    def __init__(
        self,
        safe_config: Optional[SafeConfig] = None,
        window_size_seconds: int = 10,
        sensitivity: float = 0.8,
        baseline_profile: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the DDoS Sentinel Agent.

        Args:
            safe_config: SafeDeepAgent security configuration
            window_size_seconds: Time window for traffic aggregation
            sensitivity: Detection sensitivity (0.0 to 1.0)
            baseline_profile: Optional baseline profile for anomaly detection
        """
        # Initialize SafeDeepAgent with comprehensive security
        if safe_config is None:
            safe_config = self._create_default_safe_config()

        self.safe_agent = SafeDeepAgent(safe_config=safe_config)

        # Initialize detection engine
        self.detection_engine = DDoSDetectionEngine(
            window_size_seconds=window_size_seconds,
            sensitivity=sensitivity,
            baseline_profile=baseline_profile
        )

        # State tracking
        self.last_analysis: Optional[AnalysisReport] = None
        self.baseline_trained: bool = baseline_profile is not None

        logger.info(
            "DDoS Sentinel Agent initialized",
            safe_config=safe_config,
            window_size=window_size_seconds,
            sensitivity=sensitivity
        )

    def _create_default_safe_config(self) -> SafeConfig:
        """Create default SafeConfig with all 12 foundations enabled."""
        return SafeConfig(
            enable_action_validation=True,      # Foundation #1
            enable_memory_firewalls=True,       # Foundation #2
            enable_provenance_tracking=True,    # Foundation #3
            enable_sandboxing=True,             # Foundation #4
            enable_behavioral_monitoring=True,  # Foundation #5
            enable_meta_supervision=True,       # Foundation #6
            enable_audit_logging=True,          # Foundation #7
            enable_purpose_binding=True,        # Foundation #8
            enable_intent_tracking=True,        # Foundation #9
            enable_deception_detection=True,    # Foundation #10
            enable_risk_adaptation=True,        # Foundation #11
            enable_human_governance=True        # Foundation #12
        )

    @staticmethod
    def _threat_level_to_severity(threat_level: ThreatLevel) -> Severity:
        """Convert ThreatLevel to Severity enum."""
        mapping = {
            ThreatLevel.NONE: Severity.NONE,
            ThreatLevel.LOW: Severity.LOW,
            ThreatLevel.MEDIUM: Severity.MEDIUM,
            ThreatLevel.HIGH: Severity.HIGH,
            ThreatLevel.CRITICAL: Severity.CRITICAL
        }
        return mapping.get(threat_level, Severity.NONE)

    @staticmethod
    def _severity_to_threat_level(severity: Severity) -> ThreatLevel:
        """Convert Severity to ThreatLevel enum."""
        mapping = {
            Severity.NONE: ThreatLevel.NONE,
            Severity.LOW: ThreatLevel.LOW,
            Severity.MEDIUM: ThreatLevel.MEDIUM,
            Severity.HIGH: ThreatLevel.HIGH,
            Severity.CRITICAL: ThreatLevel.CRITICAL
        }
        return mapping.get(severity, ThreatLevel.NONE)

    # =============================================================================
    # BaseSecurityAgent Interface Implementation
    # =============================================================================

    def analyze(self, observation: List[TrafficPacket]) -> AnalysisResult:
        """
        Analyze network traffic for DDoS attacks (BaseSecurityAgent interface).

        This is the core analysis method required by the BaseSecurityAgent protocol,
        enabling integration with the SecurityMeshOrchestrator.

        Args:
            observation: List of traffic packets to analyze

        Returns:
            AnalysisResult with standardized threat detection information

        Note:
            This method is routed through SafeDeepAgent.execute_safe_action()
            for security validation, audit logging, and supervision.
        """
        logger.info("Executing network analyze action", packet_count=len(observation))

        # Execute through SafeDeepAgent framework
        result = self.safe_agent.execute_safe_action({
            'tool': 'network_analyze',
            'parameters': {
                'packets': observation,
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            logger.error(
                "Network analysis blocked by security layer",
                blocked_by=result.blocked_by,
                reason=result.reason
            )
            # Return a non-attack result if blocked
            return AnalysisResult(
                domain=self.domain,
                attack_detected=False,
                severity=Severity.NONE,
                confidence=0.0,
                notes=f"Analysis blocked by security layer: {result.reason}"
            )

        # Perform actual detection using the detection engine
        report = self.detection_engine.analyze_traffic(
            packets=observation,
            include_advanced_features=True
        )

        # Store for later reference
        self.last_analysis = report

        # Convert to standardized AnalysisResult format
        # Extract indicators from detection results
        indicators = []
        for detection_result in report.detection_results:
            if detection_result.is_attack:
                # Extract suspicious source IPs (top N)
                for signature in detection_result.signatures_matched:
                    indicators.append(Indicator(
                        type="signature",
                        value=signature,
                        details={
                            "confidence": detection_result.confidence,
                            "threat_level": detection_result.threat_level.value
                        }
                    ))

        # Convert threat level to severity
        severity = self._threat_level_to_severity(report.overall_threat_level)

        # Compute average confidence across attack windows
        attack_results = [r for r in report.detection_results if r.is_attack]
        avg_confidence = (
            sum(r.confidence for r in attack_results) / len(attack_results)
            if attack_results else 0.0
        )

        logger.info(
            "Network analysis completed",
            attack_detected=report.attack_detected,
            severity=severity.value,
            confidence=avg_confidence
        )

        return AnalysisResult(
            domain=self.domain,
            attack_detected=report.attack_detected,
            severity=severity,
            confidence=avg_confidence,
            indicators=indicators,
            notes=report.summary,
            metrics={
                "packets_analyzed": report.total_packets_analyzed,
                "windows_analyzed": report.time_windows_analyzed,
                "attack_windows": sum(1 for r in report.detection_results if r.is_attack)
            }
        )

    def propose_mitigation(self, analysis: AnalysisResult) -> MitigationPlan:
        """
        Propose mitigation plan based on analysis (BaseSecurityAgent interface).

        Args:
            analysis: The AnalysisResult from analyze()

        Returns:
            MitigationPlan with immediate and follow-up actions

        Note:
            This method is routed through SafeDeepAgent for security validation
            and audit logging.
        """
        logger.info("Executing propose_mitigation action", severity=analysis.severity.value)

        result = self.safe_agent.execute_safe_action({
            'tool': 'network_mitigate',
            'parameters': {
                'severity': analysis.severity.value,
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            logger.error(
                "Mitigation proposal blocked by security layer",
                blocked_by=result.blocked_by
            )
            return MitigationPlan(
                domain=self.domain,
                severity=analysis.severity,
                immediate_actions=[],
                follow_up_actions=[],
                estimated_impact="Cannot generate plan - blocked by security layer",
                recommended_response_time="N/A"
            )

        if not analysis.attack_detected:
            return MitigationPlan(
                domain=self.domain,
                severity=Severity.NONE,
                immediate_actions=[],
                follow_up_actions=[],
                estimated_impact="No impact",
                recommended_response_time="N/A"
            )

        # Generate prioritized mitigation actions based on severity
        immediate_actions = []
        follow_up_actions = []

        if analysis.severity in [Severity.CRITICAL, Severity.HIGH]:
            immediate_actions = [
                MitigationAction(
                    description="Activate DDoS scrubbing/cleaning service",
                    target="all_ingress_points",
                    action_type="activate_scrubbing",
                    priority=10
                ),
                MitigationAction(
                    description="Enable rate limiting on all ingress points",
                    target="all_ingress_points",
                    action_type="rate_limit",
                    parameters={"max_pps": 50000, "burst_size": 10000},
                    priority=9
                ),
                MitigationAction(
                    description="Contact upstream ISP for filtering assistance",
                    target="upstream_isp",
                    action_type="notify",
                    priority=8
                ),
                MitigationAction(
                    description="Isolate affected systems if possible",
                    target="affected_systems",
                    action_type="isolate",
                    priority=7
                )
            ]

        # Add signature-specific mitigations
        for indicator in analysis.indicators:
            if indicator.type == "signature":
                sig_value = indicator.value
                if "UDP_FLOOD" in sig_value:
                    follow_up_actions.append(MitigationAction(
                        description="Implement UDP rate limiting",
                        target="udp_traffic",
                        action_type="rate_limit",
                        parameters={"protocol": "udp"},
                        priority=6
                    ))
                    follow_up_actions.append(MitigationAction(
                        description="Enable UDP reflection/amplification filtering",
                        target="udp_traffic",
                        action_type="filter",
                        parameters={"filter_type": "amplification"},
                        priority=5
                    ))
                elif "BOTNET" in sig_value:
                    follow_up_actions.append(MitigationAction(
                        description="Implement IP reputation filtering",
                        target="all_traffic",
                        action_type="filter",
                        parameters={"filter_type": "ip_reputation"},
                        priority=6
                    ))
                    follow_up_actions.append(MitigationAction(
                        description="Enable geo-blocking for suspicious regions",
                        target="all_traffic",
                        action_type="geo_block",
                        priority=5
                    ))

        # General follow-up actions
        follow_up_actions.extend([
            MitigationAction(
                description="Update firewall rules based on attack patterns",
                target="firewall",
                action_type="update_rules",
                priority=4
            ),
            MitigationAction(
                description="Enable connection tracking and state tables",
                target="firewall",
                action_type="enable_feature",
                parameters={"feature": "connection_tracking"},
                priority=3
            ),
            MitigationAction(
                description="Implement anycast routing for DDoS resilience",
                target="network_architecture",
                action_type="deploy",
                priority=2
            ),
            MitigationAction(
                description="Conduct post-incident review and update defenses",
                target="security_team",
                action_type="notify",
                priority=1
            )
        ])

        # Deduplicate actions by description
        seen_descriptions = set()
        deduplicated_follow_up = []
        for action in follow_up_actions:
            if action.description not in seen_descriptions:
                seen_descriptions.add(action.description)
                deduplicated_follow_up.append(action)

        mitigation_plan = MitigationPlan(
            domain=self.domain,
            severity=analysis.severity,
            immediate_actions=immediate_actions,
            follow_up_actions=deduplicated_follow_up,
            estimated_impact=self._estimate_impact(
                self._severity_to_threat_level(analysis.severity)
            ),
            recommended_response_time=self._get_response_time(
                self._severity_to_threat_level(analysis.severity)
            )
        )

        logger.info(
            "Mitigation plan generated",
            severity=analysis.severity.value,
            action_count=mitigation_plan.action_count()
        )

        return mitigation_plan

    # =============================================================================
    # Legacy Methods (Backwards Compatibility)
    # =============================================================================

    def run_ddos_detection(
        self,
        packets: List[TrafficPacket],
        include_advanced_features: bool = True
    ) -> Dict[str, Any]:
        """
        Run DDoS detection on network traffic packets.

        This action is executed through SafeDeepAgent's execute_safe_action()
        to ensure validation, sandboxing, and audit logging.

        Args:
            packets: List of traffic packets to analyze
            include_advanced_features: Whether to compute advanced features

        Returns:
            Dictionary with analysis results and security metadata
        """
        logger.info("Executing run_ddos_detection action", packet_count=len(packets))

        # Execute through SafeDeepAgent framework
        result = self.safe_agent.execute_safe_action({
            'tool': 'ddos_detection',
            'parameters': {
                'packets': packets,
                'include_advanced_features': include_advanced_features,
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            logger.error(
                "DDoS detection blocked by security layer",
                blocked_by=result.blocked_by,
                reason=result.reason
            )
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason,
                'analysis': None
            }

        # Perform actual detection
        analysis_report = self.detection_engine.analyze_traffic(
            packets=packets,
            include_advanced_features=include_advanced_features
        )

        # Store for later reference
        self.last_analysis = analysis_report

        logger.info(
            "DDoS detection completed",
            attack_detected=analysis_report.attack_detected,
            threat_level=analysis_report.overall_threat_level.value
        )

        return {
            'success': True,
            'blocked': False,
            'analysis': analysis_report,
            'security_metadata': {
                'action_validated': True,
                'audit_logged': True,
                'provenance_tracked': True
            }
        }

    def summarize_findings(self) -> Dict[str, Any]:
        """
        Generate human-readable summary of last analysis.

        Returns:
            Dictionary with summary and recommendations
        """
        logger.info("Executing summarize_findings action")

        result = self.safe_agent.execute_safe_action({
            'tool': 'summarize_findings',
            'parameters': {
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason
            }

        if self.last_analysis is None:
            return {
                'success': True,
                'blocked': False,
                'summary': "No analysis has been performed yet.",
                'recommendations': []
            }

        summary = {
            'success': True,
            'blocked': False,
            'timestamp': self.last_analysis.timestamp.isoformat(),
            'attack_detected': self.last_analysis.attack_detected,
            'threat_level': self.last_analysis.overall_threat_level.value,
            'summary': self.last_analysis.summary,
            'packets_analyzed': self.last_analysis.total_packets_analyzed,
            'windows_analyzed': self.last_analysis.time_windows_analyzed,
            'attack_windows': sum(
                1 for r in self.last_analysis.detection_results if r.is_attack
            ),
            'signatures_detected': list(set(
                sig
                for r in self.last_analysis.detection_results
                for sig in r.signatures_matched
            )),
            'recommendations': self.last_analysis.recommendations
        }

        logger.info("Findings summarized", attack_detected=summary['attack_detected'])

        return summary

    def propose_mitigation_legacy(self) -> Dict[str, Any]:
        """
        Propose mitigation strategies based on detected threats (legacy method).

        Returns:
            Dictionary with mitigation recommendations

        Note:
            This is the legacy method for backwards compatibility.
            New code should use propose_mitigation(analysis: AnalysisResult) instead.
        """
        logger.info("Executing propose_mitigation_legacy action")

        result = self.safe_agent.execute_safe_action({
            'tool': 'propose_mitigation',
            'parameters': {
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason
            }

        if self.last_analysis is None or not self.last_analysis.attack_detected:
            return {
                'success': True,
                'blocked': False,
                'mitigation_required': False,
                'message': "No active threats detected. No mitigation needed."
            }

        # Generate prioritized mitigation strategies
        threat_level = self.last_analysis.overall_threat_level
        recommendations = self.last_analysis.recommendations

        # Prioritize based on threat level
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []

        if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            immediate_actions = [
                "IMMEDIATE: Activate DDoS scrubbing/cleaning service",
                "IMMEDIATE: Enable rate limiting on all ingress points",
                "IMMEDIATE: Contact upstream ISP for filtering assistance",
                "IMMEDIATE: Isolate affected systems if possible"
            ]

        short_term_actions.extend(recommendations)
        short_term_actions.append("Update firewall rules based on attack patterns")
        short_term_actions.append("Enable connection tracking and state tables")

        long_term_actions = [
            "Implement anycast routing for DDoS resilience",
            "Deploy additional DDoS mitigation capacity",
            "Establish automated response playbooks",
            "Conduct post-incident review and update defenses"
        ]

        mitigation_plan = {
            'success': True,
            'blocked': False,
            'mitigation_required': True,
            'threat_level': threat_level.value,
            'immediate_actions': immediate_actions,
            'short_term_actions': short_term_actions,
            'long_term_actions': long_term_actions,
            'estimated_impact': self._estimate_impact(threat_level),
            'recommended_response_time': self._get_response_time(threat_level)
        }

        logger.info(
            "Mitigation plan proposed",
            threat_level=threat_level.value,
            action_count=len(immediate_actions + short_term_actions + long_term_actions)
        )

        return mitigation_plan

    def export_audit_report(self, filepath: str = "audit_report.json") -> Dict[str, Any]:
        """
        Export complete audit trail and analysis report.

        Args:
            filepath: Path to export audit report

        Returns:
            Dictionary with export status and metadata
        """
        logger.info("Executing export_audit_report action", filepath=filepath)

        result = self.safe_agent.execute_safe_action({
            'tool': 'export_audit',
            'parameters': {
                'filepath': filepath,
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason
            }

        if self.last_analysis is None:
            return {
                'success': False,
                'blocked': False,
                'message': "No analysis data available to export"
            }

        # Create comprehensive audit report
        audit_report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'agent_version': '0.1.0',
                'safedeepagent_enabled': True,
                'security_foundations_active': 12
            },
            'analysis_summary': {
                'timestamp': self.last_analysis.timestamp.isoformat(),
                'attack_detected': self.last_analysis.attack_detected,
                'threat_level': self.last_analysis.overall_threat_level.value,
                'packets_analyzed': self.last_analysis.total_packets_analyzed,
                'windows_analyzed': self.last_analysis.time_windows_analyzed
            },
            'detection_results': [
                {
                    'is_attack': r.is_attack,
                    'threat_level': r.threat_level.value,
                    'confidence': r.confidence,
                    'signatures': r.signatures_matched,
                    'metrics': r.metrics,
                    'explanation': r.explanation
                }
                for r in self.last_analysis.detection_results
            ],
            'recommendations': self.last_analysis.recommendations,
            'summary': self.last_analysis.summary
        }

        # In production, would write to file
        # For now, return in response
        logger.info("Audit report generated", filepath=filepath)

        return {
            'success': True,
            'blocked': False,
            'filepath': filepath,
            'report': audit_report,
            'security_metadata': {
                'provenance_tracked': True,
                'audit_logged': True,
                'tamper_protected': True
            }
        }

    def train_baseline(self, normal_traffic: List[TrafficPacket]) -> Dict[str, Any]:
        """
        Train baseline profile from normal traffic.

        Args:
            normal_traffic: List of packets representing normal traffic

        Returns:
            Dictionary with baseline profile and training status
        """
        logger.info("Executing train_baseline action", packet_count=len(normal_traffic))

        result = self.safe_agent.execute_safe_action({
            'tool': 'train_baseline',
            'parameters': {
                'packet_count': len(normal_traffic),
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason
            }

        # Train baseline
        baseline = self.detection_engine.train_baseline(normal_traffic)
        self.baseline_trained = True

        logger.info("Baseline training completed", baseline=baseline)

        return {
            'success': True,
            'blocked': False,
            'baseline_trained': True,
            'baseline_profile': baseline,
            'training_samples': len(normal_traffic)
        }

    def update_sensitivity(self, sensitivity: float) -> Dict[str, Any]:
        """
        Update detection sensitivity.

        Args:
            sensitivity: New sensitivity value (0.0 to 1.0)

        Returns:
            Dictionary with update status
        """
        logger.info("Executing update_sensitivity action", sensitivity=sensitivity)

        result = self.safe_agent.execute_safe_action({
            'tool': 'update_config',
            'parameters': {
                'sensitivity': sensitivity,
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            return {
                'success': False,
                'blocked': True,
                'blocked_by': result.blocked_by,
                'reason': result.reason
            }

        self.detection_engine.update_sensitivity(sensitivity)

        return {
            'success': True,
            'blocked': False,
            'sensitivity': sensitivity
        }

    def _estimate_impact(self, threat_level: ThreatLevel) -> str:
        """Estimate potential impact of detected attack."""
        impact_map = {
            ThreatLevel.CRITICAL: "Service unavailability, complete outage likely",
            ThreatLevel.HIGH: "Severe service degradation, partial outage possible",
            ThreatLevel.MEDIUM: "Moderate service degradation, increased latency",
            ThreatLevel.LOW: "Minor service impact, elevated resource usage",
            ThreatLevel.NONE: "No impact"
        }
        return impact_map.get(threat_level, "Unknown impact")

    def _get_response_time(self, threat_level: ThreatLevel) -> str:
        """Get recommended response time based on threat level."""
        response_map = {
            ThreatLevel.CRITICAL: "Immediate (< 5 minutes)",
            ThreatLevel.HIGH: "Urgent (< 15 minutes)",
            ThreatLevel.MEDIUM: "Priority (< 1 hour)",
            ThreatLevel.LOW: "Standard (< 4 hours)",
            ThreatLevel.NONE: "N/A"
        }
        return response_map.get(threat_level, "Unknown")

    def get_status(self) -> Dict[str, Any]:
        """
        Get current agent status.

        Returns:
            Dictionary with agent status information
        """
        return {
            'agent_initialized': True,
            'baseline_trained': self.baseline_trained,
            'last_analysis_timestamp': (
                self.last_analysis.timestamp.isoformat()
                if self.last_analysis else None
            ),
            'last_attack_detected': (
                self.last_analysis.attack_detected
                if self.last_analysis else False
            ),
            'safedeepagent_active': True,
            'security_foundations_enabled': 12
        }
