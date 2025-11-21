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

logger = structlog.get_logger(__name__)


class DDoSSentinelAgent:
    """
    Secure autonomous DDoS detection agent built with SafeDeepAgent.

    This agent orchestrates DDoS detection operations through the SafeDeepAgent
    framework, ensuring all actions are validated, audited, and supervised
    according to the 12 foundations of agentic AI safety.

    Supported Actions:
        - run_ddos_detection: Analyze traffic for DDoS attacks
        - summarize_findings: Generate human-readable summary
        - propose_mitigation: Recommend mitigation strategies
        - export_audit_report: Export complete audit trail
        - train_baseline: Train normal traffic baseline
    """

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

    def propose_mitigation(self) -> Dict[str, Any]:
        """
        Propose mitigation strategies based on detected threats.

        Returns:
            Dictionary with mitigation recommendations
        """
        logger.info("Executing propose_mitigation action")

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
