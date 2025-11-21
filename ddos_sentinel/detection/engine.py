"""
DDoS Detection Engine.

Main detection engine that coordinates traffic analysis, feature extraction,
and signature detection.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import structlog

from ddos_sentinel.data.simulator import TrafficPacket
from ddos_sentinel.data.features import TrafficFeatureExtractor
from ddos_sentinel.detection.signatures import (
    AisuruSignatureDetector,
    DetectionResult,
    ThreatLevel
)

logger = structlog.get_logger(__name__)


@dataclass
class AnalysisReport:
    """Comprehensive analysis report from the detection engine."""
    timestamp: datetime
    total_packets_analyzed: int
    time_windows_analyzed: int
    detection_results: List[DetectionResult]
    overall_threat_level: ThreatLevel
    attack_detected: bool
    summary: str
    recommendations: List[str]


class DDoSDetectionEngine:
    """
    Main DDoS detection engine.

    Coordinates traffic analysis, feature extraction, and signature-based
    detection to identify Aisuru-like DDoS attacks.
    """

    def __init__(
        self,
        window_size_seconds: int = 10,
        sensitivity: float = 0.8,
        baseline_profile: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the detection engine.

        Args:
            window_size_seconds: Time window for traffic aggregation
            sensitivity: Detection sensitivity (0.0 to 1.0)
            baseline_profile: Optional baseline profile for anomaly detection
        """
        self.feature_extractor = TrafficFeatureExtractor(
            window_size_seconds=window_size_seconds
        )
        self.signature_detector = AisuruSignatureDetector(
            baseline_profile=baseline_profile,
            sensitivity=sensitivity
        )
        self.window_size = window_size_seconds

        logger.info(
            "Detection engine initialized",
            window_size=window_size_seconds,
            sensitivity=sensitivity,
            has_baseline=baseline_profile is not None
        )

    def analyze_traffic(
        self,
        packets: List[TrafficPacket],
        include_advanced_features: bool = True
    ) -> AnalysisReport:
        """
        Analyze traffic packets for DDoS attacks.

        Args:
            packets: List of traffic packets to analyze
            include_advanced_features: Whether to compute advanced features

        Returns:
            AnalysisReport with comprehensive analysis results
        """
        logger.info("Starting traffic analysis", packet_count=len(packets))

        if not packets:
            return self._empty_report()

        # Extract time-windowed metrics
        metrics_list = self.feature_extractor.extract_metrics(packets)
        logger.info("Extracted metrics", window_count=len(metrics_list))

        # Extract advanced features if requested
        advanced_features = None
        if include_advanced_features:
            advanced_features = self.feature_extractor.extract_advanced_features(
                packets
            )
            logger.debug("Extracted advanced features", features=advanced_features)

        # Run detection on each time window
        detection_results = []
        for metrics in metrics_list:
            result = self.signature_detector.detect(metrics, advanced_features)
            detection_results.append(result)

            if result.is_attack:
                logger.warning(
                    "Attack detected in window",
                    timestamp=metrics.timestamp,
                    threat_level=result.threat_level.value,
                    signatures=result.signatures_matched
                )

        # Aggregate results
        report = self._generate_report(
            packets=packets,
            metrics_count=len(metrics_list),
            detection_results=detection_results
        )

        logger.info(
            "Analysis complete",
            attack_detected=report.attack_detected,
            threat_level=report.overall_threat_level.value
        )

        return report

    def analyze_realtime_window(
        self,
        packets: List[TrafficPacket]
    ) -> DetectionResult:
        """
        Analyze a single time window of packets (for real-time detection).

        Args:
            packets: Packets in current time window

        Returns:
            DetectionResult for this window
        """
        if not packets:
            return DetectionResult(
                is_attack=False,
                threat_level=ThreatLevel.NONE,
                confidence=0.0,
                signatures_matched=[],
                metrics={},
                explanation="No packets to analyze",
                mitigation_recommendations=[]
            )

        # Extract metrics for this window
        metrics = self.feature_extractor._compute_window_metrics(
            packets,
            packets[0].timestamp
        )

        # Extract advanced features
        advanced_features = self.feature_extractor.extract_advanced_features(packets)

        # Detect attack
        result = self.signature_detector.detect(metrics, advanced_features)

        return result

    def train_baseline(
        self,
        normal_traffic_packets: List[TrafficPacket]
    ) -> Dict[str, Any]:
        """
        Train a baseline profile from normal traffic.

        Args:
            normal_traffic_packets: Packets representing normal traffic patterns

        Returns:
            Baseline profile dictionary
        """
        logger.info(
            "Training baseline profile",
            packet_count=len(normal_traffic_packets)
        )

        baseline = self.feature_extractor.compute_baseline_profile(
            normal_traffic_packets
        )

        # Update detector with new baseline
        self.signature_detector.update_baseline(baseline)

        logger.info("Baseline profile trained", baseline=baseline)

        return baseline

    def update_sensitivity(self, sensitivity: float) -> None:
        """
        Update detection sensitivity.

        Args:
            sensitivity: New sensitivity value (0.0 to 1.0)
        """
        self.signature_detector.adjust_sensitivity(sensitivity)
        logger.info("Sensitivity updated", sensitivity=sensitivity)

    def _generate_report(
        self,
        packets: List[TrafficPacket],
        metrics_count: int,
        detection_results: List[DetectionResult]
    ) -> AnalysisReport:
        """Generate comprehensive analysis report."""
        # Determine overall threat level (worst case across all windows)
        attack_windows = [r for r in detection_results if r.is_attack]
        attack_detected = len(attack_windows) > 0

        if attack_detected:
            # Take the highest threat level
            threat_levels_order = [
                ThreatLevel.CRITICAL,
                ThreatLevel.HIGH,
                ThreatLevel.MEDIUM,
                ThreatLevel.LOW
            ]
            overall_threat = ThreatLevel.NONE
            for level in threat_levels_order:
                if any(r.threat_level == level for r in attack_windows):
                    overall_threat = level
                    break
        else:
            overall_threat = ThreatLevel.NONE

        # Collect all unique recommendations
        all_recommendations = []
        for result in attack_windows:
            all_recommendations.extend(result.mitigation_recommendations)
        recommendations = list(set(all_recommendations))  # Deduplicate

        # Generate summary
        summary = self._generate_summary(
            total_packets=len(packets),
            windows_analyzed=metrics_count,
            attack_windows=len(attack_windows),
            overall_threat=overall_threat,
            detection_results=detection_results
        )

        return AnalysisReport(
            timestamp=datetime.now(),
            total_packets_analyzed=len(packets),
            time_windows_analyzed=metrics_count,
            detection_results=detection_results,
            overall_threat_level=overall_threat,
            attack_detected=attack_detected,
            summary=summary,
            recommendations=recommendations
        )

    def _generate_summary(
        self,
        total_packets: int,
        windows_analyzed: int,
        attack_windows: int,
        overall_threat: ThreatLevel,
        detection_results: List[DetectionResult]
    ) -> str:
        """Generate human-readable summary."""
        if attack_windows == 0:
            return (
                f"Analysis complete: {total_packets:,} packets analyzed across "
                f"{windows_analyzed} time windows. No DDoS attack detected. "
                f"Traffic patterns appear normal."
            )

        # Collect signature statistics
        all_signatures = []
        for result in detection_results:
            if result.is_attack:
                all_signatures.extend(result.signatures_matched)

        unique_signatures = set(all_signatures)
        most_common_sig = max(
            set(all_signatures),
            key=all_signatures.count
        ) if all_signatures else "N/A"

        summary = [
            f"⚠️  DDoS ATTACK DETECTED",
            f"",
            f"Threat Level: {overall_threat.value.upper()}",
            f"",
            f"Analysis Summary:",
            f"  • Total packets analyzed: {total_packets:,}",
            f"  • Time windows analyzed: {windows_analyzed}",
            f"  • Attack windows detected: {attack_windows} ({attack_windows/windows_analyzed:.1%})",
            f"  • Unique signatures matched: {len(unique_signatures)}",
            f"  • Most common signature: {most_common_sig}",
            f"",
            f"This traffic pattern is consistent with an Aisuru-style DDoS attack.",
        ]

        return "\n".join(summary)

    def _empty_report(self) -> AnalysisReport:
        """Generate empty report for no packets."""
        return AnalysisReport(
            timestamp=datetime.now(),
            total_packets_analyzed=0,
            time_windows_analyzed=0,
            detection_results=[],
            overall_threat_level=ThreatLevel.NONE,
            attack_detected=False,
            summary="No packets provided for analysis.",
            recommendations=[]
        )
