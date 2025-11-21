"""
Aisuru DDoS signature detection.

Implements specific detection logic for Aisuru-style DDoS attacks.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum
from ddos_sentinel.data.simulator import TrafficMetrics


class ThreatLevel(Enum):
    """Threat severity levels."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """Result of a DDoS detection check."""
    is_attack: bool
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    signatures_matched: List[str]
    metrics: Dict[str, Any]
    explanation: str
    mitigation_recommendations: List[str]


class AisuruSignatureDetector:
    """
    Detects Aisuru-style DDoS attack signatures.

    Aisuru attacks are characterized by:
    - Massive UDP floods (95%+ UDP traffic)
    - Extremely high packets per second (100k-300k+)
    - Large number of unique source IPs (botnet behavior)
    - Small packet sizes (amplification attacks)
    - Focused targeting (few destination IPs)
    """

    def __init__(
        self,
        baseline_profile: Optional[Dict[str, Any]] = None,
        sensitivity: float = 0.8
    ):
        """
        Initialize the Aisuru signature detector.

        Args:
            baseline_profile: Normal traffic baseline for anomaly detection
            sensitivity: Detection sensitivity (0.0 to 1.0, higher = more sensitive)
        """
        self.baseline = baseline_profile or {}
        self.sensitivity = sensitivity

        # Aisuru-specific thresholds (based on known attack patterns)
        self.thresholds = {
            # PPS thresholds
            "pps_warning": 50000,
            "pps_critical": 100000,

            # UDP ratio thresholds (Aisuru heavily uses UDP)
            "udp_ratio_suspicious": 0.80,
            "udp_ratio_critical": 0.95,

            # Unique source IP thresholds (botnet indicators)
            "unique_ips_warning": 1000,
            "unique_ips_critical": 3000,

            # Packet size thresholds (amplification attacks use small packets)
            "avg_packet_size_suspicious": 300,  # bytes

            # IP concentration (attack focusing)
            "dest_ip_concentration_critical": 0.90,  # 90%+ to few IPs
        }

    def detect(
        self,
        metrics: TrafficMetrics,
        advanced_features: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Detect Aisuru-style DDoS attack signatures in traffic metrics.

        Args:
            metrics: Aggregated traffic metrics
            advanced_features: Optional advanced feature dict

        Returns:
            DetectionResult with detection outcome and details
        """
        signatures_matched = []
        threat_scores = []
        recommendations = []

        # Signature 1: Massive UDP flood
        udp_score, udp_sig = self._check_udp_flood(metrics)
        if udp_sig:
            signatures_matched.append(udp_sig)
            threat_scores.append(udp_score)
            recommendations.append("Implement UDP rate limiting")
            recommendations.append("Enable UDP reflection/amplification filtering")

        # Signature 2: Extremely high PPS
        pps_score, pps_sig = self._check_high_pps(metrics)
        if pps_sig:
            signatures_matched.append(pps_sig)
            threat_scores.append(pps_score)
            recommendations.append("Apply connection rate limiting")
            recommendations.append("Enable DDoS scrubbing/cleaning")

        # Signature 3: Botnet behavior (many unique source IPs)
        botnet_score, botnet_sig = self._check_botnet_pattern(metrics)
        if botnet_sig:
            signatures_matched.append(botnet_sig)
            threat_scores.append(botnet_score)
            recommendations.append("Implement IP reputation filtering")
            recommendations.append("Enable geo-blocking for suspicious regions")

        # Signature 4: Small packet amplification attack
        if advanced_features:
            amp_score, amp_sig = self._check_amplification_attack(
                metrics, advanced_features
            )
            if amp_sig:
                signatures_matched.append(amp_sig)
                threat_scores.append(amp_score)
                recommendations.append("Block common amplification ports (DNS, NTP, etc.)")

        # Signature 5: Focused targeting
        if advanced_features:
            target_score, target_sig = self._check_focused_targeting(advanced_features)
            if target_sig:
                signatures_matched.append(target_sig)
                threat_scores.append(target_score)
                recommendations.append("Isolate targeted assets")
                recommendations.append("Enable upstream ISP filtering")

        # Signature 6: Baseline anomaly detection
        if self.baseline:
            anomaly_score, anomaly_sig = self._check_baseline_anomaly(metrics)
            if anomaly_sig:
                signatures_matched.append(anomaly_sig)
                threat_scores.append(anomaly_score)

        # Compute overall detection decision
        is_attack = len(signatures_matched) > 0
        confidence = max(threat_scores) if threat_scores else 0.0

        # Determine threat level based on signatures and scores
        threat_level = self._compute_threat_level(
            signatures_matched,
            threat_scores
        )

        # Generate explanation
        explanation = self._generate_explanation(
            metrics,
            signatures_matched,
            threat_scores
        )

        # Deduplicate recommendations
        recommendations = list(set(recommendations))

        return DetectionResult(
            is_attack=is_attack,
            threat_level=threat_level,
            confidence=confidence,
            signatures_matched=signatures_matched,
            metrics={
                "pps": metrics.packets_per_second,
                "udp_ratio": metrics.udp_ratio,
                "unique_source_ips": metrics.unique_source_ips,
                "avg_packet_size": metrics.avg_packet_size,
            },
            explanation=explanation,
            mitigation_recommendations=recommendations
        )

    def _check_udp_flood(self, metrics: TrafficMetrics) -> tuple[float, Optional[str]]:
        """Check for UDP flood signature."""
        udp_ratio = metrics.udp_ratio

        if udp_ratio >= self.thresholds["udp_ratio_critical"]:
            return (0.95, f"CRITICAL_UDP_FLOOD (UDP ratio: {udp_ratio:.2%})")
        elif udp_ratio >= self.thresholds["udp_ratio_suspicious"]:
            return (0.7, f"SUSPICIOUS_UDP_FLOOD (UDP ratio: {udp_ratio:.2%})")

        return (0.0, None)

    def _check_high_pps(self, metrics: TrafficMetrics) -> tuple[float, Optional[str]]:
        """Check for extremely high packet rate."""
        pps = metrics.packets_per_second

        if pps >= self.thresholds["pps_critical"]:
            return (0.95, f"CRITICAL_HIGH_PPS (PPS: {pps:,.0f})")
        elif pps >= self.thresholds["pps_warning"]:
            return (0.7, f"WARNING_HIGH_PPS (PPS: {pps:,.0f})")

        return (0.0, None)

    def _check_botnet_pattern(
        self,
        metrics: TrafficMetrics
    ) -> tuple[float, Optional[str]]:
        """Check for botnet behavior (many unique source IPs)."""
        unique_ips = metrics.unique_source_ips

        if unique_ips >= self.thresholds["unique_ips_critical"]:
            return (0.90, f"CRITICAL_BOTNET_PATTERN (Unique IPs: {unique_ips:,})")
        elif unique_ips >= self.thresholds["unique_ips_warning"]:
            return (0.6, f"WARNING_BOTNET_PATTERN (Unique IPs: {unique_ips:,})")

        return (0.0, None)

    def _check_amplification_attack(
        self,
        metrics: TrafficMetrics,
        features: Dict[str, Any]
    ) -> tuple[float, Optional[str]]:
        """Check for amplification attack (small packets, high volume)."""
        avg_size = metrics.avg_packet_size
        pps = metrics.packets_per_second

        # Amplification attacks: small packets + high PPS
        is_small_packets = avg_size < self.thresholds["avg_packet_size_suspicious"]
        is_high_volume = pps > self.thresholds["pps_warning"]

        if is_small_packets and is_high_volume:
            return (
                0.85,
                f"AMPLIFICATION_ATTACK (Avg size: {avg_size:.0f}B, PPS: {pps:,.0f})"
            )

        return (0.0, None)

    def _check_focused_targeting(
        self,
        features: Dict[str, Any]
    ) -> tuple[float, Optional[str]]:
        """Check for focused targeting (most traffic to few IPs)."""
        # Check if traffic is highly concentrated on few destination IPs
        dest_ip_entropy = features.get("dest_ip_entropy", 5.0)
        unique_dest_ips = features.get("unique_dest_ips", 100)

        # Low entropy + few destination IPs = focused attack
        if dest_ip_entropy < 2.0 and unique_dest_ips < 10:
            return (
                0.75,
                f"FOCUSED_TARGETING (Dest IPs: {unique_dest_ips}, "
                f"Entropy: {dest_ip_entropy:.2f})"
            )

        return (0.0, None)

    def _check_baseline_anomaly(
        self,
        metrics: TrafficMetrics
    ) -> tuple[float, Optional[str]]:
        """Check for anomalies compared to baseline."""
        if not self.baseline:
            return (0.0, None)

        anomalies = []

        # Check PPS anomaly
        baseline_pps = self.baseline.get("pps_mean", 1000)
        baseline_pps_std = self.baseline.get("pps_std", 200)
        pps_threshold = baseline_pps + (3 * baseline_pps_std * self.sensitivity)

        if metrics.packets_per_second > pps_threshold:
            deviation = metrics.packets_per_second / baseline_pps
            anomalies.append(f"PPS: {deviation:.1f}x baseline")

        # Check unique IPs anomaly
        baseline_ips = self.baseline.get("unique_ips_mean", 50)
        baseline_ips_std = self.baseline.get("unique_ips_std", 10)
        ips_threshold = baseline_ips + (3 * baseline_ips_std * self.sensitivity)

        if metrics.unique_source_ips > ips_threshold:
            deviation = metrics.unique_source_ips / baseline_ips
            anomalies.append(f"Unique IPs: {deviation:.1f}x baseline")

        # Check UDP ratio anomaly
        baseline_udp = self.baseline.get("udp_ratio_mean", 0.3)
        if metrics.udp_ratio > baseline_udp + 0.3:  # +30% absolute increase
            anomalies.append(f"UDP ratio increase: {metrics.udp_ratio:.2%}")

        if anomalies:
            return (0.8, f"BASELINE_ANOMALY ({', '.join(anomalies)})")

        return (0.0, None)

    def _compute_threat_level(
        self,
        signatures: List[str],
        scores: List[float]
    ) -> ThreatLevel:
        """Compute overall threat level."""
        if not signatures:
            return ThreatLevel.NONE

        max_score = max(scores)
        signature_count = len(signatures)

        # Multiple critical signatures = CRITICAL
        critical_sigs = sum(1 for s in signatures if "CRITICAL" in s)
        if critical_sigs >= 2 or max_score >= 0.95:
            return ThreatLevel.CRITICAL

        # Any critical signature or many warnings = HIGH
        if critical_sigs >= 1 or signature_count >= 3:
            return ThreatLevel.HIGH

        # Multiple warnings = MEDIUM
        if signature_count >= 2 or max_score >= 0.7:
            return ThreatLevel.MEDIUM

        # Single signature = LOW
        return ThreatLevel.LOW

    def _generate_explanation(
        self,
        metrics: TrafficMetrics,
        signatures: List[str],
        scores: List[float]
    ) -> str:
        """Generate human-readable explanation of detection."""
        if not signatures:
            return "No DDoS attack signatures detected. Traffic appears normal."

        explanation_parts = [
            f"DDoS ATTACK DETECTED with {len(signatures)} signature(s) matched:",
            ""
        ]

        for sig, score in zip(signatures, scores):
            explanation_parts.append(f"  • {sig} (confidence: {score:.1%})")

        explanation_parts.extend([
            "",
            "Traffic Characteristics:",
            f"  • Packets/second: {metrics.packets_per_second:,.0f}",
            f"  • UDP traffic ratio: {metrics.udp_ratio:.1%}",
            f"  • Unique source IPs: {metrics.unique_source_ips:,}",
            f"  • Average packet size: {metrics.avg_packet_size:.0f} bytes",
        ])

        return "\n".join(explanation_parts)

    def update_baseline(self, new_baseline: Dict[str, Any]) -> None:
        """Update the baseline profile."""
        self.baseline = new_baseline

    def adjust_sensitivity(self, sensitivity: float) -> None:
        """
        Adjust detection sensitivity.

        Args:
            sensitivity: New sensitivity value (0.0 to 1.0)
        """
        self.sensitivity = max(0.0, min(1.0, sensitivity))
