"""Tests for DDoS detection engine."""

import pytest

from ddos_sentinel.data.simulator import TrafficSimulator
from ddos_sentinel.detection.engine import DDoSDetectionEngine
from ddos_sentinel.detection.signatures import (
    AisuruSignatureDetector,
    ThreatLevel
)


class TestAisuruSignatureDetector:
    """Test suite for Aisuru signature detection."""

    def test_init(self):
        """Test detector initialization."""
        detector = AisuruSignatureDetector(sensitivity=0.8)
        assert detector.sensitivity == 0.8
        assert detector.baseline == {}

    def test_detect_normal_traffic(self):
        """Test that normal traffic is not flagged."""
        detector = AisuruSignatureDetector()
        sim = TrafficSimulator(seed=42)

        # Generate normal traffic
        packets = sim.generate_normal_traffic(
            duration_seconds=10,
            base_pps=1000
        )

        # Extract metrics and detect
        from ddos_sentinel.data.features import TrafficFeatureExtractor
        extractor = TrafficFeatureExtractor(window_size_seconds=10)
        metrics_list = extractor.extract_metrics(packets)

        if metrics_list:
            result = detector.detect(metrics_list[0])
            assert result.is_attack is False
            assert result.threat_level == ThreatLevel.NONE

    def test_detect_aisuru_attack(self):
        """Test detection of Aisuru-style DDoS attack."""
        detector = AisuruSignatureDetector()
        sim = TrafficSimulator(seed=42)

        # Generate attack traffic
        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=1,
            attack_pps=150000,
            botnet_size=5000
        )

        # Extract metrics and detect
        from ddos_sentinel.data.features import TrafficFeatureExtractor
        extractor = TrafficFeatureExtractor(window_size_seconds=10)
        metrics_list = extractor.extract_metrics(packets)

        if metrics_list:
            result = detector.detect(metrics_list[0])
            assert result.is_attack is True
            assert result.threat_level in [
                ThreatLevel.HIGH,
                ThreatLevel.CRITICAL
            ]
            assert len(result.signatures_matched) > 0
            assert result.confidence > 0.7

    def test_udp_flood_detection(self):
        """Test UDP flood signature detection."""
        detector = AisuruSignatureDetector()

        # Create metrics with high UDP ratio
        from ddos_sentinel.data.simulator import TrafficMetrics
        from datetime import datetime

        metrics = TrafficMetrics(
            timestamp=datetime.now(),
            total_packets=10000,
            total_bytes=1000000,
            packets_per_second=150000,
            bytes_per_second=15000000,
            unique_source_ips=5000,
            unique_dest_ips=1,
            udp_ratio=0.98,  # 98% UDP
            tcp_ratio=0.02,
            avg_packet_size=100,
            protocol_distribution={"UDP": 9800, "TCP": 200}
        )

        result = detector.detect(metrics)
        assert result.is_attack is True
        assert any("UDP_FLOOD" in sig for sig in result.signatures_matched)


class TestDDoSDetectionEngine:
    """Test suite for DDoS detection engine."""

    def test_init(self):
        """Test engine initialization."""
        engine = DDoSDetectionEngine(
            window_size_seconds=10,
            sensitivity=0.8
        )
        assert engine.window_size == 10
        assert engine.signature_detector is not None

    def test_analyze_normal_traffic(self):
        """Test analysis of normal traffic."""
        engine = DDoSDetectionEngine()
        sim = TrafficSimulator(seed=42)

        packets = sim.generate_normal_traffic(
            duration_seconds=30,
            base_pps=1000
        )

        report = engine.analyze_traffic(packets)

        assert report.total_packets_analyzed == len(packets)
        assert report.time_windows_analyzed > 0
        assert report.attack_detected is False
        assert report.overall_threat_level == ThreatLevel.NONE

    def test_analyze_attack_traffic(self):
        """Test analysis of attack traffic."""
        engine = DDoSDetectionEngine()
        sim = TrafficSimulator(seed=42)

        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=10,
            attack_pps=150000,
            botnet_size=5000
        )

        report = engine.analyze_traffic(packets)

        assert report.total_packets_analyzed == len(packets)
        assert report.attack_detected is True
        assert report.overall_threat_level in [
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL
        ]
        assert len(report.recommendations) > 0

    def test_train_baseline(self):
        """Test baseline training."""
        engine = DDoSDetectionEngine()
        sim = TrafficSimulator(seed=42)

        normal_packets = sim.generate_normal_traffic(
            duration_seconds=60,
            base_pps=1000
        )

        baseline = engine.train_baseline(normal_packets)

        assert "pps_mean" in baseline
        assert "unique_ips_mean" in baseline
        assert baseline["pps_mean"] > 0

    def test_baseline_anomaly_detection(self):
        """Test anomaly detection with baseline."""
        sim = TrafficSimulator(seed=42)

        # Train baseline on normal traffic
        normal_packets = sim.generate_normal_traffic(
            duration_seconds=60,
            base_pps=1000
        )

        engine = DDoSDetectionEngine()
        baseline = engine.train_baseline(normal_packets)

        # Test with attack traffic
        attack_packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=10,
            attack_pps=150000
        )

        report = engine.analyze_traffic(attack_packets)
        assert report.attack_detected is True
