"""Tests for traffic simulation."""

import pytest
from datetime import datetime, timedelta

from ddos_sentinel.data.simulator import (
    TrafficSimulator,
    TrafficType,
    TrafficPacket
)


class TestTrafficSimulator:
    """Test suite for TrafficSimulator."""

    def test_init(self):
        """Test simulator initialization."""
        sim = TrafficSimulator(seed=42)
        assert sim.rng is not None
        assert len(sim.packet_buffer) == 0

    def test_generate_normal_traffic(self):
        """Test normal traffic generation."""
        sim = TrafficSimulator(seed=42)
        packets = sim.generate_normal_traffic(
            duration_seconds=10,
            base_pps=100
        )

        assert len(packets) > 0
        assert 800 < len(packets) < 1200  # Allow for variance

        # Check packet structure
        first_packet = packets[0]
        assert isinstance(first_packet, TrafficPacket)
        assert first_packet.protocol in ["TCP", "UDP", "ICMP"]
        assert first_packet.packet_size > 0

        # Check protocol distribution (should be mostly TCP for normal)
        tcp_count = sum(1 for p in packets if p.protocol == "TCP")
        assert tcp_count > len(packets) * 0.5  # At least 50% TCP

    def test_generate_aisuru_ddos_traffic(self):
        """Test Aisuru-style DDoS traffic generation."""
        sim = TrafficSimulator(seed=42)
        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=1,
            attack_pps=10000,
            botnet_size=100
        )

        assert len(packets) > 9000  # Should be close to 10k
        assert len(packets) < 11000

        # Check Aisuru characteristics
        udp_count = sum(1 for p in packets if p.protocol == "UDP")
        udp_ratio = udp_count / len(packets)
        assert udp_ratio > 0.90  # Should be >90% UDP

        # Check source IP diversity (botnet)
        unique_sources = len(set(p.source_ip for p in packets))
        assert unique_sources > 50  # Many unique IPs

        # Check small packet sizes
        avg_size = sum(p.packet_size for p in packets) / len(packets)
        assert avg_size < 300  # Small packets

    def test_generate_mixed_scenario(self):
        """Test mixed scenario generation."""
        sim = TrafficSimulator(seed=42)
        packets = sim.generate_mixed_scenario(
            total_duration=30,
            attack_start=10,
            attack_duration=10,
            normal_pps=100,
            attack_pps=1000
        )

        assert len(packets) > 0

        # Check phases exist
        phase1_end = packets[0].timestamp + timedelta(seconds=10)
        phase1_packets = [p for p in packets if p.timestamp < phase1_end]

        # Phase 1 should be normal traffic
        assert len(phase1_packets) > 0
        tcp_ratio_phase1 = sum(
            1 for p in phase1_packets if p.protocol == "TCP"
        ) / len(phase1_packets)
        assert tcp_ratio_phase1 > 0.5  # Normal traffic is mostly TCP

    def test_clear_buffer(self):
        """Test buffer clearing."""
        sim = TrafficSimulator(seed=42)
        sim.generate_normal_traffic(duration_seconds=1)

        assert len(sim.packet_buffer) > 0

        sim.clear_buffer()
        assert len(sim.packet_buffer) == 0
