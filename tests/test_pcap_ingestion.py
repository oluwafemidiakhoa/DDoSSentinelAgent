"""Tests for PCAP ingestion."""

import pytest
from unittest.mock import Mock, patch

from ddos_sentinel.data.simulator import TrafficSimulator


class TestPCAPIngestion:
    """Test PCAP ingestion functionality."""

    def test_pcap_ingestion_import(self):
        """Test that PCAP ingestion can be imported."""
        try:
            from ddos_sentinel.data.pcap_ingestion import PCAPIngestion
            assert PCAPIngestion is not None
        except ImportError as e:
            pytest.skip(f"Scapy not installed: {e}")

    def test_pcap_not_found(self):
        """Test handling of missing PCAP file."""
        try:
            from ddos_sentinel.data.pcap_ingestion import PCAPIngestion
        except ImportError:
            pytest.skip("Scapy not installed")

        ingestion = PCAPIngestion()

        with pytest.raises(FileNotFoundError):
            ingestion.read_pcap("nonexistent.pcap")

    def test_simulator_to_pcap_compatibility(self):
        """Test that simulated packets have same structure as PCAP packets."""
        # Generate simulated packets
        sim = TrafficSimulator(seed=42)
        packets = sim.generate_normal_traffic(duration_seconds=1, base_pps=100)

        # Verify packet structure
        assert len(packets) > 0

        for pkt in packets:
            assert hasattr(pkt, 'timestamp')
            assert hasattr(pkt, 'source_ip')
            assert hasattr(pkt, 'dest_ip')
            assert hasattr(pkt, 'protocol')
            assert hasattr(pkt, 'packet_size')
