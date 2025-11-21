"""Tests for DDoS Sentinel Agent."""

import pytest

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.simulator import TrafficSimulator
from safedeepagent.core.safe_agent import SafeConfig


class TestDDoSSentinelAgent:
    """Test suite for DDoSSentinelAgent."""

    def test_init(self):
        """Test agent initialization."""
        agent = DDoSSentinelAgent()
        assert agent.safe_agent is not None
        assert agent.detection_engine is not None
        assert agent.baseline_trained is False

    def test_init_with_custom_config(self):
        """Test initialization with custom SafeConfig."""
        config = SafeConfig(
            enable_action_validation=True,
            enable_audit_logging=True
        )
        agent = DDoSSentinelAgent(safe_config=config)
        assert agent.safe_agent is not None

    def test_run_ddos_detection_normal(self):
        """Test detection on normal traffic."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        packets = sim.generate_normal_traffic(
            duration_seconds=10,
            base_pps=1000
        )

        result = agent.run_ddos_detection(packets)

        assert result['success'] is True
        assert result['blocked'] is False
        assert result['analysis'] is not None
        assert result['analysis'].attack_detected is False

    def test_run_ddos_detection_attack(self):
        """Test detection on attack traffic."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=5,
            attack_pps=150000
        )

        result = agent.run_ddos_detection(packets)

        assert result['success'] is True
        assert result['analysis'] is not None
        assert result['analysis'].attack_detected is True

    def test_summarize_findings(self):
        """Test findings summarization."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # Run detection first
        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=5,
            attack_pps=150000
        )
        agent.run_ddos_detection(packets)

        # Get summary
        summary = agent.summarize_findings()

        assert summary['success'] is True
        assert 'attack_detected' in summary
        assert 'threat_level' in summary
        assert 'summary' in summary

    def test_propose_mitigation(self):
        """Test mitigation proposal."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # Run detection on attack
        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=5,
            attack_pps=150000
        )
        agent.run_ddos_detection(packets)

        # Propose mitigation
        mitigation = agent.propose_mitigation()

        assert mitigation['success'] is True
        if mitigation['mitigation_required']:
            assert len(mitigation['short_term_actions']) > 0

    def test_train_baseline(self):
        """Test baseline training."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        normal_packets = sim.generate_normal_traffic(
            duration_seconds=30,
            base_pps=1000
        )

        result = agent.train_baseline(normal_packets)

        assert result['success'] is True
        assert result['baseline_trained'] is True
        assert 'baseline_profile' in result

    def test_export_audit_report(self):
        """Test audit report export."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # Run some detection
        packets = sim.generate_normal_traffic(
            duration_seconds=10,
            base_pps=1000
        )
        agent.run_ddos_detection(packets)

        # Export report
        result = agent.export_audit_report()

        assert result['success'] is True
        assert 'report' in result
        assert 'security_metadata' in result

    def test_get_status(self):
        """Test status retrieval."""
        agent = DDoSSentinelAgent()
        status = agent.get_status()

        assert status['agent_initialized'] is True
        assert status['safedeepagent_active'] is True
        assert status['security_foundations_enabled'] == 12

    def test_update_sensitivity(self):
        """Test sensitivity update."""
        agent = DDoSSentinelAgent(sensitivity=0.5)

        result = agent.update_sensitivity(0.9)

        assert result['success'] is True
        assert result['sensitivity'] == 0.9
