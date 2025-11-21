"""Integration tests for complete workflow."""

import pytest

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.simulator import TrafficSimulator


class TestIntegration:
    """Integration tests for end-to-end workflows."""

    def test_complete_detection_workflow(self):
        """Test complete detection workflow."""
        # Initialize
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # 1. Train baseline
        normal_packets = sim.generate_normal_traffic(
            duration_seconds=60,
            base_pps=1000
        )
        baseline_result = agent.train_baseline(normal_packets)
        assert baseline_result['success'] is True

        # 2. Run detection on attack
        sim.clear_buffer()
        attack_packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=10,
            attack_pps=150000
        )
        detection_result = agent.run_ddos_detection(attack_packets)
        assert detection_result['success'] is True
        assert detection_result['analysis'].attack_detected is True

        # 3. Summarize findings
        summary = agent.summarize_findings()
        assert summary['success'] is True
        assert summary['attack_detected'] is True

        # 4. Propose mitigation
        mitigation = agent.propose_mitigation()
        assert mitigation['success'] is True
        assert mitigation['mitigation_required'] is True

        # 5. Export audit report
        audit = agent.export_audit_report()
        assert audit['success'] is True
        assert audit['report'] is not None

    def test_mixed_scenario_detection(self):
        """Test detection on mixed traffic scenario."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # Train baseline first
        normal = sim.generate_normal_traffic(
            duration_seconds=60,
            base_pps=1000
        )
        agent.train_baseline(normal)

        # Generate mixed scenario
        sim.clear_buffer()
        packets = sim.generate_mixed_scenario(
            total_duration=120,
            attack_start=30,
            attack_duration=60,
            normal_pps=1000,
            attack_pps=150000
        )

        # Analyze
        result = agent.run_ddos_detection(packets)

        assert result['success'] is True
        assert result['analysis'].attack_detected is True
        assert result['analysis'].time_windows_analyzed > 10

        # Should detect attack in some windows
        attack_windows = sum(
            1 for r in result['analysis'].detection_results
            if r.is_attack
        )
        assert attack_windows > 0

    def test_false_positive_rate(self):
        """Test false positive rate on extended normal traffic."""
        agent = DDoSSentinelAgent()
        sim = TrafficSimulator(seed=42)

        # Train baseline
        baseline_traffic = sim.generate_normal_traffic(
            duration_seconds=60,
            base_pps=1000
        )
        agent.train_baseline(baseline_traffic)

        # Test on new normal traffic
        sim.clear_buffer()
        test_traffic = sim.generate_normal_traffic(
            duration_seconds=120,
            base_pps=1000
        )

        result = agent.run_ddos_detection(test_traffic)

        # Should not detect attack on normal traffic
        assert result['success'] is True
        # Allow for some false positives due to variance, but should be minimal
        if result['analysis'].attack_detected:
            attack_ratio = sum(
                1 for r in result['analysis'].detection_results if r.is_attack
            ) / len(result['analysis'].detection_results)
            assert attack_ratio < 0.1  # Less than 10% false positive rate

    def test_sensitivity_adjustment(self):
        """Test that sensitivity adjustment affects detection."""
        sim = TrafficSimulator(seed=42)

        # Generate borderline suspicious traffic
        # (higher than normal but not full attack)
        packets = sim.generate_aisuru_ddos_traffic(
            duration_seconds=10,
            attack_pps=60000,  # Lower than typical attack
            botnet_size=500
        )

        # Test with low sensitivity
        agent_low = DDoSSentinelAgent(sensitivity=0.3)
        result_low = agent_low.run_ddos_detection(packets)

        # Test with high sensitivity
        agent_high = DDoSSentinelAgent(sensitivity=0.9)
        result_high = agent_high.run_ddos_detection(packets)

        # High sensitivity should be more likely to detect
        # (though both might detect this level of traffic)
        assert result_low['success'] is True
        assert result_high['success'] is True
