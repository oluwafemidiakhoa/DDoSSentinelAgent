"""
Tests for the multi-agent security mesh.

Tests core types, agents, and orchestrator functionality.
"""

import pytest
from safedeepagent.core.safe_agent import SafeDeepAgent, SafeConfig

from ddos_sentinel.core.types import (
    Severity,
    Indicator,
    AnalysisResult,
    MitigationAction,
    MitigationPlan
)
from ddos_sentinel.dns.agent import DNSIntegrityAgent, DNSObservation
from ddos_sentinel.supply_chain.agent import SupplyChainGuardianAgent, SupplyChainObservation
from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.simulator import TrafficSimulator
from ddos_sentinel.mesh.orchestrator import SecurityMeshOrchestrator


class TestCoreTypes:
    """Test core types and data structures."""

    def test_severity_ordering(self):
        """Test that severity levels can be compared."""
        assert Severity.NONE < Severity.LOW
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL

        assert Severity.CRITICAL > Severity.HIGH
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) == Severity.CRITICAL

    def test_indicator_creation(self):
        """Test indicator creation."""
        indicator = Indicator(
            type="ip",
            value="192.168.1.1",
            details={"country": "US"}
        )
        assert indicator.type == "ip"
        assert indicator.value == "192.168.1.1"
        assert indicator.details["country"] == "US"
        assert "192.168.1.1" in str(indicator)

    def test_analysis_result_validation(self):
        """Test AnalysisResult validation."""
        result = AnalysisResult(
            domain="test",
            attack_detected=True,
            severity=Severity.HIGH,
            confidence=0.95
        )
        assert result.confidence == 0.95

        # Test invalid confidence
        with pytest.raises(ValueError):
            AnalysisResult(
                domain="test",
                attack_detected=True,
                severity=Severity.HIGH,
                confidence=1.5  # Invalid
            )

    def test_mitigation_plan_action_count(self):
        """Test mitigation plan action counting."""
        plan = MitigationPlan(
            domain="test",
            severity=Severity.HIGH,
            immediate_actions=[
                MitigationAction("action1", "target1", "block"),
                MitigationAction("action2", "target2", "rate_limit")
            ],
            follow_up_actions=[
                MitigationAction("action3", "target3", "monitor")
            ]
        )
        assert plan.action_count() == 3
        assert len(plan.all_actions()) == 3


class TestDNSIntegrityAgent:
    """Test DNS Integrity Agent."""

    def test_agent_initialization(self):
        """Test DNS agent initialization."""
        agent = DNSIntegrityAgent(sensitivity=0.9)
        assert agent.name == "DNS Integrity Agent"
        assert agent.domain == "dns"
        assert agent.sensitivity == 0.9

    def test_clean_dns_traffic(self):
        """Test analysis of clean DNS traffic."""
        agent = DNSIntegrityAgent()
        observation = DNSObservation(
            domain="example.com",
            qps=50.0,
            unique_client_ips=30,
            asn_distribution={"AS1234": 15, "AS5678": 10, "AS9012": 5},
            query_types={"A": 25, "AAAA": 20, "MX": 5},
            http_traffic_ratio=0.8
        )

        result = agent.analyze(observation)
        assert result.domain == "dns"
        assert not result.attack_detected
        assert result.severity == Severity.NONE

    def test_dns_abuse_detection(self):
        """Test detection of DNS popularity manipulation."""
        agent = DNSIntegrityAgent()
        observation = DNSObservation(
            domain="targetdomain.com",
            qps=8000.0,  # Excessive QPS
            unique_client_ips=3000,  # Botnet pattern
            asn_distribution={"AS6666": 2100, "AS7777": 600, "AS8888": 300},
            query_types={"A": 7500, "AAAA": 400, "MX": 100},
            http_traffic_ratio=0.05  # Low HTTP traffic
        )

        result = agent.analyze(observation)
        assert result.domain == "dns"
        assert result.attack_detected
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]
        assert len(result.indicators) > 0

    def test_dns_mitigation_plan(self):
        """Test DNS mitigation plan generation."""
        agent = DNSIntegrityAgent()
        analysis = AnalysisResult(
            domain="dns",
            attack_detected=True,
            severity=Severity.CRITICAL,
            confidence=0.95,
            indicators=[
                Indicator("dns_abuse", "excessive_qps_test.com", {})
            ]
        )

        plan = agent.propose_mitigation(analysis)
        assert plan.domain == "dns"
        assert plan.severity == Severity.CRITICAL
        assert len(plan.immediate_actions) > 0
        assert "rate limit" in plan.immediate_actions[0].description.lower()


class TestSupplyChainGuardianAgent:
    """Test Supply Chain Guardian Agent."""

    def test_agent_initialization(self):
        """Test supply chain agent initialization."""
        agent = SupplyChainGuardianAgent(sensitivity=0.8)
        assert agent.name == "Supply Chain Guardian Agent"
        assert agent.domain == "supply_chain"

    def test_clean_release(self):
        """Test analysis of clean firmware release."""
        agent = SupplyChainGuardianAgent()
        observation = SupplyChainObservation(
            release_id="v1.0.0",
            version="1.0.0",
            signing_key_id="KEY_PROD_001",
            build_host="build-server-01.company.com",
            rollout_speed=800.0,
            total_devices_updated=5000,
            deployment_duration_hours=6.0,
            post_release_traffic_multiplier=1.1,
            is_known_signing_key=True,
            build_host_reputation="trusted",
            device_behavior_anomalies=2
        )

        result = agent.analyze(observation)
        assert result.domain == "supply_chain"
        assert not result.attack_detected
        assert result.severity == Severity.NONE

    def test_compromised_release_detection(self):
        """Test detection of compromised firmware release."""
        agent = SupplyChainGuardianAgent()
        observation = SupplyChainObservation(
            release_id="v2.0.0_COMPROMISED",
            version="2.0.0",
            signing_key_id="KEY_UNKNOWN_999",  # Unknown key
            build_host="suspicious-builder.external.com",
            rollout_speed=25000.0,  # Worm-like speed
            total_devices_updated=45000,
            deployment_duration_hours=1.8,
            post_release_traffic_multiplier=12.0,
            is_known_signing_key=False,  # CRITICAL
            build_host_reputation="suspicious",
            device_behavior_anomalies=8000
        )

        result = agent.analyze(observation)
        assert result.domain == "supply_chain"
        assert result.attack_detected
        assert result.severity == Severity.CRITICAL
        assert len(result.indicators) >= 2  # Multiple indicators

    def test_supply_chain_mitigation(self):
        """Test supply chain mitigation plan."""
        agent = SupplyChainGuardianAgent()
        analysis = AnalysisResult(
            domain="supply_chain",
            attack_detected=True,
            severity=Severity.CRITICAL,
            confidence=0.95,
            indicators=[
                Indicator("signing_key", "KEY_UNKNOWN_999", {"is_known": False})
            ],
            metrics={"release_id": "v2.0.0"}
        )

        plan = agent.propose_mitigation(analysis)
        assert plan.domain == "supply_chain"
        assert plan.severity == Severity.CRITICAL
        assert len(plan.immediate_actions) > 0
        # Should have halt rollout action
        action_types = [a.action_type for a in plan.immediate_actions]
        assert "halt_rollout" in action_types or "revoke_key" in action_types


class TestSecurityMeshOrchestrator:
    """Test multi-agent mesh orchestrator."""

    def test_orchestrator_initialization(self):
        """Test orchestrator initialization."""
        network_agent = DDoSSentinelAgent()
        dns_agent = DNSIntegrityAgent()
        supply_chain_agent = SupplyChainGuardianAgent()

        safe_agent = SafeDeepAgent(safe_config=SafeConfig())
        mesh = SecurityMeshOrchestrator(
            agents=[network_agent, dns_agent, supply_chain_agent],
            safe_agent=safe_agent
        )

        assert len(mesh.agents) == 3
        assert mesh.list_domains() == ["network", "dns", "supply_chain"]

    def test_mesh_clean_scenario(self):
        """Test mesh with clean traffic across all domains."""
        # Initialize agents
        network_agent = DDoSSentinelAgent()
        dns_agent = DNSIntegrityAgent()
        supply_chain_agent = SupplyChainGuardianAgent()

        safe_agent = SafeDeepAgent(safe_config=SafeConfig())
        mesh = SecurityMeshOrchestrator(
            agents=[network_agent, dns_agent, supply_chain_agent],
            safe_agent=safe_agent
        )

        # Generate clean observations
        simulator = TrafficSimulator(seed=42)
        observations = {
            "network": simulator.generate_normal_traffic(
                duration_seconds=10,
                base_pps=1000
            ),
            "dns": DNSObservation(
                domain="example.com",
                qps=50.0,
                unique_client_ips=30,
                asn_distribution={"AS1234": 15, "AS5678": 10},
                query_types={"A": 25, "AAAA": 20},
                http_traffic_ratio=0.8
            ),
            "supply_chain": SupplyChainObservation(
                release_id="v1.0.0",
                version="1.0.0",
                signing_key_id="KEY_PROD_001",
                build_host="build-server-01.company.com",
                rollout_speed=800.0,
                total_devices_updated=5000,
                deployment_duration_hours=6.0,
                is_known_signing_key=True,
                build_host_reputation="trusted"
            )
        }

        # Run mesh analysis
        result = mesh.run_end_to_end(observations)

        assert result['summary']['attacks_detected'] == 0
        assert result['summary']['global_severity'] == 'none'
        assert len(result['per_agent_analyses']) == 3

    def test_mesh_multi_domain_attack(self):
        """Test mesh with attacks across multiple domains."""
        # Initialize agents
        network_agent = DDoSSentinelAgent()
        dns_agent = DNSIntegrityAgent()
        supply_chain_agent = SupplyChainGuardianAgent()

        safe_agent = SafeDeepAgent(safe_config=SafeConfig())
        mesh = SecurityMeshOrchestrator(
            agents=[network_agent, dns_agent, supply_chain_agent],
            safe_agent=safe_agent
        )

        # Generate attack observations
        simulator = TrafficSimulator(seed=42)
        observations = {
            "network": simulator.generate_aisuru_ddos_traffic(
                duration_seconds=10,
                attack_pps=150000,
                botnet_size=5000
            ),
            "dns": DNSObservation(
                domain="targetdomain.com",
                qps=8000.0,
                unique_client_ips=3000,
                asn_distribution={"AS6666": 2100, "AS7777": 600},
                query_types={"A": 7500, "AAAA": 400},
                http_traffic_ratio=0.05
            ),
            "supply_chain": SupplyChainObservation(
                release_id="v2.0.0_COMPROMISED",
                version="2.0.0",
                signing_key_id="KEY_UNKNOWN_999",
                build_host="suspicious-builder.external.com",
                rollout_speed=25000.0,
                total_devices_updated=45000,
                deployment_duration_hours=1.8,
                post_release_traffic_multiplier=12.0,
                is_known_signing_key=False,
                build_host_reputation="suspicious",
                device_behavior_anomalies=8000
            )
        }

        # Run mesh analysis
        result = mesh.run_end_to_end(observations)

        # Should detect attacks in all domains
        assert result['summary']['attacks_detected'] >= 2
        assert result['summary']['global_severity'] in ['high', 'critical']
        assert len(result['summary']['affected_domains']) >= 2

        # Global plan should exist
        global_plan = result['global_plan']
        assert global_plan.severity in [Severity.HIGH, Severity.CRITICAL]
        assert global_plan.action_count() > 0


@pytest.mark.integration
class TestIntegrationMesh:
    """Integration tests for the full mesh."""

    def test_end_to_end_mesh_workflow(self):
        """Test complete end-to-end mesh workflow."""
        # This is a comprehensive integration test
        network_agent = DDoSSentinelAgent(sensitivity=0.8)
        dns_agent = DNSIntegrityAgent(sensitivity=0.8)
        supply_chain_agent = SupplyChainGuardianAgent(sensitivity=0.8)

        safe_agent = SafeDeepAgent(safe_config=SafeConfig())
        mesh = SecurityMeshOrchestrator(
            agents=[network_agent, dns_agent, supply_chain_agent],
            safe_agent=safe_agent
        )

        # Test multiple scenarios
        scenarios = ['clean', 'network_only', 'multi_domain']

        for scenario_name in scenarios:
            # Generate appropriate observations
            if scenario_name == 'clean':
                simulator = TrafficSimulator(seed=42)
                observations = {
                    "network": simulator.generate_normal_traffic(10, 1000),
                    "dns": DNSObservation(
                        domain="example.com", qps=50.0, unique_client_ips=30,
                        asn_distribution={"AS1234": 15}, query_types={"A": 25},
                        http_traffic_ratio=0.8
                    ),
                    "supply_chain": SupplyChainObservation(
                        release_id="v1.0.0", version="1.0.0",
                        signing_key_id="KEY_PROD_001",
                        build_host="build-server-01.company.com",
                        rollout_speed=800.0, total_devices_updated=5000,
                        deployment_duration_hours=6.0, is_known_signing_key=True,
                        build_host_reputation="trusted"
                    )
                }
            elif scenario_name == 'network_only':
                simulator = TrafficSimulator(seed=42)
                observations = {
                    "network": simulator.generate_aisuru_ddos_traffic(10, 150000, 5000),
                    "dns": DNSObservation(
                        domain="example.com", qps=50.0, unique_client_ips=30,
                        asn_distribution={"AS1234": 15}, query_types={"A": 25},
                        http_traffic_ratio=0.8
                    ),
                    "supply_chain": SupplyChainObservation(
                        release_id="v1.0.0", version="1.0.0",
                        signing_key_id="KEY_PROD_001",
                        build_host="build-server-01.company.com",
                        rollout_speed=800.0, total_devices_updated=5000,
                        deployment_duration_hours=6.0, is_known_signing_key=True,
                        build_host_reputation="trusted"
                    )
                }
            else:  # multi_domain
                simulator = TrafficSimulator(seed=42)
                observations = {
                    "network": simulator.generate_aisuru_ddos_traffic(10, 150000, 5000),
                    "dns": DNSObservation(
                        domain="attack.com", qps=8000.0, unique_client_ips=3000,
                        asn_distribution={"AS6666": 2100}, query_types={"A": 7500},
                        http_traffic_ratio=0.05
                    ),
                    "supply_chain": SupplyChainObservation(
                        release_id="v2.0.0_BAD", version="2.0.0",
                        signing_key_id="KEY_UNKNOWN_999",
                        build_host="bad-builder.com",
                        rollout_speed=25000.0, total_devices_updated=45000,
                        deployment_duration_hours=1.8,
                        post_release_traffic_multiplier=12.0,
                        is_known_signing_key=False,
                        build_host_reputation="suspicious",
                        device_behavior_anomalies=8000
                    )
                }

            result = mesh.run_end_to_end(observations)

            # Basic validation
            assert 'per_agent_analyses' in result
            assert 'global_plan' in result
            assert 'summary' in result
            assert result['summary']['total_agents'] == 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
