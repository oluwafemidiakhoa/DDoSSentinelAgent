"""
Security Mesh Orchestrator - Multi-Agent Coordination.

Coordinates multiple domain-specific security agents to provide
comprehensive threat detection and unified mitigation planning.
"""

from typing import List, Dict, Any
from datetime import datetime
import structlog

from safedeepagent.core.safe_agent import SafeDeepAgent, SafeConfig
from ddos_sentinel.core.base_agent import BaseSecurityAgent, validate_agent
from ddos_sentinel.core.types import (
    Severity,
    Indicator,
    AnalysisResult,
    MitigationAction,
    MitigationPlan
)

logger = structlog.get_logger(__name__)


class SecurityMeshOrchestrator:
    """
    Multi-agent security mesh orchestrator.

    Coordinates analysis and mitigation across multiple security domains:
    - Network (DDoS detection)
    - DNS (popularity manipulation)
    - Supply chain (firmware compromise)

    Features:
    - Parallel agent analysis with SafeDeepAgent supervision
    - Cross-domain threat correlation
    - Global mitigation plan synthesis
    - Escalation management
    """

    def __init__(
        self,
        agents: List[BaseSecurityAgent],
        safe_agent: SafeDeepAgent
    ):
        """
        Initialize the security mesh orchestrator.

        Args:
            agents: List of domain-specific security agents
            safe_agent: Shared SafeDeepAgent for orchestration-level actions

        Raises:
            TypeError: If any agent doesn't implement BaseSecurityAgent interface
        """
        # Validate all agents
        for agent in agents:
            validate_agent(agent)

        self.agents = agents
        self.safe_agent = safe_agent
        self.agent_by_domain = {agent.domain: agent for agent in agents}

        logger.info(
            "SecurityMeshOrchestrator initialized",
            agent_count=len(agents),
            domains=[agent.domain for agent in agents]
        )

    def analyze_all(
        self,
        observations: Dict[str, Any]
    ) -> List[AnalysisResult]:
        """
        Run analysis across all agents with provided observations.

        Args:
            observations: Dictionary mapping domain -> observation
                Example: {
                    "network": List[TrafficPacket],
                    "dns": DNSObservation,
                    "supply_chain": SupplyChainObservation
                }

        Returns:
            List of AnalysisResults from all agents

        Note:
            Each agent's analyze() is already routed through SafeDeepAgent,
            but we also wrap the orchestration itself in SafeDeepAgent for
            meta-supervision.
        """
        logger.info(
            "Starting mesh-wide analysis",
            domains=list(observations.keys())
        )

        # Orchestration-level safety check
        result = self.safe_agent.execute_safe_action({
            'tool': 'mesh_analyze_all',
            'parameters': {
                'domains': list(observations.keys()),
                'timestamp': datetime.now().isoformat()
            }
        })

        if not result.allowed:
            logger.error(
                "Mesh analysis blocked by meta-supervision",
                blocked_by=result.blocked_by
            )
            # Return empty results if blocked
            return []

        # Run analysis for each agent that has an observation
        analysis_results = []

        for agent in self.agents:
            domain = agent.domain
            if domain not in observations:
                logger.debug(
                    "No observation for agent domain, skipping",
                    agent_name=agent.name,
                    domain=domain
                )
                continue

            observation = observations[domain]

            try:
                logger.info(
                    "Running agent analysis",
                    agent_name=agent.name,
                    domain=domain
                )

                # Call agent's analyze method (already SafeDeepAgent-wrapped)
                analysis = agent.analyze(observation)
                analysis_results.append(analysis)

                logger.info(
                    "Agent analysis complete",
                    agent_name=agent.name,
                    domain=domain,
                    attack_detected=analysis.attack_detected,
                    severity=analysis.severity.value
                )

            except Exception as e:
                logger.error(
                    "Agent analysis failed",
                    agent_name=agent.name,
                    domain=domain,
                    error=str(e)
                )
                # Create error result
                analysis_results.append(AnalysisResult(
                    domain=domain,
                    attack_detected=False,
                    severity=Severity.NONE,
                    confidence=0.0,
                    notes=f"Analysis failed: {str(e)}"
                ))

        logger.info(
            "Mesh-wide analysis complete",
            total_results=len(analysis_results),
            attacks_detected=sum(1 for r in analysis_results if r.attack_detected)
        )

        return analysis_results

    def build_global_plan(
        self,
        results: List[AnalysisResult]
    ) -> MitigationPlan:
        """
        Build a global mitigation plan by fusing results from all agents.

        Args:
            results: List of AnalysisResults from analyze_all()

        Returns:
            Global MitigationPlan for the entire mesh
        """
        logger.info(
            "Building global mitigation plan",
            result_count=len(results)
        )

        # Orchestration-level safety check
        safe_result = self.safe_agent.execute_safe_action({
            'tool': 'mesh_build_global_plan',
            'parameters': {
                'result_count': len(results),
                'timestamp': datetime.now().isoformat()
            }
        })

        if not safe_result.allowed:
            logger.error(
                "Global plan generation blocked by meta-supervision",
                blocked_by=safe_result.blocked_by
            )
            return MitigationPlan(
                domain="mesh",
                severity=Severity.NONE,
                estimated_impact="Plan generation blocked by security layer",
                recommended_response_time="N/A"
            )

        # Filter to attacks only
        attack_results = [r for r in results if r.attack_detected]

        if not attack_results:
            logger.info("No attacks detected across mesh")
            return MitigationPlan(
                domain="mesh",
                severity=Severity.NONE,
                estimated_impact="No threats detected",
                recommended_response_time="N/A"
            )

        # Determine global severity (max across all domains)
        global_severity = max(r.severity for r in attack_results)

        # Collect all indicators
        all_indicators = []
        for result in attack_results:
            all_indicators.extend(result.indicators)

        # Generate per-agent mitigation plans
        immediate_actions = []
        follow_up_actions = []

        for result in attack_results:
            # Find the agent for this domain
            agent = self.agent_by_domain.get(result.domain)
            if agent:
                try:
                    plan = agent.propose_mitigation(result)
                    immediate_actions.extend(plan.immediate_actions)
                    follow_up_actions.extend(plan.follow_up_actions)
                except Exception as e:
                    logger.error(
                        "Failed to generate mitigation plan for agent",
                        domain=result.domain,
                        error=str(e)
                    )

        # Add global meta-actions based on severity and attack spread
        affected_domains = [r.domain for r in attack_results]

        if global_severity == Severity.CRITICAL:
            immediate_actions.insert(0, MitigationAction(
                description="ESCALATE TO HUMAN: Critical multi-domain security event",
                target="security_operations_center",
                action_type="escalate",
                parameters={
                    "severity": "critical",
                    "affected_domains": affected_domains
                },
                priority=10
            ))

        if len(affected_domains) >= 2:
            # Multi-domain attack: likely coordinated
            immediate_actions.insert(0, MitigationAction(
                description=f"ALERT: Coordinated multi-domain attack detected "
                           f"({', '.join(affected_domains)})",
                target="security_operations_center",
                action_type="alert",
                parameters={
                    "attack_type": "coordinated",
                    "domains": affected_domains
                },
                priority=9
            ))

            follow_up_actions.append(MitigationAction(
                description="Conduct cross-domain threat correlation analysis",
                target="threat_intelligence",
                action_type="correlate",
                parameters={"domains": affected_domains},
                priority=6
            ))

        # Add mesh-level follow-up actions
        follow_up_actions.extend([
            MitigationAction(
                description="Generate comprehensive incident report across all domains",
                target="incident_response",
                action_type="report",
                priority=5
            ),
            MitigationAction(
                description="Review and update multi-domain detection rules",
                target="detection_system",
                action_type="update",
                priority=3
            ),
            MitigationAction(
                description="Conduct post-incident mesh coordination review",
                target="security_team",
                action_type="review",
                priority=2
            )
        ])

        # Deduplicate actions
        seen_immediate = set()
        deduplicated_immediate = []
        for action in immediate_actions:
            key = (action.description, action.target, action.action_type)
            if key not in seen_immediate:
                seen_immediate.add(key)
                deduplicated_immediate.append(action)

        seen_follow_up = set()
        deduplicated_follow_up = []
        for action in follow_up_actions:
            key = (action.description, action.target, action.action_type)
            if key not in seen_follow_up:
                seen_follow_up.add(key)
                deduplicated_follow_up.append(action)

        # Generate global impact assessment
        impact_parts = []
        for result in attack_results:
            impact_parts.append(f"[{result.domain}] {result.notes.split(chr(10))[0]}")

        estimated_impact = "\n".join(impact_parts)

        # Determine response time (use most urgent)
        response_time_map = {
            Severity.CRITICAL: "Immediate (< 5 minutes)",
            Severity.HIGH: "Urgent (< 15 minutes)",
            Severity.MEDIUM: "Priority (< 1 hour)",
            Severity.LOW: "Standard (< 4 hours)",
            Severity.NONE: "N/A"
        }
        recommended_response_time = response_time_map[global_severity]

        global_plan = MitigationPlan(
            domain="mesh",
            severity=global_severity,
            immediate_actions=deduplicated_immediate,
            follow_up_actions=deduplicated_follow_up,
            estimated_impact=estimated_impact,
            recommended_response_time=recommended_response_time
        )

        logger.info(
            "Global mitigation plan generated",
            severity=global_severity.value,
            affected_domains=affected_domains,
            total_actions=global_plan.action_count()
        )

        return global_plan

    def run_end_to_end(
        self,
        observations: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Run complete end-to-end analysis and mitigation planning.

        Args:
            observations: Dictionary mapping domain -> observation

        Returns:
            Dictionary containing:
                - per_agent_analyses: List[AnalysisResult]
                - global_plan: MitigationPlan
                - summary: Dict with high-level stats
        """
        logger.info("Starting end-to-end mesh analysis and planning")

        # Run analysis across all agents
        analyses = self.analyze_all(observations)

        # Build global mitigation plan
        global_plan = self.build_global_plan(analyses)

        # Generate summary
        attack_analyses = [a for a in analyses if a.attack_detected]
        summary = {
            "total_agents": len(self.agents),
            "agents_analyzed": len(analyses),
            "attacks_detected": len(attack_analyses),
            "affected_domains": [a.domain for a in attack_analyses],
            "global_severity": global_plan.severity.value,
            "total_mitigation_actions": global_plan.action_count(),
            "recommended_response_time": global_plan.recommended_response_time
        }

        logger.info(
            "End-to-end analysis complete",
            summary=summary
        )

        return {
            "per_agent_analyses": analyses,
            "global_plan": global_plan,
            "summary": summary
        }

    def get_agent_by_domain(self, domain: str) -> BaseSecurityAgent:
        """
        Get a specific agent by domain name.

        Args:
            domain: Domain name (e.g., "network", "dns", "supply_chain")

        Returns:
            The agent for that domain

        Raises:
            KeyError: If domain not found
        """
        return self.agent_by_domain[domain]

    def list_domains(self) -> List[str]:
        """Get list of all managed security domains."""
        return list(self.agent_by_domain.keys())
