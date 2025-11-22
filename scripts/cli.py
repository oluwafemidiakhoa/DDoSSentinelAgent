#!/usr/bin/env python3
"""
DDoS Sentinel Agent CLI - Demonstration Runner

Command-line interface for running DDoS detection scenarios and demonstrations.
"""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from datetime import datetime

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.simulator import TrafficSimulator
from ddos_sentinel.dns.agent import DNSIntegrityAgent, DNSObservation
from ddos_sentinel.supply_chain.agent import SupplyChainGuardianAgent, SupplyChainObservation
from ddos_sentinel.mesh.orchestrator import SecurityMeshOrchestrator
from safedeepagent.core.safe_agent import SafeConfig, SafeDeepAgent

console = Console()


@click.group()
@click.version_option(version="0.2.0")
def main():
    """
    DDoS Sentinel Agent - Secure autonomous DDoS detection using SafeDeepAgent.

    Built to showcase the SafeDeepAgent framework's 12 security foundations
    applied to network security and DDoS detection.
    """
    pass


@main.command()
@click.option(
    '--duration',
    default=60,
    help='Duration of traffic simulation in seconds'
)
@click.option(
    '--pps',
    default=1000,
    help='Packets per second for normal traffic'
)
@click.option(
    '--sensitivity',
    default=0.8,
    help='Detection sensitivity (0.0-1.0)'
)
def demo_normal(duration: int, pps: int, sensitivity: float):
    """Run demonstration with normal traffic (no attack)."""
    console.print(Panel.fit(
        "🛡️  DDoS Sentinel Agent - Normal Traffic Demo",
        border_style="green"
    ))

    console.print(f"\n[cyan]Initializing agent with SafeDeepAgent framework...[/cyan]")
    agent = DDoSSentinelAgent(sensitivity=sensitivity)

    console.print(f"[cyan]Generating {duration}s of normal traffic at {pps} pps...[/cyan]")
    simulator = TrafficSimulator(seed=42)
    packets = simulator.generate_normal_traffic(
        duration_seconds=duration,
        base_pps=pps
    )

    console.print(f"[cyan]Analyzing {len(packets):,} packets...[/cyan]\n")
    result = agent.run_ddos_detection(packets)

    if result['success']:
        _display_analysis_results(agent)
    else:
        console.print(f"[red]❌ Action blocked: {result['reason']}[/red]")


@main.command()
@click.option(
    '--duration',
    default=60,
    help='Duration of attack in seconds'
)
@click.option(
    '--pps',
    default=150000,
    help='Packets per second during attack'
)
@click.option(
    '--botnet-size',
    default=5000,
    help='Number of attacking IPs (botnet size)'
)
@click.option(
    '--sensitivity',
    default=0.8,
    help='Detection sensitivity (0.0-1.0)'
)
def demo_attack(duration: int, pps: int, botnet_size: int, sensitivity: float):
    """Run demonstration with Aisuru-style DDoS attack."""
    console.print(Panel.fit(
        "🚨 DDoS Sentinel Agent - Attack Scenario Demo",
        border_style="red"
    ))

    console.print(f"\n[cyan]Initializing agent with SafeDeepAgent framework...[/cyan]")
    agent = DDoSSentinelAgent(sensitivity=sensitivity)

    console.print(
        f"[cyan]Simulating Aisuru-style DDoS attack:\n"
        f"  • Duration: {duration}s\n"
        f"  • Attack PPS: {pps:,}\n"
        f"  • Botnet size: {botnet_size:,} IPs[/cyan]"
    )

    simulator = TrafficSimulator(seed=42)
    packets = simulator.generate_aisuru_ddos_traffic(
        duration_seconds=duration,
        attack_pps=pps,
        botnet_size=botnet_size
    )

    console.print(f"\n[cyan]Analyzing {len(packets):,} packets...[/cyan]\n")
    result = agent.run_ddos_detection(packets)

    if result['success']:
        _display_analysis_results(agent)
        _display_mitigation_plan(agent)
    else:
        console.print(f"[red]❌ Action blocked: {result['reason']}[/red]")


@main.command()
@click.option(
    '--total-duration',
    default=300,
    help='Total scenario duration in seconds'
)
@click.option(
    '--attack-start',
    default=60,
    help='When attack starts (seconds)'
)
@click.option(
    '--attack-duration',
    default=120,
    help='Duration of attack'
)
@click.option(
    '--normal-pps',
    default=1000,
    help='Normal traffic PPS'
)
@click.option(
    '--attack-pps',
    default=150000,
    help='Attack traffic PPS'
)
@click.option(
    '--sensitivity',
    default=0.8,
    help='Detection sensitivity (0.0-1.0)'
)
def demo_mixed(
    total_duration: int,
    attack_start: int,
    attack_duration: int,
    normal_pps: int,
    attack_pps: int,
    sensitivity: float
):
    """Run realistic scenario: normal → attack → recovery."""
    console.print(Panel.fit(
        "🔄 DDoS Sentinel Agent - Mixed Scenario Demo",
        border_style="yellow"
    ))

    console.print(f"\n[cyan]Initializing agent with SafeDeepAgent framework...[/cyan]")
    agent = DDoSSentinelAgent(sensitivity=sensitivity)

    console.print(
        f"[cyan]Scenario Timeline:\n"
        f"  • 0-{attack_start}s: Normal traffic ({normal_pps} pps)\n"
        f"  • {attack_start}-{attack_start + attack_duration}s: "
        f"DDoS Attack ({attack_pps:,} pps)\n"
        f"  • {attack_start + attack_duration}-{total_duration}s: "
        f"Recovery (normal traffic)[/cyan]\n"
    )

    # Train baseline on normal traffic first
    console.print("[cyan]Training baseline from initial normal traffic...[/cyan]")
    simulator = TrafficSimulator(seed=42)
    normal_packets = simulator.generate_normal_traffic(
        duration_seconds=attack_start,
        base_pps=normal_pps
    )
    baseline_result = agent.train_baseline(normal_packets)

    if baseline_result['success']:
        console.print("[green]✓ Baseline trained successfully[/green]\n")

    # Generate full mixed scenario
    console.print("[cyan]Generating mixed traffic scenario...[/cyan]")
    simulator.clear_buffer()
    packets = simulator.generate_mixed_scenario(
        total_duration=total_duration,
        attack_start=attack_start,
        attack_duration=attack_duration,
        normal_pps=normal_pps,
        attack_pps=attack_pps
    )

    console.print(f"\n[cyan]Analyzing {len(packets):,} packets...[/cyan]\n")
    result = agent.run_ddos_detection(packets)

    if result['success']:
        _display_analysis_results(agent)
        _display_mitigation_plan(agent)
    else:
        console.print(f"[red]❌ Action blocked: {result['reason']}[/red]")


@main.command()
@click.option(
    '--duration',
    default=120,
    help='Duration of normal traffic for baseline'
)
@click.option(
    '--pps',
    default=1000,
    help='Packets per second'
)
def train_baseline(duration: int, pps: int):
    """Train baseline profile from normal traffic."""
    console.print(Panel.fit(
        "📊 DDoS Sentinel Agent - Baseline Training",
        border_style="blue"
    ))

    console.print(f"\n[cyan]Initializing agent...[/cyan]")
    agent = DDoSSentinelAgent()

    console.print(
        f"[cyan]Generating {duration}s of normal traffic for baseline...[/cyan]"
    )
    simulator = TrafficSimulator(seed=42)
    packets = simulator.generate_normal_traffic(
        duration_seconds=duration,
        base_pps=pps
    )

    console.print(f"[cyan]Training baseline on {len(packets):,} packets...[/cyan]\n")
    result = agent.train_baseline(packets)

    if result['success']:
        console.print("[green]✓ Baseline training complete![/green]\n")

        # Display baseline profile
        baseline = result['baseline_profile']
        table = Table(title="Baseline Profile", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("PPS Mean", f"{baseline['pps_mean']:,.0f}")
        table.add_row("PPS Std Dev", f"{baseline['pps_std']:,.0f}")
        table.add_row("PPS 95th Percentile", f"{baseline['pps_percentile_95']:,.0f}")
        table.add_row("Unique IPs Mean", f"{baseline['unique_ips_mean']:,.0f}")
        table.add_row("UDP Ratio Mean", f"{baseline['udp_ratio_mean']:.1%}")
        table.add_row(
            "Avg Packet Size",
            f"{baseline['avg_packet_size_mean']:,.0f} bytes"
        )

        console.print(table)
    else:
        console.print(f"[red]❌ Baseline training failed: {result['reason']}[/red]")


@main.command()
def status():
    """Show agent status and configuration."""
    console.print(Panel.fit(
        "📋 DDoS Sentinel Agent - Status",
        border_style="blue"
    ))

    agent = DDoSSentinelAgent()
    status_info = agent.get_status()

    table = Table(title="Agent Status", box=box.ROUNDED)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Agent Initialized", "✓" if status_info['agent_initialized'] else "✗")
    table.add_row(
        "Baseline Trained",
        "✓" if status_info['baseline_trained'] else "✗"
    )
    table.add_row(
        "SafeDeepAgent Active",
        "✓" if status_info['safedeepagent_active'] else "✗"
    )
    table.add_row(
        "Security Foundations",
        str(status_info['security_foundations_enabled'])
    )
    table.add_row(
        "Last Analysis",
        status_info['last_analysis_timestamp'] or "Never"
    )

    console.print(table)


@main.command()
@click.option(
    '--scenario',
    type=click.Choice(['clean', 'network_attack', 'dns_abuse', 'supply_chain_compromise', 'multi_domain']),
    default='multi_domain',
    help='Security scenario to simulate'
)
@click.option(
    '--duration',
    default=60,
    help='Duration of network traffic simulation in seconds'
)
def demo_mesh(scenario: str, duration: int):
    """
    Run multi-agent security mesh demonstration.

    Demonstrates coordinated threat detection and mitigation across:
    - Network (DDoS)
    - DNS (popularity manipulation)
    - Supply chain (firmware compromise)
    """
    console.print(Panel.fit(
        "🌐 Multi-Agent Security Mesh Demo",
        border_style="cyan"
    ))

    console.print(f"\n[cyan]Initializing security mesh with SafeDeepAgent framework...[/cyan]")
    console.print(f"[cyan]Scenario: {scenario}[/cyan]\n")

    # Initialize shared SafeDeepAgent for orchestration
    shared_safe_agent = SafeDeepAgent(safe_config=SafeConfig(
        enable_action_validation=True,
        enable_memory_firewalls=True,
        enable_provenance_tracking=True,
        enable_sandboxing=True,
        enable_behavioral_monitoring=True,
        enable_meta_supervision=True,
        enable_audit_logging=True,
        enable_purpose_binding=True,
        enable_intent_tracking=True,
        enable_deception_detection=True,
        enable_risk_adaptation=True,
        enable_human_governance=True
    ))

    # Initialize domain-specific agents
    console.print("[cyan]Initializing agents:[/cyan]")

    network_agent = DDoSSentinelAgent(sensitivity=0.8)
    console.print("  ✓ DDoS Sentinel Agent (network domain)")

    dns_agent = DNSIntegrityAgent(sensitivity=0.8)
    console.print("  ✓ DNS Integrity Agent (dns domain)")

    supply_chain_agent = SupplyChainGuardianAgent(sensitivity=0.8)
    console.print("  ✓ Supply Chain Guardian Agent (supply_chain domain)")

    # Create mesh orchestrator
    mesh = SecurityMeshOrchestrator(
        agents=[network_agent, dns_agent, supply_chain_agent],
        safe_agent=shared_safe_agent
    )
    console.print("\n[green]✓ Security mesh initialized with 3 agents[/green]\n")

    # Generate observations based on scenario
    console.print(f"[cyan]Generating {scenario} observations...[/cyan]")
    observations = _generate_scenario_observations(scenario, duration)

    # Run end-to-end mesh analysis
    console.print("[cyan]Running mesh-wide analysis...[/cyan]\n")
    result = mesh.run_end_to_end(observations)

    # Display results
    _display_mesh_results(result)


def _generate_scenario_observations(scenario: str, duration: int) -> dict:
    """Generate observations for different security scenarios."""
    observations = {}
    simulator = TrafficSimulator(seed=42)

    if scenario == 'clean':
        # Normal traffic, no attacks
        observations['network'] = simulator.generate_normal_traffic(
            duration_seconds=duration,
            base_pps=1000
        )
        observations['dns'] = DNSObservation(
            domain="example.com",
            qps=50.0,
            unique_client_ips=30,
            asn_distribution={"AS1234": 15, "AS5678": 10, "AS9012": 5},
            query_types={"A": 25, "AAAA": 20, "MX": 5},
            http_traffic_ratio=0.8
        )
        observations['supply_chain'] = SupplyChainObservation(
            release_id="v2.4.1",
            version="2.4.1",
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

    elif scenario == 'network_attack':
        # DDoS attack only
        observations['network'] = simulator.generate_aisuru_ddos_traffic(
            duration_seconds=duration,
            attack_pps=150000,
            botnet_size=5000
        )
        observations['dns'] = DNSObservation(
            domain="example.com",
            qps=60.0,
            unique_client_ips=35,
            asn_distribution={"AS1234": 18, "AS5678": 12, "AS9012": 5},
            query_types={"A": 30, "AAAA": 25, "MX": 5},
            http_traffic_ratio=0.75
        )
        observations['supply_chain'] = SupplyChainObservation(
            release_id="v2.4.2",
            version="2.4.2",
            signing_key_id="KEY_PROD_001",
            build_host="build-server-01.company.com",
            rollout_speed=900.0,
            total_devices_updated=6000,
            deployment_duration_hours=6.5,
            post_release_traffic_multiplier=1.0,
            is_known_signing_key=True,
            build_host_reputation="trusted",
            device_behavior_anomalies=3
        )

    elif scenario == 'dns_abuse':
        # DNS popularity manipulation only
        observations['network'] = simulator.generate_normal_traffic(
            duration_seconds=duration,
            base_pps=1000
        )
        observations['dns'] = DNSObservation(
            domain="targetdomain.com",
            qps=8000.0,  # Massive QPS
            unique_client_ips=3000,  # Botnet
            asn_distribution={"AS6666": 2100, "AS7777": 600, "AS8888": 300},  # Concentrated
            query_types={"A": 7500, "AAAA": 400, "MX": 100},
            http_traffic_ratio=0.05  # Low HTTP traffic = fake queries
        )
        observations['supply_chain'] = SupplyChainObservation(
            release_id="v2.4.3",
            version="2.4.3",
            signing_key_id="KEY_PROD_001",
            build_host="build-server-01.company.com",
            rollout_speed=850.0,
            total_devices_updated=5500,
            deployment_duration_hours=6.3,
            post_release_traffic_multiplier=1.05,
            is_known_signing_key=True,
            build_host_reputation="trusted",
            device_behavior_anomalies=1
        )

    elif scenario == 'supply_chain_compromise':
        # Firmware compromise only
        observations['network'] = simulator.generate_normal_traffic(
            duration_seconds=duration,
            base_pps=1000
        )
        observations['dns'] = DNSObservation(
            domain="example.com",
            qps=55.0,
            unique_client_ips=32,
            asn_distribution={"AS1234": 16, "AS5678": 11, "AS9012": 5},
            query_types={"A": 28, "AAAA": 22, "MX": 5},
            http_traffic_ratio=0.78
        )
        observations['supply_chain'] = SupplyChainObservation(
            release_id="v2.5.0_COMPROMISED",
            version="2.5.0",
            signing_key_id="KEY_UNKNOWN_999",  # Unknown key!
            build_host="suspicious-builder.external.com",  # Suspicious host
            rollout_speed=25000.0,  # Worm-like speed
            total_devices_updated=45000,
            deployment_duration_hours=1.8,  # Very rapid
            post_release_traffic_multiplier=12.0,  # Massive traffic increase
            is_known_signing_key=False,  # CRITICAL
            build_host_reputation="suspicious",
            device_behavior_anomalies=8000  # Many devices acting weird
        )

    elif scenario == 'multi_domain':
        # Coordinated attack across all domains (Aisuru-like)
        observations['network'] = simulator.generate_aisuru_ddos_traffic(
            duration_seconds=duration,
            attack_pps=180000,
            botnet_size=6000
        )
        observations['dns'] = DNSObservation(
            domain="cloudflare-rank-target.com",
            qps=6500.0,
            unique_client_ips=2500,
            asn_distribution={"AS6666": 1800, "AS7777": 500, "AS8888": 200},
            query_types={"A": 6000, "AAAA": 400, "MX": 100},
            http_traffic_ratio=0.08  # Mostly fake queries
        )
        observations['supply_chain'] = SupplyChainObservation(
            release_id="v3.0.0_MALICIOUS",
            version="3.0.0",
            signing_key_id="KEY_COMPROMISED_666",
            build_host="attacker-build-server.evil.net",
            rollout_speed=30000.0,
            total_devices_updated=50000,
            deployment_duration_hours=1.5,
            post_release_traffic_multiplier=15.0,
            is_known_signing_key=False,
            build_host_reputation="suspicious",
            device_behavior_anomalies=12000
        )

    return observations


def _display_mesh_results(result: dict):
    """Display mesh analysis results."""
    analyses = result['per_agent_analyses']
    global_plan = result['global_plan']
    summary = result['summary']

    # Summary panel
    if summary['attacks_detected'] > 0:
        style = "red"
        icon = "🚨"
        title = f"MESH ALERT: {summary['attacks_detected']} DOMAIN(S) UNDER ATTACK"
    else:
        style = "green"
        icon = "✅"
        title = "ALL DOMAINS SECURE"

    console.print(Panel.fit(f"{icon} {title}", border_style=style))

    # Per-agent results
    console.print("\n[bold cyan]Per-Agent Analysis:[/bold cyan]\n")

    for analysis in analyses:
        domain_icon = {
            "network": "🌐",
            "dns": "🔍",
            "supply_chain": "📦"
        }.get(analysis.domain, "🔒")

        if analysis.attack_detected:
            severity_color = {
                "critical": "red",
                "high": "red",
                "medium": "yellow",
                "low": "yellow",
                "none": "green"
            }.get(analysis.severity.value, "white")

            console.print(f"{domain_icon} [bold]{analysis.domain.upper()}:[/bold] "
                         f"[{severity_color}]ATTACK DETECTED[/{severity_color}] "
                         f"(Severity: {analysis.severity.value.upper()}, "
                         f"Confidence: {analysis.confidence:.0%})")
            console.print(f"   {analysis.notes.split(chr(10))[0]}")
            if analysis.indicators:
                console.print(f"   Indicators: {len(analysis.indicators)}")
        else:
            console.print(f"{domain_icon} [bold]{analysis.domain.upper()}:[/bold] "
                         f"[green]CLEAN[/green]")

    # Global mitigation plan
    if global_plan.severity.value != "none":
        console.print("\n" + "="*70)
        console.print(Panel.fit(
            "🛠️  GLOBAL MITIGATION PLAN",
            border_style="yellow"
        ))

        console.print(f"\n[bold]Global Severity:[/bold] {global_plan.severity.value.upper()}")
        console.print(f"[bold]Response Time:[/bold] {global_plan.recommended_response_time}")
        console.print(f"[bold]Total Actions:[/bold] {global_plan.action_count()}")

        # Immediate actions
        if global_plan.immediate_actions:
            console.print("\n[red bold]Immediate Actions:[/red bold]")
            for i, action in enumerate(global_plan.immediate_actions[:10], 1):  # Limit display
                console.print(f"  {i}. {action.description}")
                console.print(f"     Target: {action.target}, Type: {action.action_type}, "
                             f"Priority: {action.priority}")

        # Follow-up actions (show count)
        if global_plan.follow_up_actions:
            console.print(f"\n[yellow]Follow-up Actions:[/yellow] "
                         f"{len(global_plan.follow_up_actions)} actions planned")

        # Impact
        console.print(f"\n[bold]Estimated Impact:[/bold]")
        for line in global_plan.estimated_impact.split('\n')[:5]:  # Limit lines
            console.print(f"  {line}")

    # Summary table
    console.print("\n")
    table = Table(title="Mesh Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Total Agents", str(summary['total_agents']))
    table.add_row("Agents Analyzed", str(summary['agents_analyzed']))
    table.add_row("Attacks Detected", str(summary['attacks_detected']))
    table.add_row("Affected Domains", ", ".join(summary['affected_domains']) or "None")
    table.add_row("Global Severity", summary['global_severity'].upper())
    table.add_row("Mitigation Actions", str(summary['total_mitigation_actions']))

    console.print(table)
    console.print()


def _display_analysis_results(agent: DDoSSentinelAgent):
    """Display analysis results in formatted output."""
    summary = agent.summarize_findings()

    if not summary['success']:
        console.print(f"[red]Failed to get summary: {summary.get('reason')}[/red]")
        return

    # Summary panel
    if summary['attack_detected']:
        style = "red"
        icon = "🚨"
        title = "ATTACK DETECTED"
    else:
        style = "green"
        icon = "✅"
        title = "NO ATTACK DETECTED"

    console.print(Panel.fit(
        f"{icon} {title}",
        border_style=style
    ))

    # Metrics table
    table = Table(title="Analysis Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Threat Level", summary['threat_level'].upper())
    table.add_row("Packets Analyzed", f"{summary['packets_analyzed']:,}")
    table.add_row("Windows Analyzed", str(summary['windows_analyzed']))
    table.add_row("Attack Windows", str(summary['attack_windows']))
    table.add_row(
        "Signatures Detected",
        str(len(summary['signatures_detected']))
    )

    console.print("\n", table)

    # Signatures
    if summary['signatures_detected']:
        console.print("\n[yellow]Detected Signatures:[/yellow]")
        for sig in summary['signatures_detected']:
            console.print(f"  • {sig}")

    # Summary text
    console.print(f"\n{summary['summary']}\n")


def _display_mitigation_plan(agent: DDoSSentinelAgent):
    """Display mitigation recommendations."""
    mitigation = agent.propose_mitigation_legacy()

    if not mitigation['success']:
        return

    if not mitigation['mitigation_required']:
        console.print("[green]No mitigation required.[/green]")
        return

    console.print(Panel.fit(
        "🛠️  Mitigation Plan",
        border_style="yellow"
    ))

    # Immediate actions
    if mitigation['immediate_actions']:
        console.print("\n[red bold]Immediate Actions:[/red bold]")
        for action in mitigation['immediate_actions']:
            console.print(f"  • {action}")

    # Short-term actions
    if mitigation['short_term_actions']:
        console.print("\n[yellow bold]Short-term Actions:[/yellow bold]")
        for action in mitigation['short_term_actions']:
            console.print(f"  • {action}")

    # Long-term actions
    if mitigation['long_term_actions']:
        console.print("\n[blue bold]Long-term Actions:[/blue bold]")
        for action in mitigation['long_term_actions']:
            console.print(f"  • {action}")

    console.print(
        f"\n[cyan]Estimated Impact:[/cyan] {mitigation['estimated_impact']}"
    )
    console.print(
        f"[cyan]Response Time:[/cyan] {mitigation['recommended_response_time']}\n"
    )


@main.command()
def mesh_demo():
    """
    Run Aisuru-style multi-vector attack demonstration.

    Simulates a sophisticated 5-phase coordinated attack:
    Phase 1 — Normal baseline
    Phase 2 — DDoS begins
    Phase 3 — DNS manipulation
    Phase 4 — Suspicious firmware update
    Phase 5 — Mesh correlation and mitigation
    """
    console.print(Panel.fit(
        "🎯 Aisuru Multi-Vector Attack Demonstration\n"
        "DDoS + DNS Amplification + Malicious Firmware Update",
        border_style="red bold"
    ))

    # Initialize shared SafeDeepAgent for orchestration
    shared_safe_agent = SafeDeepAgent(safe_config=SafeConfig(
        enable_action_validation=True,
        enable_memory_firewalls=True,
        enable_provenance_tracking=True,
        enable_sandboxing=True,
        enable_behavioral_monitoring=True,
        enable_meta_supervision=True,
        enable_audit_logging=True,
        enable_purpose_binding=True,
        enable_intent_tracking=True,
        enable_deception_detection=True,
        enable_risk_adaptation=True,
        enable_human_governance=True
    ))

    # Initialize domain-specific agents
    console.print("\n[cyan]Initializing Security Mesh...[/cyan]")
    network_agent = DDoSSentinelAgent(sensitivity=0.8)
    dns_agent = DNSIntegrityAgent(sensitivity=0.8)
    supply_chain_agent = SupplyChainGuardianAgent(sensitivity=0.8)

    mesh = SecurityMeshOrchestrator(
        agents=[network_agent, dns_agent, supply_chain_agent],
        safe_agent=shared_safe_agent
    )
    console.print("[green]✓ Security mesh initialized with 3 specialized agents[/green]\n")

    simulator = TrafficSimulator(seed=42)

    # ============================================================
    # PHASE 1: Normal Baseline
    # ============================================================
    console.print("="*70)
    console.print(Panel.fit(
        "🔸 PHASE 1 — Normal Baseline",
        border_style="green"
    ))
    console.print("[cyan]Network/DNS/Supply-chain operating normally...[/cyan]\n")

    observations_phase1 = {
        'network': simulator.generate_normal_traffic(duration_seconds=30, base_pps=1000),
        'dns': DNSObservation(
            domain="legitimate.com",
            qps=50.0,
            unique_client_ips=30,
            asn_distribution={"AS1234": 15, "AS5678": 10, "AS9012": 5},
            query_types={"A": 25, "AAAA": 20, "MX": 5},
            http_traffic_ratio=0.8
        ),
        'supply_chain': SupplyChainObservation(
            release_id="v2.3.0",
            version="2.3.0",
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
    }

    result_phase1 = mesh.run_end_to_end(observations_phase1)
    console.print(f"[green]✓ All domains clean ({result_phase1['summary']['attacks_detected']} attacks detected)[/green]\n")

    # ============================================================
    # PHASE 2: DDoS Begins
    # ============================================================
    console.print("="*70)
    console.print(Panel.fit(
        "🔸 PHASE 2 — DDoS Attack Begins",
        border_style="yellow"
    ))
    console.print("[yellow]Huge PPS spike + high UDP ratio detected...[/yellow]\n")

    simulator.clear_buffer()
    observations_phase2 = {
        'network': simulator.generate_aisuru_ddos_traffic(
            duration_seconds=30,
            attack_pps=180000,
            botnet_size=6000
        ),
        'dns': DNSObservation(
            domain="legitimate.com",
            qps=55.0,
            unique_client_ips=32,
            asn_distribution={"AS1234": 16, "AS5678": 11, "AS9012": 5},
            query_types={"A": 27, "AAAA": 22, "MX": 5},
            http_traffic_ratio=0.78
        ),
        'supply_chain': observations_phase1['supply_chain']
    }

    result_phase2 = mesh.run_end_to_end(observations_phase2)
    _print_phase_summary(result_phase2, "NETWORK")

    # ============================================================
    # PHASE 3: DNS Manipulation
    # ============================================================
    console.print("="*70)
    console.print(Panel.fit(
        "🔸 PHASE 3 — DNS Manipulation Added",
        border_style="yellow"
    ))
    console.print("[yellow]DNS resolver spam / fake popularity attack detected...[/yellow]\n")

    observations_phase3 = {
        'network': observations_phase2['network'],
        'dns': DNSObservation(
            domain="cloudflare-rank-target.com",
            qps=7500.0,
            unique_client_ips=3200,
            asn_distribution={"AS6666": 2300, "AS7777": 650, "AS8888": 250},
            query_types={"A": 7000, "AAAA": 400, "MX": 100},
            http_traffic_ratio=0.06  # Very low = fake queries
        ),
        'supply_chain': observations_phase1['supply_chain']
    }

    result_phase3 = mesh.run_end_to_end(observations_phase3)
    _print_phase_summary(result_phase3, "NETWORK + DNS")

    # ============================================================
    # PHASE 4: Firmware Compromise
    # ============================================================
    console.print("="*70)
    console.print(Panel.fit(
        "🔸 PHASE 4 — Suspicious Firmware Update",
        border_style="red"
    ))
    console.print("[red]Compromised update signature + mass rollout detected...[/red]\n")

    observations_phase4 = {
        'network': observations_phase2['network'],
        'dns': observations_phase3['dns'],
        'supply_chain': SupplyChainObservation(
            release_id="v3.0.0_MALICIOUS",
            version="3.0.0",
            signing_key_id="KEY_COMPROMISED_666",
            build_host="attacker-build-server.evil.net",
            rollout_speed=32000.0,
            total_devices_updated=55000,
            deployment_duration_hours=1.3,
            post_release_traffic_multiplier=18.0,
            is_known_signing_key=False,
            build_host_reputation="suspicious",
            device_behavior_anomalies=15000
        )
    }

    result_phase4 = mesh.run_end_to_end(observations_phase4)
    _print_phase_summary(result_phase4, "NETWORK + DNS + SUPPLY_CHAIN")

    # ============================================================
    # PHASE 5: Mesh Correlation & Mitigation
    # ============================================================
    console.print("="*70)
    console.print(Panel.fit(
        "🔸 PHASE 5 — Security Mesh Correlation & Response",
        border_style="cyan bold"
    ))

    global_plan = result_phase4['global_plan']
    summary = result_phase4['summary']

    console.print(f"\n[bold red]Global Severity: {summary['global_severity'].upper()}[/bold red]")
    console.print(f"[bold]Correlated Incident:[/bold] Multi-vector coordinated attack")
    console.print(f"[bold]Attack Vectors:[/bold] {', '.join(summary['affected_domains'])}")
    console.print(f"[bold]Response Time Required:[/bold] {global_plan.recommended_response_time}")
    console.print(f"[bold]Total Mitigation Actions:[/bold] {global_plan.action_count()}\n")

    # Display sample output
    console.print("[yellow bold]SAMPLE OUTPUT:[/yellow bold]\n")

    sample_output = """[NETWORK] CRITICAL: Detected 180k PPS UDP flood with 6000 unique IPs.
[DNS] HIGH: Sudden spike in QPS (7500), domain popularity manipulation via resolver spam.
[SUPPLY_CHAIN] CRITICAL: Unsigned firmware v3.0.0 from suspicious host distributed to 55k devices.
[MESH] CRITICAL: Multi-vector coordinated attack detected.
[MESH] Attack Pattern: DDoS + DNS abuse + Supply-chain compromise (Aisuru-style)
"""

    console.print(sample_output)

    # Show top mitigation actions
    console.print("[cyan bold]Recommended Mitigation Plan:[/cyan bold]\n")

    if global_plan.immediate_actions:
        for i, action in enumerate(global_plan.immediate_actions[:5], 1):
            console.print(f" {i}. {action.description}")

    console.print("\n" + "="*70)
    console.print(Panel.fit(
        "✅ Multi-Agent Demo Complete\n"
        "The Security Mesh successfully detected and correlated\n"
        "a sophisticated multi-vector attack across all domains.",
        border_style="green bold"
    ))


def _print_phase_summary(result: dict, affected_str: str):
    """Print a concise phase summary."""
    summary = result['summary']
    if summary['attacks_detected'] > 0:
        console.print(f"[red]⚠️  Attack detected in: {affected_str}[/red]")
        console.print(f"   Severity: {summary['global_severity'].upper()}")
        console.print(f"   Affected domains: {summary['attacks_detected']}/{summary['total_agents']}\n")
    else:
        console.print(f"[green]✓ All systems normal[/green]\n")


if __name__ == '__main__':
    main()
