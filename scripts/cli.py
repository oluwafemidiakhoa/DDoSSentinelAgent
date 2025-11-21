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
from safedeepagent.core.safe_agent import SafeConfig

console = Console()


@click.group()
@click.version_option(version="0.1.0")
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
    mitigation = agent.propose_mitigation()

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


if __name__ == '__main__':
    main()
