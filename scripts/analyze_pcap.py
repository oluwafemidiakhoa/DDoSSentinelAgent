#!/usr/bin/env python3
"""
Demo: Analyze real PCAP file for DDoS attacks.

This script demonstrates analyzing actual captured network traffic.
"""

import click
from rich.console import Console
from rich.panel import Panel

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.pcap_ingestion import PCAPIngestion

console = Console()


@click.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--max-packets', type=int, help='Maximum packets to analyze')
@click.option('--sensitivity', default=0.8, help='Detection sensitivity')
@click.option('--train-baseline', is_flag=True, help='Use this PCAP as baseline')
def main(pcap_file, max_packets, sensitivity, train_baseline):
    """Analyze a PCAP file for DDoS attacks."""

    console.print(Panel.fit(
        "📁 DDoS Sentinel - PCAP Analysis",
        border_style="cyan"
    ))

    # Load PCAP
    console.print(f"\n[cyan]Loading PCAP: {pcap_file}[/cyan]")

    try:
        ingestion = PCAPIngestion()

        # Get stats first
        stats = ingestion.get_pcap_stats(pcap_file)
        console.print(f"[cyan]File size: {stats['filesize_mb']:.2f} MB[/cyan]")

        # Load packets
        packets = ingestion.read_pcap(pcap_file, max_packets=max_packets)
        console.print(f"[green]✓ Loaded {len(packets):,} packets[/green]\n")

    except Exception as e:
        console.print(f"[red]✗ Failed to load PCAP: {e}[/red]")
        return

    # Initialize agent
    agent = DDoSSentinelAgent(sensitivity=sensitivity)

    if train_baseline:
        console.print("[cyan]Training baseline from this traffic...[/cyan]")
        result = agent.train_baseline(packets)
        if result['success']:
            console.print("[green]✓ Baseline trained[/green]\n")

    # Analyze
    console.print("[cyan]Analyzing traffic...[/cyan]")
    result = agent.run_ddos_detection(packets)

    if not result['success']:
        console.print(f"[red]✗ Analysis failed: {result.get('reason')}[/red]")
        return

    # Display results
    summary = agent.summarize_findings()

    if summary['attack_detected']:
        console.print("\n[red bold]🚨 ATTACK DETECTED[/red bold]\n")
        console.print(f"Threat Level: [red]{summary['threat_level'].upper()}[/red]")
        console.print(f"\nSignatures detected:")
        for sig in summary['signatures_detected']:
            console.print(f"  • {sig}")

        # Show mitigation
        mitigation = agent.propose_mitigation()
        if mitigation['immediate_actions']:
            console.print(f"\n[yellow]Immediate Actions:[/yellow]")
            for action in mitigation['immediate_actions']:
                console.print(f"  • {action}")
    else:
        console.print("\n[green]✓ No attack detected - traffic appears normal[/green]")

    console.print(f"\n{summary['summary']}\n")


if __name__ == '__main__':
    main()
