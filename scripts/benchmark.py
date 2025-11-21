#!/usr/bin/env python3
"""
Benchmark DDoS detection performance.

Measures throughput, latency, and resource usage under various workloads.
"""

import time
import click
from rich.console import Console
from rich.table import Table
from rich import box
import psutil
import os

from ddos_sentinel.agent.sentinel import DDoSSentinelAgent
from ddos_sentinel.data.simulator import TrafficSimulator

console = Console()


@click.group()
def main():
    """Benchmark DDoS Sentinel Agent performance."""
    pass


@main.command()
@click.option('--packets', default=100000, help='Number of packets to generate')
@click.option('--runs', default=5, help='Number of benchmark runs')
def throughput(packets, runs):
    """Benchmark packet processing throughput."""
    console.print(f"\n[cyan]Benchmarking throughput with {packets:,} packets...[/cyan]\n")

    simulator = TrafficSimulator(seed=42)
    agent = DDoSSentinelAgent()

    times = []
    process = psutil.Process(os.getpid())

    for run in range(runs):
        console.print(f"Run {run + 1}/{runs}... ", end="")

        # Generate traffic
        test_packets = simulator.generate_normal_traffic(
            duration_seconds=10,
            base_pps=packets // 10
        )

        # Measure detection time
        mem_before = process.memory_info().rss / 1024 / 1024  # MB

        start = time.time()
        result = agent.run_ddos_detection(test_packets)
        elapsed = time.time() - start

        mem_after = process.memory_info().rss / 1024 / 1024  # MB

        times.append(elapsed)

        pps = len(test_packets) / elapsed
        console.print(
            f"[green]{pps:,.0f} packets/sec "
            f"({elapsed:.3f}s, Δmem: {mem_after - mem_before:.1f} MB)[/green]"
        )

        simulator.clear_buffer()

    # Statistics
    avg_time = sum(times) / len(times)
    avg_pps = packets / avg_time
    min_pps = packets / max(times)
    max_pps = packets / min(times)

    console.print(f"\n[bold]Results:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Average Throughput", f"{avg_pps:,.0f} packets/sec")
    table.add_row("Min Throughput", f"{min_pps:,.0f} packets/sec")
    table.add_row("Max Throughput", f"{max_pps:,.0f} packets/sec")
    table.add_row("Average Latency", f"{avg_time:.3f} seconds")

    console.print(table)
    console.print()


@main.command()
@click.option('--window-size', default=10, help='Window size in seconds')
@click.option('--samples', default=100, help='Number of windows to test')
def latency(window_size, samples):
    """Benchmark detection latency per time window."""
    console.print(
        f"\n[cyan]Benchmarking latency for {samples} windows "
        f"({window_size}s each)...[/cyan]\n"
    )

    simulator = TrafficSimulator(seed=42)
    agent = DDoSSentinelAgent(window_size_seconds=window_size)

    latencies = []

    for i in range(samples):
        if i % 10 == 0:
            console.print(f"Processing window {i + 1}/{samples}...")

        # Generate one window of traffic
        packets = simulator.generate_normal_traffic(
            duration_seconds=window_size,
            base_pps=1000
        )

        # Measure detection latency
        start = time.time()
        result = agent.run_ddos_detection(packets)
        elapsed = time.time() - start

        latencies.append(elapsed)
        simulator.clear_buffer()

    # Statistics
    avg_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)
    p95_latency = sorted(latencies)[int(len(latencies) * 0.95)]
    p99_latency = sorted(latencies)[int(len(latencies) * 0.99)]

    console.print(f"\n[bold]Latency Results:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Average", f"{avg_latency * 1000:.2f} ms")
    table.add_row("Minimum", f"{min_latency * 1000:.2f} ms")
    table.add_row("Maximum", f"{max_latency * 1000:.2f} ms")
    table.add_row("95th Percentile", f"{p95_latency * 1000:.2f} ms")
    table.add_row("99th Percentile", f"{p99_latency * 1000:.2f} ms")

    console.print(table)
    console.print()


@main.command()
@click.option('--duration', default=60, help='Test duration in seconds')
@click.option('--pps', default=10000, help='Packets per second')
def memory(duration, pps):
    """Benchmark memory usage over time."""
    console.print(
        f"\n[cyan]Benchmarking memory usage for {duration}s "
        f"at {pps:,} pps...[/cyan]\n"
    )

    simulator = TrafficSimulator(seed=42)
    agent = DDoSSentinelAgent()
    process = psutil.Process(os.getpid())

    mem_samples = []
    start_time = time.time()

    while time.time() - start_time < duration:
        # Generate and analyze traffic
        packets = simulator.generate_normal_traffic(
            duration_seconds=1,
            base_pps=pps
        )

        agent.run_ddos_detection(packets)

        # Sample memory
        mem_mb = process.memory_info().rss / 1024 / 1024
        mem_samples.append(mem_mb)

        simulator.clear_buffer()

        if len(mem_samples) % 10 == 0:
            console.print(f"Memory: {mem_mb:.1f} MB")

    # Statistics
    avg_mem = sum(mem_samples) / len(mem_samples)
    min_mem = min(mem_samples)
    max_mem = max(mem_samples)
    mem_growth = max_mem - min_mem

    console.print(f"\n[bold]Memory Usage:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Average", f"{avg_mem:.1f} MB")
    table.add_row("Minimum", f"{min_mem:.1f} MB")
    table.add_row("Maximum", f"{max_mem:.1f} MB")
    table.add_row("Growth", f"{mem_growth:.1f} MB")
    table.add_row("Leak Detection", "PASS" if mem_growth < 100 else "WARN")

    console.print(table)
    console.print()


@main.command()
def detection_accuracy():
    """Benchmark detection accuracy (TPR/FPR)."""
    console.print("\n[cyan]Benchmarking detection accuracy...[/cyan]\n")

    simulator = TrafficSimulator(seed=42)
    agent = DDoSSentinelAgent()

    # Test 1: Normal traffic (should NOT detect)
    console.print("Testing false positive rate on normal traffic...")
    false_positives = 0
    normal_tests = 20

    for i in range(normal_tests):
        packets = simulator.generate_normal_traffic(
            duration_seconds=10,
            base_pps=1000
        )
        result = agent.run_ddos_detection(packets)

        if result['analysis'].attack_detected:
            false_positives += 1

        simulator.clear_buffer()

    fpr = false_positives / normal_tests

    # Test 2: Attack traffic (should detect)
    console.print("Testing true positive rate on attack traffic...")
    true_positives = 0
    attack_tests = 20

    for i in range(attack_tests):
        packets = simulator.generate_aisuru_ddos_traffic(
            duration_seconds=5,
            attack_pps=150000
        )
        result = agent.run_ddos_detection(packets)

        if result['analysis'].attack_detected:
            true_positives += 1

        simulator.clear_buffer()

    tpr = true_positives / attack_tests

    # Results
    console.print(f"\n[bold]Detection Accuracy:[/bold]")
    table = Table(box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Status", style="yellow")

    table.add_row(
        "True Positive Rate",
        f"{tpr:.1%}",
        "✓" if tpr > 0.95 else "⚠"
    )
    table.add_row(
        "False Positive Rate",
        f"{fpr:.1%}",
        "✓" if fpr < 0.05 else "⚠"
    )
    table.add_row(
        "True Negatives",
        f"{normal_tests - false_positives}/{normal_tests}",
        ""
    )
    table.add_row(
        "True Positives",
        f"{true_positives}/{attack_tests}",
        ""
    )

    console.print(table)
    console.print()


@main.command()
def full():
    """Run all benchmarks."""
    console.print("\n[bold cyan]Running Full Benchmark Suite[/bold cyan]\n")

    from click.testing import CliRunner
    runner = CliRunner()

    runner.invoke(throughput, ['--packets', '50000', '--runs', '3'])
    runner.invoke(latency, ['--samples', '50'])
    runner.invoke(detection_accuracy)

    console.print("[bold green]✓ All benchmarks complete[/bold green]\n")


if __name__ == '__main__':
    main()
