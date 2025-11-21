"""
Feature extraction from network traffic data.

Computes aggregated metrics and features used for DDoS detection.
"""

from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import numpy as np
from ddos_sentinel.data.simulator import TrafficPacket, TrafficMetrics


class TrafficFeatureExtractor:
    """
    Extracts features from network traffic for DDoS detection.

    Computes time-windowed aggregations and statistical features that
    characterize traffic patterns.
    """

    def __init__(self, window_size_seconds: int = 10):
        """
        Initialize the feature extractor.

        Args:
            window_size_seconds: Time window for aggregating metrics
        """
        self.window_size = timedelta(seconds=window_size_seconds)

    def extract_metrics(self, packets: List[TrafficPacket]) -> List[TrafficMetrics]:
        """
        Extract aggregated metrics from a list of packets.

        Args:
            packets: List of traffic packets to analyze

        Returns:
            List of TrafficMetrics for each time window
        """
        if not packets:
            return []

        # Sort packets by timestamp
        sorted_packets = sorted(packets, key=lambda p: p.timestamp)

        metrics = []
        window_start = sorted_packets[0].timestamp
        window_end = window_start + self.window_size
        window_packets = []

        for packet in sorted_packets:
            if packet.timestamp < window_end:
                window_packets.append(packet)
            else:
                # Process completed window
                if window_packets:
                    metric = self._compute_window_metrics(
                        window_packets,
                        window_start
                    )
                    metrics.append(metric)

                # Start new window
                window_start = window_end
                window_end = window_start + self.window_size
                window_packets = [packet]

        # Process final window
        if window_packets:
            metric = self._compute_window_metrics(window_packets, window_start)
            metrics.append(metric)

        return metrics

    def _compute_window_metrics(
        self,
        packets: List[TrafficPacket],
        window_start: datetime
    ) -> TrafficMetrics:
        """
        Compute metrics for a single time window.

        Args:
            packets: Packets in this window
            window_start: Start timestamp of window

        Returns:
            TrafficMetrics for this window
        """
        total_packets = len(packets)
        total_bytes = sum(p.packet_size for p in packets)

        # Compute rates (per second)
        window_duration = self.window_size.total_seconds()
        pps = total_packets / window_duration
        bps = total_bytes / window_duration

        # Count unique IPs
        unique_sources = len(set(p.source_ip for p in packets))
        unique_dests = len(set(p.dest_ip for p in packets))

        # Protocol distribution
        protocol_counts = Counter(p.protocol for p in packets)
        udp_count = protocol_counts.get("UDP", 0)
        tcp_count = protocol_counts.get("TCP", 0)

        udp_ratio = udp_count / total_packets if total_packets > 0 else 0.0
        tcp_ratio = tcp_count / total_packets if total_packets > 0 else 0.0

        # Average packet size
        avg_size = total_bytes / total_packets if total_packets > 0 else 0.0

        return TrafficMetrics(
            timestamp=window_start,
            total_packets=total_packets,
            total_bytes=total_bytes,
            packets_per_second=pps,
            bytes_per_second=bps,
            unique_source_ips=unique_sources,
            unique_dest_ips=unique_dests,
            udp_ratio=udp_ratio,
            tcp_ratio=tcp_ratio,
            avg_packet_size=avg_size,
            protocol_distribution=dict(protocol_counts)
        )

    def extract_advanced_features(
        self,
        packets: List[TrafficPacket]
    ) -> Dict[str, Any]:
        """
        Extract advanced statistical features for anomaly detection.

        Args:
            packets: List of traffic packets

        Returns:
            Dictionary of advanced features
        """
        if not packets:
            return {}

        # IP-based features
        source_ips = [p.source_ip for p in packets]
        dest_ips = [p.dest_ip for p in packets]
        source_ip_counts = Counter(source_ips)
        dest_ip_counts = Counter(dest_ips)

        # Port-based features
        dest_ports = [p.dest_port for p in packets]
        dest_port_counts = Counter(dest_ports)

        # Temporal features
        timestamps = [p.timestamp for p in packets]
        if len(timestamps) > 1:
            time_diffs = [
                (timestamps[i+1] - timestamps[i]).total_seconds()
                for i in range(len(timestamps) - 1)
            ]
            inter_arrival_mean = np.mean(time_diffs)
            inter_arrival_std = np.std(time_diffs)
        else:
            inter_arrival_mean = 0.0
            inter_arrival_std = 0.0

        # Packet size statistics
        packet_sizes = [p.packet_size for p in packets]

        features = {
            # IP diversity metrics
            "unique_source_ips": len(source_ip_counts),
            "unique_dest_ips": len(dest_ip_counts),
            "source_ip_entropy": self._compute_entropy(source_ip_counts),
            "dest_ip_entropy": self._compute_entropy(dest_ip_counts),
            "max_source_ip_freq": max(source_ip_counts.values()) if source_ip_counts else 0,
            "max_dest_ip_freq": max(dest_ip_counts.values()) if dest_ip_counts else 0,

            # Port metrics
            "unique_dest_ports": len(dest_port_counts),
            "dest_port_entropy": self._compute_entropy(dest_port_counts),

            # Protocol metrics
            "protocol_distribution": dict(Counter(p.protocol for p in packets)),

            # Temporal metrics
            "inter_arrival_mean": inter_arrival_mean,
            "inter_arrival_std": inter_arrival_std,

            # Packet size metrics
            "avg_packet_size": np.mean(packet_sizes),
            "std_packet_size": np.std(packet_sizes),
            "min_packet_size": min(packet_sizes),
            "max_packet_size": max(packet_sizes),

            # Volume metrics
            "total_packets": len(packets),
            "total_bytes": sum(packet_sizes),
        }

        return features

    def _compute_entropy(self, counter: Counter) -> float:
        """
        Compute Shannon entropy of a distribution.

        Args:
            counter: Counter object with frequencies

        Returns:
            Entropy value
        """
        if not counter:
            return 0.0

        total = sum(counter.values())
        probabilities = [count / total for count in counter.values()]

        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        return entropy

    def compute_baseline_profile(
        self,
        normal_packets: List[TrafficPacket]
    ) -> Dict[str, Any]:
        """
        Compute a baseline profile from normal traffic.

        This profile can be used to detect anomalies by comparing
        against current traffic patterns.

        Args:
            normal_packets: Packets representing normal traffic

        Returns:
            Baseline profile dictionary
        """
        metrics = self.extract_metrics(normal_packets)

        if not metrics:
            return {}

        # Compute statistics across all windows
        pps_values = [m.packets_per_second for m in metrics]
        unique_src_values = [m.unique_source_ips for m in metrics]
        udp_ratio_values = [m.udp_ratio for m in metrics]
        avg_size_values = [m.avg_packet_size for m in metrics]

        baseline = {
            "pps_mean": np.mean(pps_values),
            "pps_std": np.std(pps_values),
            "pps_percentile_95": np.percentile(pps_values, 95),

            "unique_ips_mean": np.mean(unique_src_values),
            "unique_ips_std": np.std(unique_src_values),
            "unique_ips_percentile_95": np.percentile(unique_src_values, 95),

            "udp_ratio_mean": np.mean(udp_ratio_values),
            "udp_ratio_std": np.std(udp_ratio_values),

            "avg_packet_size_mean": np.mean(avg_size_values),
            "avg_packet_size_std": np.std(avg_size_values),
        }

        return baseline
