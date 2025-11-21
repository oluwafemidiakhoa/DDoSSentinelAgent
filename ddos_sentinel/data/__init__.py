"""Data simulation and feature extraction layer."""

from ddos_sentinel.data.simulator import TrafficSimulator
from ddos_sentinel.data.features import TrafficFeatureExtractor

__all__ = ["TrafficSimulator", "TrafficFeatureExtractor"]
