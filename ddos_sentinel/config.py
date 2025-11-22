"""
Configuration management for DDoS Sentinel Agent.

Supports loading from YAML files, environment variables, and defaults.
"""

from typing import Optional, Dict, Any
from pathlib import Path
from pydantic import BaseModel, Field, validator
import os
import yaml


class ThresholdConfig(BaseModel):
    """Detection threshold configuration."""

    pps_warning: int = Field(50000, description="Warning threshold for PPS")
    pps_critical: int = Field(100000, description="Critical threshold for PPS")

    udp_ratio_suspicious: float = Field(0.80, ge=0.0, le=1.0)
    udp_ratio_critical: float = Field(0.95, ge=0.0, le=1.0)

    unique_ips_warning: int = Field(1000, description="Warning threshold for unique IPs")
    unique_ips_critical: int = Field(3000, description="Critical threshold for unique IPs")

    avg_packet_size_suspicious: int = Field(300, description="Suspicious avg packet size (bytes)")

    @validator('udp_ratio_critical')
    def critical_greater_than_suspicious(cls, v, values):
        """Ensure critical threshold is greater than suspicious."""
        if 'udp_ratio_suspicious' in values and v <= values['udp_ratio_suspicious']:
            raise ValueError('critical threshold must be > suspicious threshold')
        return v


class DetectionConfig(BaseModel):
    """Detection engine configuration."""

    window_size_seconds: int = Field(10, gt=0, description="Time window for aggregation")
    sensitivity: float = Field(0.8, ge=0.0, le=1.0, description="Detection sensitivity")
    enable_baseline: bool = Field(True, description="Enable baseline learning")
    enable_advanced_features: bool = Field(True, description="Compute advanced features")

    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)


class IngestionConfig(BaseModel):
    """Traffic ingestion configuration."""

    max_packet_buffer_size: int = Field(100000, gt=0, description="Max packets in buffer")
    max_packets_per_second: int = Field(1000000, gt=0, description="Rate limit for ingestion")
    enable_rate_limiting: bool = Field(True, description="Enable ingestion rate limiting")


class SafeAgentConfig(BaseModel):
    """SafeDeepAgent configuration."""

    enable_action_validation: bool = True
    enable_memory_firewalls: bool = True
    enable_provenance_tracking: bool = True
    enable_sandboxing: bool = True
    enable_behavioral_monitoring: bool = True
    enable_meta_supervision: bool = True
    enable_audit_logging: bool = True
    enable_purpose_binding: bool = True
    enable_intent_tracking: bool = True
    enable_deception_detection: bool = True
    enable_risk_adaptation: bool = True
    enable_human_governance: bool = True


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: str = Field("INFO", description="Log level (DEBUG, INFO, WARNING, ERROR)")
    format: str = Field("json", description="Log format (json, console)")
    output: str = Field("stdout", description="Log output (stdout, file)")
    file_path: Optional[str] = Field(None, description="Log file path if output=file")


class DDoSSentinelConfig(BaseModel):
    """Main configuration for DDoS Sentinel Agent."""

    # Component configs
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ingestion: IngestionConfig = Field(default_factory=IngestionConfig)
    safe_agent: SafeAgentConfig = Field(default_factory=SafeAgentConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Deployment config
    deployment_mode: str = Field("standalone", description="Deployment mode")
    environment: str = Field("development", description="Environment (dev/staging/prod)")

    class Config:
        """Pydantic config."""
        env_prefix = "DDOS_SENTINEL_"
        env_nested_delimiter = "__"


class ConfigManager:
    """
    Manage configuration loading from multiple sources.

    Priority (highest to lowest):
    1. Environment variables
    2. Config file
    3. Defaults
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize config manager.

        Args:
            config_path: Path to YAML config file (optional)
        """
        self.config_path = config_path
        self._config: Optional[DDoSSentinelConfig] = None

    def load(self) -> DDoSSentinelConfig:
        """
        Load configuration from all sources.

        Returns:
            Loaded configuration
        """
        config_dict = {}

        # 1. Load from file if provided
        if self.config_path:
            config_dict = self._load_from_file(self.config_path)

        # 2. Override with environment variables (handled by Pydantic)
        # 3. Apply defaults (handled by Pydantic)

        self._config = DDoSSentinelConfig(**config_dict)
        return self._config

    def _load_from_file(self, filepath: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            filepath: Path to config file

        Returns:
            Configuration dictionary
        """
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {filepath}")

        with open(path, 'r') as f:
            if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                return yaml.safe_load(f) or {}
            else:
                raise ValueError(f"Unsupported config format: {filepath}")

    def get(self) -> DDoSSentinelConfig:
        """Get current configuration."""
        if self._config is None:
            return self.load()
        return self._config

    def save(self, filepath: str):
        """
        Save current configuration to file.

        Args:
            filepath: Path to save config
        """
        if self._config is None:
            raise ValueError("No configuration loaded")

        config_dict = self._config.dict()

        with open(filepath, 'w') as f:
            if filepath.endswith('.yaml') or filepath.endswith('.yml'):
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            else:
                raise ValueError(f"Unsupported config format: {filepath}")


# Convenience functions
def load_config(config_path: Optional[str] = None) -> DDoSSentinelConfig:
    """
    Load configuration.

    Args:
        config_path: Optional path to config file

    Returns:
        Configuration object
    """
    # Check default locations
    if config_path is None:
        default_paths = [
            "config.yaml",
            "config.yml",
            os.path.expanduser("~/.ddos_sentinel/config.yaml"),
            "/etc/ddos_sentinel/config.yaml"
        ]

        for path in default_paths:
            if Path(path).exists():
                config_path = path
                break

    manager = ConfigManager(config_path)
    return manager.load()


def create_default_config(output_path: str = "config.yaml"):
    """
    Create a default configuration file.

    Args:
        output_path: Where to save the config
    """
    config = DDoSSentinelConfig()
    manager = ConfigManager()
    manager._config = config
    manager.save(output_path)
    print(f"Default configuration saved to: {output_path}")
