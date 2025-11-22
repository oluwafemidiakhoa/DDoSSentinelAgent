# Internal Design Documentation

**DDoS Sentinel Agent - Multi-Agent Security Mesh**

Version: 0.2.0
Author: Oluwafemi Idiakhoa
Last Updated: 2025-11-22

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Agent Interfaces](#agent-interfaces)
3. [Orchestrator Logic](#orchestrator-logic)
4. [SafeDeepAgent Integration](#safedeepagent-integration)
5. [Event Flow](#event-flow)
6. [Data Models](#data-models)
7. [Detection Algorithms](#detection-algorithms)
8. [Mitigation Planning](#mitigation-planning)

---

## Architecture Overview

The DDoS Sentinel Agent has evolved from a single-agent DDoS detector into a **multi-agent security mesh** that provides comprehensive threat detection across multiple security domains.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Security Mesh Orchestrator                          │
│                   (SafeDeepAgent Meta-Supervision)                      │
│                                                                         │
│  Responsibilities:                                                      │
│  • Coordinate parallel agent analysis                                  │
│  • Cross-domain threat correlation                                     │
│  • Global severity assessment                                          │
│  • Unified mitigation plan synthesis                                   │
└────────────────────┬───────────────┬────────────────┬───────────────────┘
                     │               │                │
         ┌───────────▼──────┐  ┌────▼─────────┐  ┌──▼──────────────────┐
         │  Network Agent   │  │  DNS Agent   │  │ Supply Chain Agent  │
         │   (DDoS Detection)│  │(DNS Integrity)│ │  (Firmware Guard)   │
         │                  │  │              │  │                     │
         │ SafeDeepAgent    │  │SafeDeepAgent │  │  SafeDeepAgent      │
         │ Wrapper          │  │Wrapper       │  │  Wrapper            │
         └───────────┬──────┘  └────┬─────────┘  └──┬──────────────────┘
                     │               │                │
         ┌───────────▼──────┐  ┌────▼─────────┐  ┌──▼──────────────────┐
         │ Traffic Packets  │  │DNS Queries   │  │ Firmware Releases   │
         │ • UDP floods     │  │• Popularity  │  │ • Signing keys      │
         │ • High PPS       │  │• Resolver    │  │ • Deployment rate   │
         │ • Botnet IPs     │  │  abuse       │  │ • Device behavior   │
         └──────────────────┘  └──────────────┘  └─────────────────────┘
```

### Design Principles

1. **Domain Specialization**: Each agent focuses on a specific security domain
2. **Parallel Analysis**: Agents analyze their domains independently and concurrently
3. **Cross-Domain Correlation**: Orchestrator identifies multi-vector attacks
4. **Defense in Depth**: SafeDeepAgent wraps both agents and orchestrator
5. **Unified Response**: Single global mitigation plan synthesized from all domains

---

## Agent Interfaces

### BaseSecurityAgent Interface

All domain agents implement the `BaseSecurityAgent` interface:

```python
class BaseSecurityAgent(Protocol):
    """
    Base interface for all security domain agents.

    Required attributes:
        name: str - Agent identifier
        domain: str - Security domain (e.g., "network", "dns")

    Required methods:
        analyze(observation: Any) -> AnalysisResult
        propose_mitigation(analysis: AnalysisResult) -> MitigationPlan
    """

    @property
    def name(self) -> str:
        """Agent name (e.g., 'DDoSSentinelAgent')."""
        ...

    @property
    def domain(self) -> str:
        """Security domain (e.g., 'network', 'dns', 'supply_chain')."""
        ...

    def analyze(self, observation: Any) -> AnalysisResult:
        """
        Analyze observations from this agent's domain.

        Returns:
            AnalysisResult with attack_detected, severity, confidence, etc.
        """
        ...

    def propose_mitigation(self, analysis: AnalysisResult) -> MitigationPlan:
        """
        Generate domain-specific mitigation plan.

        Returns:
            MitigationPlan with immediate/follow-up actions
        """
        ...
```

### Domain Agents

#### 1. Network Agent (DDoSSentinelAgent)

**Domain**: `network`
**Input**: `List[TrafficPacket]`
**Detects**:
- Aisuru-style DDoS attacks (UDP floods, high PPS, botnet patterns)
- Traffic anomalies relative to baseline
- Amplification attacks

**Key Signatures**:
- CRITICAL_UDP_FLOOD: UDP ratio ≥ 95%
- CRITICAL_HIGH_PPS: PPS ≥ 100,000
- CRITICAL_BOTNET_PATTERN: Unique source IPs ≥ 3,000

#### 2. DNS Agent (DNSIntegrityAgent)

**Domain**: `dns`
**Input**: `DNSObservation`
**Detects**:
- DNS popularity manipulation (Cloudflare 1.1.1.1 rank abuse)
- Resolver abuse and spam queries
- Botnet-driven DNS queries with low HTTP correlation

**Key Indicators**:
- QPS spikes (> 1000 QPS)
- Low HTTP traffic ratio (< 0.3)
- Concentrated ASN distribution

#### 3. Supply Chain Agent (SupplyChainGuardianAgent)

**Domain**: `supply_chain`
**Input**: `SupplyChainObservation`
**Detects**:
- Suspicious firmware releases (TotoLink-style)
- Unknown or compromised signing keys
- Rapid worm-like deployments
- Post-release anomalous device behavior

**Key Indicators**:
- Unknown signing key
- Suspicious build host
- Rapid rollout speed (> 10,000 devices/hour)
- High post-release traffic multiplier (> 5x)

---

## Orchestrator Logic

### SecurityMeshOrchestrator

The orchestrator coordinates all domain agents through a three-phase process:

#### Phase 1: Parallel Analysis

```python
def analyze_all(self, observations: Dict[str, Any]) -> List[AnalysisResult]:
    """
    Run analysis across all agents with provided observations.

    Flow:
    1. Meta-supervision check via SafeDeepAgent
    2. For each agent with an observation:
       a. Call agent.analyze(observation)
       b. Collect AnalysisResult
    3. Return all analysis results
    """
```

**Key Features**:
- Agents run independently (no cross-agent dependencies)
- Each agent already wrapped in SafeDeepAgent
- Orchestrator adds meta-supervision layer
- Errors in one agent don't block others

#### Phase 2: Global Plan Synthesis

```python
def build_global_plan(self, results: List[AnalysisResult]) -> MitigationPlan:
    """
    Build global mitigation plan by fusing all agent results.

    Flow:
    1. Meta-supervision check via SafeDeepAgent
    2. Determine global severity (max across all domains)
    3. Collect indicators from all attacks
    4. Generate per-agent mitigation plans
    5. Add mesh-level meta-actions:
       - Escalation for CRITICAL severity
       - Multi-domain attack alerts
       - Cross-domain correlation tasks
    6. Deduplicate actions
    7. Return unified MitigationPlan
    """
```

**Global Severity Rules**:
- `CRITICAL`: If any agent reports CRITICAL
- `HIGH`: If any agent reports HIGH
- `MEDIUM`: If any agent reports MEDIUM
- `LOW`: If any agent reports LOW
- `NONE`: If no attacks detected

**Meta-Actions**:
- **CRITICAL + Multi-domain**: Escalate to human + alert SOC
- **Multi-domain attack**: Trigger cross-domain correlation
- **Always**: Generate incident report + update detection rules

#### Phase 3: End-to-End Execution

```python
def run_end_to_end(self, observations: Dict[str, Any]) -> Dict[str, Any]:
    """
    Complete analysis and mitigation planning pipeline.

    Returns:
        - per_agent_analyses: List[AnalysisResult]
        - global_plan: MitigationPlan
        - summary: Dict with stats
    """
```

---

## SafeDeepAgent Integration

### 12 Security Foundations

Every agent operation is wrapped in SafeDeepAgent's security framework:

1. **Action Validation** - Prevent prompt injection attacks
2. **Memory Firewalls** - Risk-scored data access
3. **Provenance Tracking** - Complete data lineage
4. **Execution Sandboxing** - Process-level isolation
5. **Behavioral Monitoring** - Anomaly detection on agent behavior
6. **Meta Supervision** - Multi-agent coordination oversight
7. **Audit Logging** - Complete audit trails
8. **Purpose Binding** - Scope enforcement
9. **Intent Tracking** - Goal alignment verification
10. **Deception Detection** - Truth verification
11. **Risk Adaptation** - Dynamic security adjustment
12. **Human Governance** - Approval workflows for high-risk actions

### Two-Level Security Model

```
┌──────────────────────────────────────────────────┐
│         Meta-Supervision (Orchestrator)          │
│           SafeDeepAgent Layer 2                  │
└───────────┬──────────────┬───────────────────────┘
            │              │
    ┌───────▼──────┐  ┌───▼──────────┐
    │ Agent 1      │  │ Agent 2      │
    │ SafeDeepAgent│  │ SafeDeepAgent│
    │ Layer 1      │  │ Layer 1      │
    └──────────────┘  └──────────────┘
```

**Layer 1** (Agent-level): Validates individual agent analysis actions
**Layer 2** (Orchestrator-level): Validates mesh-wide coordination actions

### Integration Points

#### Agent-Level

```python
# In DDoSSentinelAgent.run_ddos_detection()
result = self.safe_agent.execute_safe_action({
    'tool': 'ddos_detection',
    'parameters': {
        'packets': packets,
        'timestamp': datetime.now().isoformat()
    }
})

if result.allowed:
    # Run detection
    return analysis_results
else:
    # Action blocked
    return {'success': False, 'blocked_by': result.blocked_by}
```

#### Orchestrator-Level

```python
# In SecurityMeshOrchestrator.analyze_all()
result = self.safe_agent.execute_safe_action({
    'tool': 'mesh_analyze_all',
    'parameters': {
        'domains': list(observations.keys()),
        'timestamp': datetime.now().isoformat()
    }
})
```

---

## Event Flow

### Complete Detection Pipeline

```
1. Observation Collection
   └─> gather data from all security domains
        ├─> Network: traffic packets
        ├─> DNS: query statistics
        └─> Supply Chain: release metadata

2. Orchestrator Initialization
   └─> SecurityMeshOrchestrator(agents=[...], safe_agent=...)

3. End-to-End Analysis
   └─> mesh.run_end_to_end(observations)
        │
        ├─> Phase 1: analyze_all()
        │    ├─> [Meta-supervision check]
        │    ├─> For each agent:
        │    │    └─> agent.analyze(observation)
        │    │         ├─> [Agent-level SafeDeepAgent check]
        │    │         ├─> Feature extraction
        │    │         ├─> Signature matching
        │    │         ├─> Anomaly detection
        │    │         └─> Return AnalysisResult
        │    └─> Return List[AnalysisResult]
        │
        ├─> Phase 2: build_global_plan()
        │    ├─> [Meta-supervision check]
        │    ├─> Determine global severity
        │    ├─> For each attack result:
        │    │    └─> agent.propose_mitigation(result)
        │    │         ├─> [Agent-level SafeDeepAgent check]
        │    │         └─> Return MitigationPlan
        │    ├─> Add mesh-level meta-actions
        │    ├─> Deduplicate actions
        │    └─> Return global MitigationPlan
        │
        └─> Phase 3: Return summary
             └─> {analyses, global_plan, summary}

4. Response Execution
   └─> Present findings to user/SOC
   └─> Execute mitigation actions (with human approval for critical)
```

### Timing Characteristics

- **Agent Analysis**: < 1s per domain
- **Orchestration Overhead**: < 100ms
- **Total Pipeline**: < 5s for 3 agents
- **Parallel Speedup**: ~3x vs sequential

---

## Data Models

### Core Types

#### Severity

```python
class Severity(Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

#### AnalysisResult

```python
@dataclass
class AnalysisResult:
    domain: str                    # e.g., "network", "dns"
    attack_detected: bool
    severity: Severity
    confidence: float              # 0.0-1.0
    indicators: List[Indicator]
    notes: str
    timestamp: datetime
```

#### MitigationPlan

```python
@dataclass
class MitigationPlan:
    domain: str
    severity: Severity
    immediate_actions: List[MitigationAction]
    follow_up_actions: List[MitigationAction]
    estimated_impact: str
    recommended_response_time: str
```

---

## Detection Algorithms

### Network Domain (DDoS)

**Signature-Based Detection**:
- 6 Aisuru-specific signatures
- Confidence thresholds: 0.75-0.95
- Parallel signature matching

**Anomaly Detection**:
- Baseline profiling: mean + 3σ
- Metrics: PPS, UDP ratio, unique IPs
- Statistical deviation scoring

### DNS Domain

**Popularity Manipulation**:
- QPS threshold: > 1000
- HTTP correlation: < 0.3
- ASN concentration analysis

### Supply Chain Domain

**Firmware Compromise**:
- Signing key verification
- Build host reputation check
- Rollout speed analysis (worm detection)
- Post-release behavior correlation

---

## Mitigation Planning

### Action Priority System

**Priority Levels** (1-10):
- 10: Immediate human escalation
- 9: Critical automated response
- 7-8: Urgent actions (rate limiting, blocking)
- 5-6: Investigation and correlation
- 3-4: Updates and reviews
- 1-2: Post-incident analysis

### Deduplication

Actions are deduplicated by `(description, target, action_type)` tuple to avoid redundant operations across agents.

### Response Time Mapping

```python
{
    Severity.CRITICAL: "Immediate (< 5 minutes)",
    Severity.HIGH: "Urgent (< 15 minutes)",
    Severity.MEDIUM: "Priority (< 1 hour)",
    Severity.LOW: "Standard (< 4 hours)",
    Severity.NONE: "N/A"
}
```

---

## Future Enhancements

1. **Real-time PCAP ingestion** - Live packet capture
2. **ML-based anomaly detection** - Replace statistical baselines
3. **Distributed agent deployment** - Deploy agents across network edge
4. **SIEM integration** - Feed alerts to Splunk, ELK, etc.
5. **Automated response execution** - Execute low-risk mitigations automatically
6. **Threat intelligence feeds** - Integrate IOC databases
7. **Historical trend analysis** - Long-term attack pattern recognition

---

## References

- [SafeDeepAgent Framework](https://github.com/oluwafemidiakhoa/Deepagent)
- [Aisuru DDoS Analysis](https://github.com/oluwafemidiakhoa/DDoSSentinelAgent)
- Multi-Agent Systems in Cybersecurity (2024)
