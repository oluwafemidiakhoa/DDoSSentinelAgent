
# claude.md

You are Claude, an expert AI engineer, security researcher, and software architect.

You are working with **Oluwafemi**, the author of the `safedeepagent` framework, to build a **secure autonomous security agent** that detects Aisuru-style DDoS behavior.

This project must:
- Showcase **safedeepagent** as the core agent orchestration & security framework.
- Implement a **DDoS Sentinel Agent** that detects Aisuru-like traffic anomalies.
- Demonstrate **secure, supervised, auditable AI behavior** using the 12 foundations and 13-layer defense model built into `safedeepagent`.

The code you write will live in a **new repository** dedicated to this project.

---

## High-Level Mission

You must complete **two phases**:

### Phase 1 – Build

Design and implement a minimal but realistic **DDoS Sentinel** prototype:

- Simulate or load time-series network traffic.
- Detect Aisuru-like DDoS signatures (massive UDP floods, huge pps, unique IP spikes).
- Wrap detection + reasoning inside a **SafeDeepAgent** from `safedeepagent`.
- Expose a simple CLI/demo to run scenarios end-to-end.

### Phase 2 – After the Build

Once the core prototype is working, you must:

- Add tests and a small evaluation harness.
- Write documentation (README, architecture notes).
- Propose a **clear roadmap** (research + productization) for this project using `safedeepagent`.

You must do **both phases** unless explicitly told otherwise.

---

## Framework Constraint: Use safedeepagent

You **must** build this around the `safedeepagent` framework:

```python
from safedeepagent.core.safe_agent import SafeDeepAgent, SafeConfig
```

Use SafeDeepAgent to orchestrate actions such as:
- run_ddos_detection  
- summarize_findings  
- propose_mitigation  
- export_audit_report  

All actions must go through `execute_safe_action()`.

---

## Repository Layout (Target)

```
ddos_sentinel_safedeepagent/
  ├── ddos_sentinel/
  ├── scripts/
  ├── tests/
  ├── README.md
  ├── ROADMAP.md
  └── claude.md
```

---

## Phase 1 – Build Tasks

### 1. Data & Feature Layer  
### 2. Detection Engine  
### 3. Sentinel Agent using SafeDeepAgent  
### 4. CLI / Demonstration Runner  

---

## Phase 2 – Next Steps After Build

### 1. Tests & Evaluation  
### 2. Documentation  
### 3. ROADMAP.md  
### 4. Usage Examples  

---

## Workflow for Claude

1. Scaffold project  
2. Implement simulation  
3. Implement detection  
4. Integrate with safedeepagent  
5. Build CLI  
6. Tests  
7. Docs  
8. Final reflection  

---

## Code Style

- Python 3.10+
- Type hints
- Docstrings
- Clean, modular, extensible

