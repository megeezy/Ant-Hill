# 🐜 Anthill
> **An autonomous, distributed endpoint security system inspired by the swarm intelligence of ant colonies.**

[![Rust](https://img.shields.io/badge/language-rust-orange.svg)](https://www.rust-lang.org)
[![eBPF](https://img.shields.io/badge/kernel-eBPF-blue.svg)](https://ebpf.io/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-blue.svg)](CONTRIBUTING.md)

[Overview](#overview) • [Architecture](#architecture) • [Quick Start](#quick-start) • [Configuration](#configuration) • [Roadmap](#roadmap) • [Contributing](#contributing)

> [!IMPORTANT]
> **Availability**: Current implementation (v0.1.x) is available for **Linux platforms alone**. macOS and Windows support are scheduled for Phase 4.

## Overview

**Anthill** is a next-generation Endpoint Detection and Response (EDR) system. Unlike monolithic antivirus software that relies on heavy, centralized scanning, Anthill operates as a **digital swarm**. It uses lightweight, specialized "Worker Ants" (sensors) to hunt for threats, propagating "Pheromones" (alerts) across a high-speed bus to the "Queen" (engine) for collective decision-making.

```text
Process Event → [ Worker Ant ] → Prefilter → Pheromone Bus → Queen Engine → Soldier Response
                     ↑                                         (ML + Behaviour)      |
                     └───────────────────── feedback loop ────────────────────────────┘
```

The result is a system that can detect complex, multi-stage attacks (MITRE ATT&CK techniques) with minimal system overhead, isolating threats in milliseconds while maintaining forensic integrity.

> **Think of it this way**: traditional AV is like a single security guard watching 100 monitors. **Anthill** is a swarm of thousands of tiny sensors, each looking for one specific thing. Individually they are simple; together, they are an unstoppable immune system.

---

## Why Anthill?

| Feature | Traditional AV / EDR | Anthill Swarm |
| :--- | :--- | :--- |
| **Detection** | Static signatures & heavy heuristics | Swarm intelligence & temporal behavioral correlation |
| **Performance** | Significant CPU/RAM "scan spikes" | Distributed, asynchronous, and burst-collapsed |
| **Resilience** | Single point of failure (Main service) | Decoupled tiers; the colony survives even if nodes fail |
| **Response** | Aggressive, often breaks user apps | Safety-guarded with two-tier protected process lists |
| **Visibility** | Opaque dashboard | Real-time TUI pheromone stream + gRPC forensics |

---

## Architecture

Anthill is built on a high-performance **Five-Tier Distributed Strategy**:

1.  **Tier 1: Worker Ants (Sensors)** — Lightweight probes (eBPF, libpcap) collecting telemetry.
2.  **Tier 1.5: Pre-filter** — In-process deduplication and burst suppression.
3.  **Tier 2: Pheromone Bus** — Low-latency relay (Protobuf + tokio) connecting the colony.
4.  **Tier 3: Queen Engine** — The brain. Executes SIG + BEH + ML scoring engines.
5.  **Tier 4: Soldier Layer** — The enforcement arm. Handles isolation, forensics, and quarantine.

```text
┌─────────────────────────────────────────────────────────┐
│                    API Gateway (Rust/gRPC)              │
│          Monitoring · External Auth · Orchestration     │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                  Queen Engine (Rust)                    │
│  ┌─────────────────┐  ┌────────────┐  ┌──────────────┐  │
│  │ Behaviour       │← │ Pheromone  │→ │ ML Inference │  │
│  │ Scorer          │  │ Bus        │  │ (ONNX/ORT)   │  │
│  └─────────────────┘  └────────────┘  └──────────────┘  │
└──────────────┬───────────────────────────┬──────────────┘
               │                           │
               │         Protobuf / IPC    │
       ┌───────┴───────┐           ┌───────┴───────┐
       │               │           │               │
┌──────▼───────┐ ┌─────▼────────┐ ┌▼─────────────┐ ┌▼─────────────┐
│Signature DB  │ │ Prefilter    │ │ Sensor Ant A │ │ Sensor Ant B │
│(SQLite/SHA2) │ │ (Burst Col.) │ │ (eBPF hooks) │ │ (Net sniffer)│
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│                  Soldier Response Layer                 │
│         Forensic Capture · Safety Guards · Actions      │
│              Protected Process Enforcement              │
└─────────────────────────────────────────────────────────┘
```

---

## Threat Lifecycle (Swarm Logic)

1.  **Sensing**: A Worker Ant (eBPF kprobe) detects a suspicious `execve()` call.
2.  **Filtering**: The Pre-filter collapses 100 identical process bursts into 1 high-confidence Pheromone.
3.  **Propagation**: The Pheromone is broadcast over the `anthill-bus`.
4.  **Correlation**: The **Queen** correlates the event across temporal windows (5s to 30m).
5.  **Verdict**: Weighted scoring (Signature + Behaviour + ML) crosses the threshold (e.g., > 0.70).
6.  **Response**: The **Soldier** takes a forensic snapshot, verifies against the Safety Allowlist, and executes a `KILL` or `QUARANTINE`.

---

## Project Structure (Industrial Hierarchy)

Anthill is architected as an industrial-scale telemetry and detection ecosystem. The workspace is categorized into specialized domains to ensure high modularity and platform-agnostic detection logic.

```text
Ant-Hill/
├── bin/
│   └── anthill           # Main Hive Supervisor (Life-cycle & Orchestration)
│
├── core/                 # Shared Infrastructure & Foundations
│   ├── common/           # Unified config, types, and Protobuf re-exports
│   ├── bus/              # High-speed Pheromone Relay (Telemetry bus)
│   ├── db/               # Persistence Layer (SQLite + Sled)
│   └── protocol/         # Protobuf contract definitions (.proto)
│
├── engines/              # Advanced Swarm Intelligence
│   ├── queen/            # Behavioral Correlation Engine & State logic
│   ├── prefilter/        # Signal deduplication and burst suppression
│   └── intelligence/     # [STUB] ONNX ML models & drift monitoring
│
├── platform/             # Specialized Worker Ants (Sensor Probes)
│   ├── linux/
│   │   ├── agents/       # Process, File, and Network kprobes
│   │   └── ebpf/         # C-level BPF kprobe source & maps
│   ├── windows/          # [ROADMAP] ETW & Kernel callback providers
│   └── darwin/           # [ROADMAP] FSEvents & SkyLight providers
│
├── response/             # Active Defense & Remediation
│   └── soldier/          # Active response orchestrator (Safety + Forensics)
│
├── ui/                   # Frontend & External Interfaces
│   ├── tui/              # Terminal-based real-time Dashboard
│   └── api/              # gRPC API for external fleet management
│
├── infrastructure/       # DevOps & Deployment Scaffolding
│   ├── docker/           # Containerization & local simulation
│   └── k8s/              # Kubernetes manifests for fleet nodes
│
├── docs/                 # Engineering Documents
│   ├── rfc/              # Design proposals & architectural changes
│   └── api/              # gRPC and shared logic documentation
│
├── benchmarks/           # Latency and throughput evaluation suites
├── scripts/              # Swarm automation & stress-test utilities
└── storage/              # [LOCAL] Vault, Forensics, and DB storage
```

---

## Quick Start

### Prerequisites
| Dependency | Version | Purpose |
| :--- | :--- | :--- |
| **Rust** | ≥ 1.78 | Main implementation |
| **Clang/LLVM** | ≥ 15 | eBPF probe compilation |
| **libsqlite3** | ≥ 3.40 | Long-term storage |
| **libpcap** | ≥ 1.10 | Network sensing |

### 1. Clone and Build

```bash
git clone https://github.com/your-org/anthill.git
cd anthill

# Build the entire workspace
cargo build --release
```

### 2. Configure

Edit `config/default.toml` or create a local profile:
```toml
[response]
mode = "confirm"   # auto | confirm | monitor
confirm_timeout_s = 300
```

### 3. Start Anthill

Anthill requires `root` to attach kernel probes and capture forensics.

```bash
sudo ./target/release/anthill --profile developer
```

---

## Configuration

All system behavior is controlled via TOML profiles.

```toml
[agent]
file_monitor_enabled = true
proc_monitor_enabled = true

[queen]
sig_weight     = 0.30
beh_weight     = 0.35
ml_weight      = 0.25
box_weight     = 0.10

[persistence]
db_path        = "/var/lib/anthill/anthill.db"
forensics_path = "/var/lib/anthill/forensics"
```

---

## Roadmap

### Phase 1: Industrial Foundation ✅ (Current)
- [x] Five-tier decoupled architecture
- [x] Protobuf-based Pheromone Bus
- [x] Basic Signature and ML engine stubs
- [x] Safety-guarded Response Layer

### Phase 2: Sensor & Hardware Integration ⏳
- [ ] eBPF kprobes for deep process tree visibility
- [ ] libpcap network flow analysis
- [ ] Sliding window temporal correlation engine

### Phase 3: Intelligence Swarm
- [ ] Distributed gRPC worker fleet (multi-node monitoring)
- [ ] ML-based drift monitoring and model sign-off
- [ ] Community YARA rule integration

### Phase 4: Hardening & UI
- [ ] Native macOS (FSEvents) and Windows (ETW) support
- [ ] Authenticated gRPC Management API
- [ ] Fully interactive TUI Dashboard

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

### Commit Convention
- `feat(queen):` added sliding window for T1055 injection
- `fix(soldier):` bypass safety check for non-executable files
- `perf(bus):` optimized Protobuf serialization overhead

---

## Design Decisions

- **Why Rust?** anthill is a low-level system tool. Rust provides the memory safety required for kernel-adjacent code without the overhead of a garbage collector.
- **Why Five Tiers?** Security systems are often fragile. By decoupling sensing from detection and response, we ensure that a failure in one component doesn't take down the whole colony.
- **Why Ant Colony?** Nature solved decentralized threat detection millions of years ago. Swarm intelligence is naturally resistant to the kind of "one-shot" evasion that bypasses centralized AI.

---

**Built with Rust for absolute safety · Swarm logic for absolute detection**

*Anthill has no single brain. Neither does a truly resilient defense.*
