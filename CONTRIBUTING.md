# Contributing to Anthill

First off, thank you for considering contributing to Anthill! It's people like you who make the digital swarm stronger and more resilient.

Anthill is an industrial-grade, distributed EDR system. Because we operate close to the kernel and handle critical security decisions, we maintain high standards for code quality, safety, and performance.

---

## 🛠 Development Setup

### Prerequisites
To build and test the full Anthill swarm, you will need:

- **Rust**: Latest stable (use [rustup](https://rustup.rs/))
- **Clang/LLVM**: ≥ 15 (for eBPF compilation)
- **libsqlite3-dev**: For the threat database
- **libpcap-dev**: For network sensing
- **Python**: ≥ 3.11 (for the ML pipeline)

### Initializing the Workspace
```bash
git clone https://github.com/megeezy/Ant-Hill.git
cd Ant-Hill

# Install workspace-wide linting tools
rustup component add rustfmt clippy
```

---

## 🐜 Project Architecture

Anthill follows a strict **Five-Tier Distributed Strategy**. Before submitting a PR, ensure your changes fit into the correct crate:

- `anthill-agents`: Telemetry collection (Kernel/Network hooks). **Safety critical.**
- `anthill-bus`: High-speed relay. **Performance critical.**
- `anthill-queen`: Detection logic (SIG/BEH/ML). **Accuracy critical.**
- `anthill-soldier`: Enforcement and forensics. **Stability critical.**
- `anthill-core`: Shared types and Protobuf definitions.

---

## 🎋 Branching & Workflow

1. **Fork the Repository**: Create your own fork and work on a feature branch.
2. **Branch Naming**: Use descriptive names: `feat/ebpf-proc-tree`, `fix/queen-memory-leak`, `chore/update-dependencies`.
3. **Keep it Small**: We prefer small, atomic PRs that do one thing well. Large "mega-PRs" will be rejected or asked to be split.

---

## 📝 Coding Standards

### Rust Logic
- **Memory Safety**: Avoid `unsafe` unless absolutely necessary (mostly within `anthill-agents` or eBPF glue). Every `unsafe` block must have a `// SAFETY:` comment.
- **Error Handling**: Use `anyhow` for top-level applications and `thiserror` for library crates. Never `unwrap()` or `panic!()` in the detection path.
- **Logging**: Use the `tracing` crate. Follow the levels:
    - `error!`: Actionable failures.
    - `warn!`: Suspicious behavior or non-fatal issues.
    - `info!`: Significant lifecycle events.
    - `debug!`: Detailed state for developers.

### Commits
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` A new feature.
- `fix:` A bug fix.
- `perf:` A code change that improves performance.
- `docs:` Documentation only changes.
- `test:` Adding missing tests or correcting existing tests.

---

## 🧪 Testing

Every PR must pass the local CI suite:

```bash
# Check formatting
cargo fmt --all -- --check

# Run lints
cargo clippy --workspace -- -D warnings

# Run all tests
cargo test --workspace
```

For `anthill-agents` changes, you may need to run tests with `sudo` if they interact with eBPF or network interfaces.

---

## 🚀 Pull Request Process

1. Update the **README.md** or crate-level documentation if your change introduces new behavior or config options.
2. Ensure your code compiles on **Linux** (primary platform).
3. The Queen's guardians (maintainers) will review your code. Expect feedback on:
    - Performance implications of new detection rules.
    - Safety of kernel/forensic operations.
    - Adherence to the distributed swarm metaphor.

---

## ⚖️ License
By contributing to Anthill, you agree that your contributions will be licensed under the **MIT License**.

---

**Together, we are the colony.**
