# LATTICE

**SIH26164 - Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**
National Technical Research Organisation (NTRO) · Theme: Blockchain & Cybersecurity · Category: Software
Team: **DoodleByte**

---

*LATTICE* has a deliberate double meaning. The tool maps a **lattice** - a complete,
connected grid of every cryptographic asset across an organisation. The algorithms that
replace the broken ones (ML-KEM, ML-DSA) are themselves **lattice-based cryptography**.
The name is the thesis: see the whole lattice, then migrate it.

---

## The one-sentence idea

Existing tools answer *"what cryptography do I have?"* LATTICE answers
*"which of my secrets will a quantum adversary actually read, when, and what is the
cheapest safe way to stop it?"* - turning a static inventory into a decision engine.

---

## The document pack

Read in this order.

| # | Document | What it covers |
|---|----------|----------------|
| 1 | [problem_statement.md](problem_statement.md) | The PS verbatim, decoded; why it is hard; what already exists and where it fails |
| 2 | [solution.md](solution.md) | The idea, the reframing, the five novel mechanisms, a worked example |
| 3 | [architecture.md](architecture.md) | The three tiers, every component, data model, graph schema, deployment |
| 4 | [features.md](features.md) | The full feature list, MVP vs later, mapped to PS deliverables |
| 5 | [techstack.md](techstack.md) | Every crate and why, layer by layer, Rust-first |
| 6 | [security.md](security.md) | Threat model, parser sandboxing, air-gap, signing, explainability, compliance |
| 7 | [decisions.md](decisions.md) | "Why X over Y" - every major trade-off with the honest reasoning |
| 8 | [roadmap.md](roadmap.md) | Build plan, milestones, the hackathon demo script |
| 9 | [IMPLEMENTATION.md](IMPLEMENTATION.md) | Executable status, delivered guarantees, gaps, and immediate build order |
| - | [diagrams/eraser-architecture-prompt.md](diagrams/eraser-architecture-prompt.md) | Paste-ready prompt to generate the architecture diagram in Eraser |

---

## The four decisions already locked

These are argued in full in [decisions.md](decisions.md).

| Decision | Choice | One-line reason |
|----------|--------|-----------------|
| Core language | **Rust** | Single static air-gapped binary; the best X.509/TLS/binary parsers are Rust-native; memory safety for a security tool |
| Graph store | **Embedded (`petgraph` + `redb`)** | Keeps the single-binary, no-external-service, air-gapped promise; no Neo4j to deploy inside NTRO |
| Runtime confirmation | **Opt-in, via `aya` eBPF + `tls-parser`** | Delivers the "Confirmed" liveness state without making the core depend on it |
| Demo anchor | **Generic engine, banking/UPI flagship scenario** | Sharp story tied to the RBI quantum-safe push, without narrowing the tool |

---

## Status

Implementation started. The first offline `scan → normalize → assess → CBOM` vertical slice is available; see [IMPLEMENTATION.md](IMPLEMENTATION.md) for exact coverage and remaining milestones.
