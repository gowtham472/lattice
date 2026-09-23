# Eraser Architecture Prompt - LATTICE

> **Note.** This prompt produced `Archi-lattice.png`, the original design diagram. The built
> system differs in places: container images are scanned from exported archives (no
> `oci-client` pull), runtime evidence comes from packet captures (eBPF is planned), the graph
> is in-process `petgraph` exported per scan (no `redb`), the cockpit draws its graph in SVG
> (no Cytoscape.js), and there is no PDF report yet. [architecture.md](../architecture.md) is
> the as-built specification.

Two ways to generate the diagram in Eraser (eraser.io):

- **Option A** - paste the *natural-language prompt* into Eraser's "Generate diagram with
  AI" box.
- **Option B** - paste the *diagram-as-code* into an Eraser "Cloud Architecture" diagram for
  a precise, editable result (recommended - deterministic).

---

## Option A - Natural-language prompt (paste into Eraser AI)

```
Create a cloud architecture diagram titled "LATTICE - Cryptographic Discovery & PQC
Migration Engine". Layout top-to-bottom, grouped into horizontal tiers. Use a clean,
enterprise style. Draw a dashed boundary labelled "Air-gapped boundary - zero network
egress" around the entire LATTICE system, with the scan targets outside it on the left.

GROUP "Scan Targets" (outside the air-gapped boundary, left side):
- Source Repositories (git)
- Binaries & Libraries
- Container Images (OCI registry)
- Certificates & Config
- Cloud KMS / IaC
- Live Traffic / PCAP

GROUP "Tier 1 - Discovery" (six collectors, each reading one target):
- Source Collector (tree-sitter)
- Binary Collector (goblin)
- Container Collector (oci-client)
- Config/Cert Collector (x509-parser)
- Cloud KMS Collector
- Runtime Collector (aya eBPF + tls-parser) [mark as optional]
All six feed into:
- Normaliser (dedupe, canonical IDs, evidence grade)

GROUP "Tier 2 - Connect":
- Crypto Data-Flow Graph (petgraph + redb)
- Tri-state Liveness Resolver (Capable / Configured / Confirmed)
- Data Classifier (regex + ONNX)
The Normaliser feeds the Data-Flow Graph; the Liveness Resolver and Data Classifier both
read and enrich the graph.

GROUP "Tier 3 - Decide":
- Quantum-Breakability Map (Shor / Grover)
- Mosca Engine (X + Y > Z)
- HNDL Exposure Index
- Crypto-Agility Score
- Migration Planner (FIPS 203/204/205 + hybrid)
- CI Gate
The Data-Flow Graph feeds all of Tier 3; the Migration Planner consumes the four scoring
modules.

GROUP "Outputs":
- CycloneDX 1.6 CBOM (JSON)
- ML-DSA-signed PDF Report
- Interactive Cockpit (React + Cytoscape.js)
- CI Verdict (pass/fail)

GROUP "Cross-cutting" (a side panel touching all tiers):
- Security Sandbox (seccomp + Landlock + panic isolation)
- Signed Knowledge Bundles (algorithm map, CVE mirror)
- CBOM Signer (BLAKE3 hash-chain + ML-DSA)

CONNECTIONS:
- Each Scan Target connects to its matching Collector, crossing the air-gapped boundary.
- All Collectors connect to the Normaliser.
- Normaliser connects to the Crypto Data-Flow Graph.
- Liveness Resolver and Data Classifier connect bidirectionally to the Graph.
- Graph connects to each Tier 3 scoring module.
- Scoring modules connect to the Migration Planner.
- Tier 3 connects to all four Outputs.
- CBOM Signer connects to the CBOM and PDF outputs.
- Signed Knowledge Bundles connect to the Normaliser and the scoring modules.
- Security Sandbox wraps the Collectors.
Label the flow left-to-right, top-to-bottom as: DISCOVER → CONNECT → DECIDE → REPORT.
Deploys as a single static Rust binary.
```

---

## Option B - Eraser diagram-as-code (Cloud Architecture)

Paste this into an Eraser diagram file. Adjust icons/colors to taste.

```
// LATTICE - Cryptographic Discovery & PQC Migration Engine
direction down

Targets [icon: folder, color: gray] {
  Repos [label: "Source Repositories", icon: git]
  Bins [label: "Binaries & Libraries", icon: package]
  Images [label: "Container Images", icon: docker]
  Certs [label: "Certificates & Config", icon: file-lock]
  Cloud [label: "Cloud KMS / IaC", icon: cloud]
  Pcap [label: "Live Traffic / PCAP", icon: activity]
}

LATTICE [label: "LATTICE  (air-gapped · single static Rust binary · zero egress)", icon: shield, color: blue] {

  Tier1 [label: "Tier 1 - Discovery", color: teal] {
    C1 [label: "Source Collector\n(tree-sitter)", icon: code]
    C2 [label: "Binary Collector\n(goblin)", icon: cpu]
    C3 [label: "Container Collector\n(oci-client)", icon: box]
    C4 [label: "Cert/Config Collector\n(x509-parser)", icon: file-text]
    C5 [label: "Cloud KMS Collector", icon: key]
    C6 [label: "Runtime Collector (opt)\n(aya eBPF · tls-parser)", icon: radio]
    Norm [label: "Normaliser\n(dedupe · evidence grade)", icon: filter]
  }

  Tier2 [label: "Tier 2 - Connect", color: indigo] {
    Graph [label: "Crypto Data-Flow Graph\n(petgraph · redb)", icon: git-merge]
    Live [label: "Tri-state Liveness\nCapable→Configured→Confirmed", icon: eye]
    Classify [label: "Data Classifier\n(regex · ONNX)", icon: tag]
  }

  Tier3 [label: "Tier 3 - Decide", color: orange] {
    QB [label: "Quantum-Breakability\n(Shor / Grover)", icon: zap]
    Mosca [label: "Mosca Engine\n(X + Y > Z)", icon: clock]
    HNDL [label: "HNDL Exposure Index", icon: trending-up]
    CAS [label: "Crypto-Agility Score", icon: sliders]
    Plan [label: "Migration Planner\n(FIPS 203/204/205 · hybrid)", icon: map]
    Gate [label: "CI Gate", icon: git-branch]
  }

  Cross [label: "Cross-cutting", color: red] {
    Sandbox [label: "Security Sandbox\n(seccomp · Landlock)", icon: lock]
    Bundles [label: "Signed Knowledge Bundles", icon: database]
    Signer [label: "CBOM Signer\n(BLAKE3 · ML-DSA)", icon: check-circle]
  }

  Out [label: "Outputs", color: green] {
    CBOM [label: "CycloneDX 1.6 CBOM", icon: file-json]
    PDF [label: "Signed PDF Report", icon: file]
    UI [label: "Interactive Cockpit\n(React · Cytoscape.js)", icon: monitor]
    CI [label: "CI Verdict", icon: check]
  }
}

// targets to collectors (cross the boundary)
Repos > C1
Bins > C2
Images > C3
Certs > C4
Cloud > C5
Pcap > C6

// discovery
C1 > Norm
C2 > Norm
C3 > Norm
C4 > Norm
C5 > Norm
C6 > Norm

// connect
Norm > Graph
Live <> Graph
Classify <> Graph

// decide
Graph > QB
Graph > Mosca
Graph > HNDL
Graph > CAS
QB > Plan
Mosca > Plan
HNDL > Plan
CAS > Plan

// outputs
Plan > CBOM
Plan > PDF
Plan > UI
Gate > CI
Graph > UI

// cross-cutting
Bundles > Norm
Bundles > QB
Sandbox > C1
Sandbox > C2
Sandbox > C3
Signer > CBOM
Signer > PDF
```

---

## Tips
- In Eraser AI mode, if the six collectors crowd, add: *"lay the six collectors in one row."*
- Keep the dashed air-gap boundary - it is the single most important visual (it says
  "sovereign, offline"), and it maps directly to [security.md §5](../security.md).
- The three tier colours (teal → indigo → orange) reinforce the DISCOVER → CONNECT → DECIDE
  story from [solution.md](../solution.md).
