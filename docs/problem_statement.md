# Problem Statement

**SIH26164 - Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**
Organisation: National Technical Research Organisation (NTRO)
Theme: Blockchain & Cybersecurity · Category: Software

---

## 1. The statement, verbatim

> **Background** - Transitioning to Post Quantum Cryptography based solutions requires
> preparedness, risk assessment and financial and operational investment. Towards this,
> discovery and inventory of Cryptographic Artefacts is the critical first step, that
> will enable the transition.
>
> **Description**
> i. Identify and catalogue all cryptographic artefacts (algorithms, keys, certificates,
> protocols, libraries, hardware modules, cloud services) across internal and external
> facing applications, products and infrastructure.
> ii. The tool should perform a comprehensive quantum risk assessment and identify systems
> prone to potential quantum attacks, and highlight risks to sensitive data.
> iii. Classify all the artefacts by type, lifetime and business criticality. Apply
> structured frameworks such as Mosca's algorithm (compare data lifetime plus migration
> time against expected arrival of a cryptographically relevant quantum computer) to
> identify and categorise risks.
> iv. Recommend suitable alternatives (PQC / Hybrid algorithms) for applications based on
> risk profile, latency, cost, etc.
>
> **Expected Solution / Deliverables** - A comprehensive CBOM analytics tool that can scan
> source code repositories, binaries, libraries and container images, for assessing risks
> (due to quantum computers), classifying artefacts and suggesting alternatives: produce a
> report displaying all cryptographic assets including versions / modes in standardised
> formats; an interactive GUI platform to visualise the scan, risks and results.
>
> *Dataset note:* standard open-source datasets for source code repositories (e.g. GitHub)
> and libraries (e.g. OpenSSL) may be used.

---

## 2. What it is actually asking for, decoded

Strip the wording down and the tool must do five things:

1. **Find** every piece of cryptography, everywhere - six named surfaces:
   source code, binaries, libraries, container images, and by extension certificates,
   hardware security modules and cloud key services.
2. **Judge** which of it a quantum computer will break, and which sensitive data that
   endangers.
3. **Classify** each finding by *type*, *data lifetime*, and *business criticality* - and
   run **Mosca's inequality** (X + Y > Z) to decide urgency.
4. **Recommend** post-quantum or hybrid replacements, weighed by risk, latency and cost.
5. **Report** it all as a standard **CBOM** (Cryptographic Bill of Materials) plus an
   interactive GUI.

---

## 3. Why this is hard, and why it matters now

### 3.1 The threat is already live: Harvest-Now-Decrypt-Later
An adversary does not need a quantum computer today to hurt you today. They record your
encrypted traffic now and decrypt it after "Q-day." Any secret with a long shelf life -
state records, defence communications, health and financial data, identity keys - is
**already exposed**. This is why discovery cannot wait for the quantum computer to exist.

### 3.2 The replacements have arrived, so migration is now a mandate, not a research topic
- **NIST finalised the standards** in August 2024: ML-KEM (FIPS 203), ML-DSA (FIPS 204),
  SLH-DSA (FIPS 205).
- **NSA CNSA 2.0** requires PQC preference by 2025 and exclusive use by 2030.
- **India** has a national deadline. The DST Task Force report *"Implementation of a
  Quantum Safe Ecosystem in India"* (Feb 2026) sets a **2027–2029 migration timeline for
  Critical Information Infrastructure**, and explicitly requires **mandatory cryptographic
  inventories** and crypto-agile design. The RBI (2025) is pushing quantum-safe payment
  infrastructure. The National Quantum Mission is funded at **₹6,003.65 crore**.

An NTRO tool that produces that mandatory inventory - and then tells you what to do with
it - is directly on the critical path of a funded national programme.

### 3.3 Crypto is genuinely hard to find
A decade-old estate carries **cryptographic debt**: encryption, signing and authentication
buried in legacy applications, firmware, HSMs, cloud configs, SaaS APIs and custom code,
with no central record. The industry rule of thumb is brutal: *"an inventory that captures
80% of your cryptography is not 80% useful"* - audits and breaches are decided by the last
20%, the assets nobody knew about.

---

## 4. What already exists - and where it falls short

We surveyed the field before designing. The point is not to rebuild what exists; it is to
solve what the incumbents openly admit they cannot.

### The incumbents
| Tool | Approach | Surfaces |
|------|----------|----------|
| **IBM CBOMkit** (donated to Linux Foundation PQCA) - Sonar-cryptography, CBOMkit-theia | Source (Java/Python) + container scanning, CBOM generation | source, container |
| **SandboxAQ AQtive Guard** (acquired Cryptosense) | Network analyser + application-runtime analyser + filesystem analyser | network, runtime, files |
| **Keyfactor Command** (acquired InfoSec Global 2025) | Certificate-centric crypto inventory | certs, config |
| **Academic** - Cryptoscope, Architecture-Derived CBOMs, Cryptarium | Source-level crypto usage analysis | source |

### The gaps they document about themselves - our opening
These are not our opinions; they are stated limitations in the vendors' and standards
bodies' own material.

1. **Capability ≠ usage.** A CBOM lists what a library *can* do, not what the system
   *actually runs or is configured to use*. In plain terms: *"a CBOM won't indicate whether
   an organisation is using SHA-1 or SHA-256 even if both are supported."* This is the
   single most-admitted weakness in the space.
2. **An inventory cannot decide anything.** *"A CBOM cannot discover unknown assets, assess
   risk, prioritise remediation, or manage migration on its own."* It is a list, not an
   engine.
3. **Crypto-agility has no score yet.** NIST's own CSWP 39 (final, Dec 2025) says a
   crypto-agility maturity model with KPIs still **needs to be built by the community** -
   it does not exist.
4. **The last-20% blind spot.** Legacy binaries, firmware, HSMs and configuration-driven
   crypto are where scanners miss, and where audits fail.
5. **Prioritisation by data-flow is advised but not automated.** Everyone says "migrate
   your highest-value data flows first"; no tool computes which those are for you.

---

## 5. Success criteria for our solution

A submission that wins this PS must:

- Scan **all six surfaces** the PS names, not two or three.
- Emit a **standards-compliant CBOM** (CycloneDX 1.6) - the "standardised format" clause.
- Do more than inventory: **assess quantum risk, run Mosca, and rank remediation** - the
  clauses (ii), (iii), (iv) that a plain CBOM tool skips.
- Close at least one documented gap above that the incumbents cannot - ideally the
  capability-vs-usage gap and the missing crypto-agility score.
- Run **offline / air-gapped**, because it is an NTRO tool scanning sensitive estates.
- Ship an **interactive GUI**, as the deliverables require.

How we meet each of these is [solution.md](solution.md) and [architecture.md](architecture.md).
