# Solution

**LATTICE** - a data-flow-aware Cryptographic BOM and post-quantum migration cockpit.

---

## 1. The reframing (the whole idea in one move)

Every incumbent builds an **inventory** and stops. Their own documentation admits the
inventory reports *capability, not usage*, and *cannot assess risk or prioritise*.

LATTICE is built the other way round. The inventory is the foundation, not the product.
On top of it we build a **decision engine**:

> Existing tools answer: **"What cryptography do I have?"**
> LATTICE answers: **"Which of my secrets will a quantum adversary actually read, when,
> and what is the cheapest safe way to stop it?"**

That shift - from list to decision - is why the architecture has three tiers
(discover → connect → decide) instead of one, and it is why every novel mechanism below
targets a gap the incumbents openly cannot close.

---

## 2. The five novel mechanisms

Each one maps to a documented gap from [problem_statement.md](problem_statement.md) §4.

### 2.1 Tri-state crypto liveness: Capable → Configured → Confirmed
*Closes gap #1 - capability ≠ usage.*

Every asset carries a **liveness state**, not just an entry in a list:

| State | Meaning | How we establish it |
|-------|---------|---------------------|
| **Capable** | A present library *can* do it | binary / library collector |
| **Configured** | A config or policy *selects* it | config collector - cipher suites, JCA policy, TLS settings |
| **Confirmed** | It is *observed* on a real path or handshake | graph reachability, or opt-in runtime capture (eBPF / PCAP) |

We report the **highest state reached**. So instead of "you might use SHA-1," LATTICE says
"RSA is **Confirmed** on the payments handshake." No other tool cleanly separates these
three states - and it is the exact weakness every vendor admits.

### 2.2 Crypto Data-Flow Graph - not a flat list
*Closes gap #2 - an inventory cannot assess risk.*

We build a property graph linking each **algorithm → the data it protects → the code paths
that reach it → the entry points that expose it**. Risk becomes a property of the *path*,
not the algorithm in isolation:

- RSA in dead code that nothing calls → near-zero risk.
- ECDHE on an internet-facing endpoint guarding 25-year secrets → critical.

Because the graph knows *what each key protects and for how long*, **Mosca's inequality is
computed per asset instead of guessed** - which is precisely what clause (iii) of the PS
demands.

### 2.3 HNDL Exposure Index - the prioritiser
*Closes gap #5 - prioritisation by data-flow is advised but never automated.*

A single 0–100 ranking number per asset:

```
HNDL = 100 · ExternalExposure · min(DataLifetime / Lmax, 1) · QuantumBreakability · Liveness
```

It answers the only question a CISO or an NTRO analyst actually has under a deadline:
*what do I fix first?* - the channels an adversary can record today and break after Q-day.

### 2.4 Automated Crypto-Agility Score (CAS) - the KPI NIST says is missing
*Closes gap #3 - crypto-agility has no score yet.*

We measure agility **mechanically**, per asset: is the algorithm behind a provider
interface (JCA, OpenSSL EVP, PKCS#11) or hardcoded? Is the key size parameterised? Is there
a negotiation layer? → a **0–100 score that predicts migration cost**. This is a genuinely
new, quantitative KPI aligned to an open problem that NIST's own CSWP 39 says the community
still has to build. It is our strongest "we built the thing the standard body hasn't" claim.

### 2.5 Mosca-driven migration planner + no-backslide CI gate
*Delivers clause (iv), and defends the result over time.*

Mosca's inequality - **X** (secrecy lifetime, from the graph) + **Y** (migration time, from
the CAS) **> Z** (Q-day, a configurable *range*, not a guess) - feeds a **dependency-ordered
roadmap** recommending ML-KEM / ML-DSA / hybrid, with latency and handshake-size deltas so
cost is visible. A **crypto-agility CI gate** then fails any future build that reintroduces
weak crypto, and the CBOM is **hash-chained and signed with ML-DSA** (we dogfood the
post-quantum future), running **fully air-gapped**.

---

## 3. How the solution maps to the PS, clause by clause

| PS clause | LATTICE mechanism |
|-----------|-------------------|
| (i) Catalogue all artefacts across 6 surfaces | Six collectors → one normalised CycloneDX CBOM |
| (ii) Quantum risk assessment, risk to sensitive data | Quantum Breakability map + Data-Flow Graph tying assets to classified data |
| (iii) Classify by type / lifetime / criticality; Mosca | Graph-derived data lifetime → Mosca computed per asset, not guessed |
| (iv) Recommend PQC / hybrid by risk, latency, cost | Agility-aware advisor with FIPS 203/204/205 + latency/size deltas |
| Deliverable: standardised report | CycloneDX 1.6 CBOM (JSON), signed PDF |
| Deliverable: interactive GUI | Web cockpit: inventory, graph, risk heatmap, Mosca timeline, roadmap |
| Deliverable: scan repos, binaries, libs, containers | Collectors 1–3 cover exactly these; 4–6 extend the reach |

---

## 4. A worked example (why it is tangible, not a slogan)

A payment gateway's TLS handshake negotiates **ECDHE**:

1. **Discover** - the source collector sees the handshake code; the runtime collector
   captures a real handshake. Liveness = **Confirmed**.
2. **Connect** - the data-flow graph shows this endpoint is **internet-facing** and
   **protects card data** classified with a **10-year** secrecy requirement.
3. **Decide**
   - Quantum Breakability = 1.0 (ECDHE is Shor-breakable).
   - Mosca: X(10) + Y(migration) > Z(~2030) → **migrate now**.
   - HNDL Index lands near the top of the estate.
   - But the code calls **OpenSSL EVP**, so the Crypto-Agility Score is high → the fix is a
     **cheap hybrid X25519 + ML-KEM swap**.
4. **Recommend** - LATTICE ranks it **do-first, low-cost**, with the exact hybrid suite and
   the handshake-size delta.

A flat CBOM could produce *none* of that ranking. That gap is the product.

---

## 5. The unfair-advantage line

> Every competitor, and even NIST, admits two things are missing: **confirmed usage**
> (not just capability) and a **crypto-agility score**. LATTICE makes both first-class,
> then uses them to rank quantum risk by what an adversary can actually harvest today.

The engineering that makes this real is in [architecture.md](architecture.md).
