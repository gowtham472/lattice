# LATTICE site

The marketing site for LATTICE: a Next.js app exported as static HTML, CSS and JS.

```bash
npm ci
npm run dev      # http://localhost:3000
npm run build    # static site in out/, hostable on any web server or GitHub Pages
npm run lint
```

## What is on the page

Every number and example comes from LATTICE 1.0.1 runs, collected in `src/data/site.ts`: the demo
estate's scan and roadmap, the OpenSSL 3.5.5 golden scan, the risk policy
(`knowledge/policy.toml`), and the recorded `lattice trace` and `lattice sandbox-check` output.
The Mosca calculator uses the engine's own formula, Y = 0.25 + (100 − agility) × 0.04, and Q-day
range, 2030 to 2035.

| Component | What it does |
|---|---|
| `HalftoneMark` | The lattice mark in dots; a lens follows the cursor, or drifts on its own |
| `Harvest` | Traffic recorded in 2026, by data class: sealed, readable, or past secrecy in a chosen year |
| `EvidenceExplorer` | The nine kinds of evidence, each with a real finding |
| `LaserFlow` + `TraceCard` | A beam that lands on what `lattice trace` recorded inside LATTICE's own server |
| `MoscaLab` | X + Y against Z for any data class and agility score |
| `RoadmapExplorer` | The demo estate's four waves and their changes |
| `SandboxProbe` | Replays the probes of `lattice sandbox-check` |
| `Storyboard` | The three-minute demo video, scene by scene |

## Credits

- Laser background: LaserFlow from [React Bits](https://reactbits.dev) by David Haz, ported to plain
  WebGL (MIT + Commons Clause; used as part of this site, not redistributed on its own).
- Icons: [Phosphor](https://phosphoricons.com) (MIT).
- Type: Satoshi from [Fontshare](https://www.fontshare.com) (Indian Type Foundry, loaded from its CDN),
  Plus Jakarta Sans and JetBrains Mono through `next/font`.
