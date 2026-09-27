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

The page is told in six chapters. Each opens with one short line that holds the screen while it
is scrolled into focus (`Chapter`), followed by an interactive part:

| Component | What it does |
|---|---|
| `HalftoneMark` | The lattice mark in dots; a lens follows the cursor, or drifts on its own |
| `Harvest` | Traffic recorded in 2026, by data class: sealed, readable, or past secrecy in a chosen year |
| `EvidenceExplorer` | The nine kinds of evidence, each with a real finding |
| `LaserFlow` + `Listeners` | Full width: a beam falls onto the runtimes `lattice trace` listens inside (OpenSSL, BoringSSL, AWS-LC, rustls, Go, Java), each named in a TechText wordmark over a tab bar |
| `MoscaLab` | X + Y against Z for any data class and agility score |
| `RoadmapExplorer` | The demo estate's four waves and their changes |
| `SandboxProbe` | Replays the probes of `lattice sandbox-check` |
| `HalftoneMark` with `text` | The closing word, LATTICE, in dots under the same lens |
| `ScrollRail` | A chapter scroll bar at the right edge, and the progress line under the navigation |

Text and motion come from [React Bits](https://reactbits.dev), kept in `src/components/bits`, each
file noting any change from the published version: TechText, DecryptedText, RotatingText, TextType,
BlurText, ShinyText, CountUp, ScrollVelocity, SpotlightCard, AnimatedContent, Magnet and ClickSpark.
Everything holds still when the system asks for reduced motion.

## Credits

- Animations: [React Bits](https://reactbits.dev) by David Haz (MIT + Commons Clause; used as part of
  this site, not redistributed on its own). LaserFlow is ported to plain WebGL, with a falling beam,
  a white-hot core and sparks added.
- Icons: [Phosphor](https://phosphoricons.com) (MIT).
- Type: Satoshi from [Fontshare](https://www.fontshare.com) (Indian Type Foundry, loaded from its CDN),
  Plus Jakarta Sans and JetBrains Mono through `next/font`.
