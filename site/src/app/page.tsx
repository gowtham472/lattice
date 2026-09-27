import {
  ArrowUpRight, CheckCircle, Detective, FileCode, Fingerprint, GithubLogo, HardDrives, Lightning, MagnifyingGlass, Play,
  SealCheck, ShareNetwork, Signature, Cpu, ChartBar,
} from "@phosphor-icons/react/dist/ssr";
import EvidenceExplorer from "@/components/EvidenceExplorer";
import HalftoneMark from "@/components/HalftoneMark";
import Harvest from "@/components/Harvest";
import LaserFlow from "@/components/LaserFlow";
import LatticeLogo from "@/components/LatticeLogo";
import MoscaLab from "@/components/MoscaLab";
import RoadmapExplorer from "@/components/RoadmapExplorer";
import SandboxProbe from "@/components/SandboxProbe";
import Storyboard from "@/components/Storyboard";
import TraceCard from "@/components/TraceCard";
import { REPO, stats } from "@/data/site";

const NAV = [
  ["#why", "Why now"], ["#how", "How it works"], ["#proof", "Proof"], ["#mosca", "Deadlines"], ["#trust", "Trust"], ["#demo", "Demo"],
] as const;

export default function Home() {
  return (
    <div className="page">
      <div className="rails" aria-hidden="true" />

      <div className="nav-shell">
        <header className="nav">
          <a className="brand" href="#top" aria-label="LATTICE home"><LatticeLogo size={22} />LATTICE</a>
          <nav className="nav-links" aria-label="Sections">
            {NAV.map(([href, label]) => <a key={href} href={href}>{label}</a>)}
          </nav>
          <a className="btn btn-dark" href={REPO} style={{ paddingRight: 16 }}><GithubLogo size={17} weight="fill" />GitHub</a>
        </header>
      </div>

      <main id="top">
        <section className="hero" aria-labelledby="hero-title">
          <div className="wrap">
            <div className="hero-grid">
              <div className="hero-copy">
                <h1 id="hero-title"><span>See every cipher.</span><span className="accent">Fix what breaks first.</span></h1>
                <p className="lead">
                  LATTICE finds the cryptography across your code, binaries, certificates, configuration, containers, traffic and
                  running processes. Then it shows which secrets a quantum computer will read, when, and the cheapest safe fix,
                  dated against India&apos;s 2027 to 2029 deadline.
                </p>
                <div className="cta">
                  <a className="btn btn-dark" href={REPO}>
                    <GithubLogo size={18} weight="fill" />View on GitHub<span className="arrow"><ArrowUpRight size={15} weight="bold" /></span>
                  </a>
                  <a className="btn" href="#demo"><Play size={16} weight="fill" />Watch the demo flow</a>
                </div>
              </div>
              <div className="mark-card">
                <HalftoneMark />
                <div className="mark-status">
                  <span className="live"><i /><span><b>Sandbox on</b>, offline</span></span>
                  <span>Hover the lattice</span>
                </div>
              </div>
            </div>
            <div className="stats">
              {stats.map((s) => (
                <div className="stat" key={s.value}><b>{s.value}</b><span>{s.label}</span></div>
              ))}
            </div>
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="why" aria-labelledby="why-title">
          <div className="wrap split">
            <div className="section-head">
              <h2 id="why-title">The recording has already started.</h2>
              <p className="lead">
                Traffic recorded today can be decrypted once a quantum computer breaks RSA and elliptic curves. What decides the
                risk is how long each secret must stay secret. Drag the year and see what a 2026 recording gives away.
              </p>
              <div className="letter">
                <dl>
                  <dt>FROM</dt><dd>an adversary, 2032</dd>
                  <dt>TO</dt><dd>the operators of payments-api</dd>
                </dl>
                <blockquote>Thank you for the traffic you sent us in 2026. We opened it this morning.<span className="caret" aria-hidden="true" /></blockquote>
                <small>A thought experiment. The packet capture in LATTICE&apos;s demo estate is real.</small>
              </div>
              <div className="facts-list">
                <div className="fact-row">
                  <span className="glyph"><Detective size={20} weight="duotone" /></span>
                  <div><h3>Harvest now, decrypt later</h3><p>Confidentiality of long-lived data, such as identity and payment records.</p></div>
                </div>
                <div className="fact-row">
                  <span className="glyph"><Signature size={20} weight="duotone" /></span>
                  <div><h3>Trust now, forge later</h3><p>Authenticity of certificates, signed tokens and firmware while they stay trusted.</p></div>
                </div>
              </div>
            </div>
            <Harvest />
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="how" aria-labelledby="how-title">
          <div className="wrap">
            <div className="section-head">
              <h2 id="how-title">One pass from raw estate to a dated plan.</h2>
              <p className="lead">Three stages in one offline binary. Every finding keeps its file and line; every score keeps the terms it was computed from.</p>
            </div>
            <div className="pipeline">
              <article className="card stage">
                <div className="stage-top"><span className="stage-icon"><MagnifyingGlass size={26} weight="duotone" /></span><span className="stage-n">01</span></div>
                <h3>Discover every artefact</h3>
                <p>Collectors read nine kinds of evidence and merge them into one asset per algorithm, key or protocol.</p>
                <ul>
                  <li><CheckCircle size={15} weight="fill" /><span>Algorithm, key size, mode, padding and curve</span></li>
                  <li><CheckCircle size={15} weight="fill" /><span>Keys kept as fingerprints, never copied</span></li>
                </ul>
              </article>
              <article className="card stage">
                <div className="stage-top"><span className="stage-icon"><ShareNetwork size={26} weight="duotone" /></span><span className="stage-n">02</span></div>
                <h3>Connect it to what it protects</h3>
                <p>A crypto graph links entry points to functions, cryptography and data, each data class with its secrecy lifetime.</p>
                <ul>
                  <li><CheckCircle size={15} weight="fill" /><span>Capable, Configured or Confirmed, with the reason</span></li>
                  <li><CheckCircle size={15} weight="fill" /><span>Evidence graded A to D by independent layers</span></li>
                </ul>
              </article>
              <article className="card stage">
                <div className="stage-top"><span className="stage-icon"><ChartBar size={26} weight="duotone" /></span><span className="stage-n">03</span></div>
                <h3>Decide what to fix first</h3>
                <p>Quantum breakability, exposure, Mosca per asset and a crypto-agility score set the priority and the replacement.</p>
                <ul>
                  <li><CheckCircle size={15} weight="fill" /><span>Byte cost and effort in person-weeks</span></li>
                  <li><CheckCircle size={15} weight="fill" /><span>Four waves due against the DST timeline</span></li>
                </ul>
              </article>
            </div>
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="evidence" aria-labelledby="evidence-title">
          <div className="wrap">
            <div className="section-head">
              <h2 id="evidence-title">Nine kinds of evidence, one inventory.</h2>
              <p className="lead">Pick a source to see what LATTICE read, the rule that matched and what it concluded. Every example comes from the demo estate or a recorded run.</p>
            </div>
            <EvidenceExplorer />
          </div>
        </section>

        <section className="section proof" id="proof" aria-labelledby="proof-title">
          <LaserFlow targetId="trace-card" />
          <div className="wrap proof-grid">
            <div>
              <h2 id="proof-title">Evidence from the running system.</h2>
              <p className="lead" style={{ marginTop: 18 }}>
                A library that can do RSA is a different risk from a service that uses it. Every asset records how far it has been
                proven, and by what.
              </p>
              <div className="states">
                <div className="state">
                  <span className="glyph"><Cpu size={22} weight="duotone" /></span>
                  <div><h3>Capable <span>weight 0.4</span></h3><p>A library can do it: OpenSSL 3.0.13 inside the payments image.</p></div>
                </div>
                <div className="state">
                  <span className="glyph"><FileCode size={22} weight="duotone" /></span>
                  <div><h3>Configured <span>weight 0.7</span></h3><p>Code or configuration selects it: ssl_protocols TLSv1 in nginx.conf.</p></div>
                </div>
                <div className="state">
                  <span className="glyph"><SealCheck size={22} weight="duotone" /></span>
                  <div><h3>Confirmed <span>weight 1.0</span></h3><p>Reached from an entry point, seen on the wire, or called by a running process.</p></div>
                </div>
              </div>
              <ul className="tracers">
                <li><Lightning size={18} weight="fill" /><span>OpenSSL 3<small>libcrypto and libssl</small></span></li>
                <li><Lightning size={18} weight="fill" /><span>BoringSSL and AWS-LC<small>their own entry points</small></span></li>
                <li><Lightning size={18} weight="fill" /><span>rustls<small>on AWS-LC or ring</small></span></li>
                <li><Lightning size={18} weight="fill" /><span>Go<small>stripped binaries too</small></span></li>
                <li><Lightning size={18} weight="fill" /><span>Java<small>its Flight Recorder, no root</small></span></li>
                <li><Lightning size={18} weight="fill" /><span>Setup ignored<small>only real use is recorded</small></span></li>
              </ul>
            </div>
            <div className="trace-slot"><TraceCard /></div>
          </div>
        </section>

        <section className="section" id="mosca" aria-labelledby="mosca-title">
          <div className="wrap split">
            <div className="section-head">
              <h2 id="mosca-title">A deadline on one line of code.</h2>
              <p className="lead">
                Mosca adds how long data must stay secret (X) to how long the migration takes (Y) and compares it with the years
                before a quantum computer arrives (Z). LATTICE computes it for every asset it can break, from the path that reaches it.
              </p>
              <div className="facts-list">
                <div className="fact-row">
                  <span className="glyph"><FileCode size={20} weight="duotone" /></span>
                  <div><h3>payments-api/app/server.py:8</h3><p>POST /v1/payments reaches tokenize_card, which protects card numbers with RSA-2048. Agility 10, card data 10 years: already late.</p></div>
                </div>
              </div>
            </div>
            <MoscaLab />
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="roadmap" aria-labelledby="roadmap-title">
          <div className="wrap">
            <div className="section-head">
              <h2 id="roadmap-title">From findings to a dated budget.</h2>
              <p className="lead">
                Urgent changes that are cheap go first; urgent changes that need engineering follow. This is the real plan for the
                demo estate, each wave due against India&apos;s timeline.
              </p>
            </div>
            <RoadmapExplorer />
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="trust" aria-labelledby="trust-title">
          <div className="wrap">
            <div className="section-head">
              <h2 id="trust-title">A scanner that cannot leak what it reads.</h2>
              <p className="lead">Before it opens a single file, LATTICE asks the Linux kernel to take away its own network and its ability to start programs, and makes the estate read-only.</p>
            </div>
            <div className="trust-grid">
              <SandboxProbe />
              <div className="pillars">
                <div className="card pillar"><span className="glyph"><Signature size={24} weight="duotone" /></span><h3>Signed with ML-DSA-65</h3><p>CBOMs, PDF reports and release SBOMs carry FIPS 204 signatures. Change one byte and verification names the part.</p></div>
                <div className="card pillar"><span className="glyph"><Fingerprint size={24} weight="duotone" /></span><h3>Reproducible</h3><p>The same commit gives the same bytes. The demo&apos;s CBOM is identical on Linux, Windows and macOS.</p></div>
                <div className="card pillar"><span className="glyph"><SealCheck size={24} weight="duotone" /></span><h3>It inventories itself</h3><p>Every release ships LATTICE&apos;s own CBOM and a signed SBOM of everything inside.</p></div>
                <div className="card pillar"><span className="glyph"><HardDrives size={24} weight="duotone" /></span><h3>Air-gap ready</h3><p>Knowledge and rules are compiled in. Updates arrive as signed bundles with rollback protection.</p></div>
              </div>
            </div>
          </div>
        </section>

        <div className="divider" />

        <section className="section" id="demo" aria-labelledby="demo-title">
          <div className="wrap">
            <div className="section-head">
              <h2 id="demo-title">The demo, shot by shot.</h2>
              <p className="lead">Three minutes, ten scenes, everything live and rehearsed with scripts/demo.sh. The network stays off from the first scan to the last frame.</p>
            </div>
            <Storyboard />
          </div>
        </section>

        <div className="divider" />

        <section className="section" aria-labelledby="close-title">
          <div className="wrap">
            <div className="card closing">
              <div>
                <h2 id="close-title">India&apos;s deadline starts with an inventory.</h2>
                <p className="lead" style={{ marginTop: 16 }}>LATTICE delivers the inventory, the proof and the plan, in one offline binary you can verify.</p>
                <div className="standards">
                  <span>FIPS 203</span><span>FIPS 204</span><span>FIPS 205</span><span>NIST IR 8547</span><span>CycloneDX 1.6</span><span>DST Task Force 2026</span>
                </div>
              </div>
              <div className="cta">
                <a className="btn btn-dark" href={REPO}><GithubLogo size={18} weight="fill" />Read the code<span className="arrow"><ArrowUpRight size={15} weight="bold" /></span></a>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer>
        <div className="wrap foot">
          <div>
            <a className="brand" href="#top"><LatticeLogo size={22} />LATTICE</a>
            <p style={{ marginTop: 14 }}>
              Built for Smart India Hackathon 2026, problem statement SIH26164 from the National Technical Research Organisation,
              by team DoodleByte. Version 1.0.1, Apache License 2.0.
            </p>
            <p className="credits">
              Laser background ported from LaserFlow in React Bits by David Haz (MIT + Commons Clause). Icons from Phosphor (MIT).
              Type set in Satoshi (Indian Type Foundry) and Plus Jakarta Sans.
            </p>
          </div>
          <div className="foot-links">
            <a className="btn" href={REPO}><GithubLogo size={17} weight="fill" />github.com/gowtham472/lattice</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
