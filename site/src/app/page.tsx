import {
  ArrowUpRight, ChartBar, Fingerprint, GithubLogo, HardDrives, MagnifyingGlass, Pulse, SealCheck, ShareNetwork, Signature,
} from "@phosphor-icons/react/dist/ssr";
import AnimatedContent from "@/components/bits/AnimatedContent";
import BlurText from "@/components/bits/BlurText";
import ClickSpark from "@/components/bits/ClickSpark";
import CountUp from "@/components/bits/CountUp";
import DecryptedText from "@/components/bits/DecryptedText";
import Magnet from "@/components/bits/Magnet";
import RotatingText from "@/components/bits/RotatingText";
import ScrollVelocity from "@/components/bits/ScrollVelocity";
import ShinyText from "@/components/bits/ShinyText";
import SpotlightCard from "@/components/bits/SpotlightCard";
import TextType from "@/components/bits/TextType";
import Chapter from "@/components/Chapter";
import CipherTicker from "@/components/CipherTicker";
import EvidenceExplorer from "@/components/EvidenceExplorer";
import HalftoneMark from "@/components/HalftoneMark";
import Harvest from "@/components/Harvest";
import LaserFlow from "@/components/LaserFlow";
import LatticeLogo from "@/components/LatticeLogo";
import Listeners from "@/components/Listeners";
import MoscaLab from "@/components/MoscaLab";
import RoadmapExplorer from "@/components/RoadmapExplorer";
import SandboxProbe from "@/components/SandboxProbe";
import ScrollRail from "@/components/ScrollRail";
import { REPO, stats } from "@/data/site";

const NAV = [
  ["#why", "Why now"], ["#find", "How it works"], ["#proof", "Proof"], ["#deadline", "Deadlines"], ["#plan", "Plan"], ["#trust", "Trust"],
] as const;

const CHAPTERS = [
  { id: "why", label: "The letter" }, { id: "find", label: "Find" }, { id: "proof", label: "Proof" }, { id: "deadline", label: "Deadline" },
  { id: "plan", label: "Plan" }, { id: "trust", label: "Trust" },
];

const loop = { type: "spring", damping: 30, stiffness: 380 } as const;

export default function Home() {
  return (
    <div className="page">
      <div className="rails" aria-hidden="true" />
      <ClickSpark />
      <ScrollRail items={CHAPTERS} />

      <div className="nav-shell">
        <header className="nav">
          <a className="brand" href="#top" aria-label="LATTICE home"><LatticeLogo size={22} />LATTICE</a>
          <nav className="nav-links" aria-label="Sections">
            {NAV.map(([href, label]) => (
              <a key={href} href={href}><DecryptedText text={label} animateOn="hover" speed={30} maxIterations={8} characters="ABCDEF0123456789#/" encryptedClassName="enc" /></a>
            ))}
          </nav>
          <a className="btn btn-dark" href={REPO} style={{ paddingRight: 16 }}><GithubLogo size={17} weight="fill" />GitHub</a>
          <span className="nav-progress" aria-hidden="true"><i /></span>
        </header>
      </div>

      <main id="top">
        {/* ---------- hero ---------- */}
        <section className="hero" aria-labelledby="hero-title">
          <div className="wrap">
            <div className="hero-grid">
              <div className="hero-copy">
                <h1 id="hero-title">
                  <span className="h1-row">
                    See every{" "}
                    <RotatingText
                      texts={["cipher.", "key.", "certificate.", "handshake.", "protocol."]}
                      mainClassName="rot" splitLevelClassName="rot-split"
                      staggerFrom="last" staggerDuration={0.025} rotationInterval={2600}
                      initial={{ y: "100%", opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: "-115%", opacity: 0 }}
                      transition={loop}
                    />
                  </span>
                  <span className="accent">Fix what breaks first.</span>
                </h1>
                <p className="lead">
                  One offline scan finds the cryptography across an estate. Then LATTICE shows what a quantum computer breaks first, and when.
                </p>
                <div className="cta">
                  <Magnet>
                    <a className="btn btn-dark" href={REPO}>
                      <GithubLogo size={18} weight="fill" />View on GitHub<span className="arrow"><ArrowUpRight size={15} weight="bold" /></span>
                    </a>
                  </Magnet>
                  <Magnet><a className="btn" href="#proof"><Pulse size={16} weight="bold" />See it listen</a></Magnet>
                </div>
                <CipherTicker />
              </div>
              <div className="mark-card">
                <span className="corner tl" /><span className="corner tr" /><span className="corner bl" /><span className="corner br" />
                <HalftoneMark />
                <div className="mark-status">
                  <span className="live"><i /><span><b>Sandbox on</b>, offline</span></span>
                  <TextType
                    as="span" className="typed"
                    text={["lattice scan ./estate", "lattice trace --duration 300", "lattice sandbox-check", "lattice ci --fail-on high"]}
                    typingSpeed={55} deletingSpeed={25} pauseDuration={1800} cursorCharacter="_"
                  />
                </div>
              </div>
            </div>
            <div className="stats">
              {stats.map((s, k) => (
                <AnimatedContent key={s.label} distance={40} delay={k * 0.08} duration={0.7}>
                  <SpotlightCard className="stat" spotlightColor="rgba(255, 91, 26, 0.18)">
                    <b className="num"><CountUp to={s.to} separator="," duration={1.6} delay={0.15 + k * 0.1} />{s.suffix ?? ""}</b>
                    <span>{s.label}</span>
                  </SpotlightCard>
                </AnimatedContent>
              ))}
            </div>
          </div>
        </section>

        <div className="velocity-band" aria-hidden="true">
          <ScrollVelocity
            velocity={36} numCopies={5}
            texts={[
              <span key="old" className="v-old">RSA-2048 · ECDSA P-256 · X25519 · 3DES-CBC · TLS 1.0 · MD5 · AES-ECB ·</span>,
              <span key="new" className="v-new">ML-KEM-768 · ML-DSA-65 · SLH-DSA · AES-256-GCM · SHA-384 · X25519MLKEM768 ·</span>,
            ]}
          />
        </div>

        {/* ---------- 1. the letter ---------- */}
        <Chapter id="why" tone="dark">
          <div className="film-letter">
            <dl>
              <dt>FROM</dt><dd>an adversary, 2032</dd>
              <dt>TO</dt><dd>the operators of payments-api</dd>
            </dl>
            <TextType
              as="h2" className="film-line"
              text="Thank you for the traffic you sent us in 2026. We opened it this morning."
              typingSpeed={38} initialDelay={350} loop={false} startOnVisible cursorCharacter="_"
            />
            <small>A thought experiment. The recording in LATTICE&apos;s demo estate is real.</small>
          </div>
        </Chapter>

        <section className="section" aria-labelledby="harvest-title">
          <div className="wrap">
            <div className="section-head center">
              <h2 id="harvest-title">The recording has <span className="accent">already started.</span></h2>
              <p className="loop-line">
                <RotatingText
                  texts={["Harvest now, decrypt later.", "Trust now, forge later."]} splitBy="words"
                  mainClassName="rot-words" staggerDuration={0.06} rotationInterval={3200}
                  initial={{ y: "60%", opacity: 0, filter: "blur(6px)" }} animate={{ y: 0, opacity: 1, filter: "blur(0px)" }} exit={{ y: "-60%", opacity: 0, filter: "blur(6px)" }}
                  transition={loop}
                />
              </p>
            </div>
            <AnimatedContent distance={60}><Harvest /></AnimatedContent>
          </div>
        </section>

        {/* ---------- 2. find ---------- */}
        <Chapter id="find" text="Find every cipher, *wherever* it *hides.*" note="source · binaries · certificates · config · IaC · images · traffic · processes · key custody" />

        <section className="section tight" aria-label="How LATTICE works">
          <div className="wrap">
            <div className="pipeline">
              {[
                { n: "01", Icon: MagnifyingGlass, t: "Discover", d: "Nine collectors read the estate. Nothing is run." },
                { n: "02", Icon: ShareNetwork, t: "Connect", d: "Every finding is tied to the data it protects." },
                { n: "03", Icon: ChartBar, t: "Decide", d: "Risk, deadline, fix and cost for every asset." },
              ].map(({ n, Icon, t, d }, k) => (
                <AnimatedContent key={n} distance={50} delay={k * 0.12}>
                  <SpotlightCard className="stage" spotlightColor="rgba(255, 91, 26, 0.16)">
                    <div className="stage-top"><span className="stage-icon"><Icon size={26} weight="duotone" /></span><span className="stage-n">{n}</span></div>
                    <h3>{t}</h3>
                    <p>{d}</p>
                  </SpotlightCard>
                </AnimatedContent>
              ))}
            </div>
            <AnimatedContent distance={60}><EvidenceExplorer /></AnimatedContent>
          </div>
        </section>

        {/* ---------- 3. proof ---------- */}
        <Chapter id="proof" tone="dark" text="Not what *could* run. What *does* run." note="kernel uprobes · OpenSSL · BoringSSL · AWS-LC · rustls · Go · Java" />

        <section className="proof" aria-labelledby="proof-title">
          <LaserFlow targetId="runtime-panel" />
          <div className="proof-inner">
            <div className="proof-head">
              <h2 id="proof-title">Watch cryptography <span className="accent">happen.</span></h2>
              <p className="lead"><code>lattice trace</code> listens inside running programs, from the kernel. No source, no restart, no agent. What it sees is marked Confirmed.</p>
            </div>
            <Listeners />
          </div>
        </section>

        {/* ---------- 4. deadline ---------- */}
        <Chapter id="deadline" text="Every asset gets a *deadline.*" note="X + Y > Z  means the data is still secret when the quantum computer arrives" />

        <section className="section tight" aria-labelledby="mosca-title">
          <div className="wrap split">
            <div className="section-head">
              <h2 id="mosca-title" className="equation-big">
                <span className="x">X</span> + <span className="y">Y</span> &gt; <span className="z">Z</span>
              </h2>
              <dl className="terms">
                <div><dt className="x">X</dt><dd>years the data must stay secret</dd></div>
                <div><dt className="y">Y</dt><dd>years the migration takes</dd></div>
                <div><dt className="z">Z</dt><dd>years until Q-day, 2030 to 2035</dd></div>
              </dl>
            </div>
            <AnimatedContent distance={60}><MoscaLab /></AnimatedContent>
          </div>
        </section>

        {/* ---------- 5. plan ---------- */}
        <Chapter id="plan" text="Then a plan, with *dates* and a *budget.*" note="34 changes · 4 waves · 167.5 person-weeks · due 2027 to 2029" />

        <section className="section tight" aria-label="The migration roadmap">
          <div className="wrap">
            <AnimatedContent distance={60}><RoadmapExplorer /></AnimatedContent>
          </div>
        </section>

        {/* ---------- 6. trust ---------- */}
        <Chapter id="trust" tone="dark" text="A scanner that *cannot* leak what it reads." note="landlock · seccomp · no network · no programs · targets read-only" />

        <section className="section tight" aria-label="Why LATTICE can be trusted">
          <div className="wrap trust-grid">
            <AnimatedContent distance={60}><SandboxProbe /></AnimatedContent>
            <div className="pillars">
              {[
                { Icon: Signature, t: "Signed with ML-DSA-65", d: "Change one byte and verification names the part." },
                { Icon: Fingerprint, t: "Reproducible", d: "The same bytes on Linux, Windows and macOS." },
                { Icon: SealCheck, t: "It inventories itself", d: "Every release ships its own CBOM and SBOM." },
                { Icon: HardDrives, t: "Air-gap ready", d: "Signed updates, with rollback protection." },
              ].map(({ Icon, t, d }, k) => (
                <AnimatedContent key={t} distance={40} delay={k * 0.08}>
                  <SpotlightCard className="pillar" spotlightColor="rgba(255, 91, 26, 0.16)">
                    <span className="glyph"><Icon size={24} weight="duotone" /></span>
                    <h3>{t}</h3>
                    <p>{d}</p>
                  </SpotlightCard>
                </AnimatedContent>
              ))}
            </div>
          </div>
        </section>

        {/* ---------- closing ---------- */}
        <section className="closing-section" aria-labelledby="close-title">
          <div className="wrap closing">
            <div aria-hidden="true"><BlurText text="India's deadline starts with an inventory." className="closing-title" delay={90} animateBy="words" direction="bottom" /></div>
            <h2 id="close-title" className="sr-only">India&apos;s deadline starts with an inventory.</h2>
            <p className="lead">
              <ShinyText text="The inventory, the proof and the plan. One offline binary you can verify." color="#55544F" shineColor="#FF5B1A" speed={3.2} spread={110} />
            </p>
            <div className="cta">
              <Magnet>
                <a className="btn btn-dark" href={REPO}><GithubLogo size={18} weight="fill" />Read the code<span className="arrow"><ArrowUpRight size={15} weight="bold" /></span></a>
              </Magnet>
            </div>
            <div className="standards">
              <span>FIPS 203</span><span>FIPS 204</span><span>FIPS 205</span><span>NIST IR 8547</span><span>CycloneDX 1.6</span><span>DST Task Force 2026</span>
            </div>
          </div>
          <div className="word-wrap">
            <div className="halftone-word"><HalftoneMark text="LATTICE" /></div>
            <p className="word-hint">Move the cursor across the word</p>
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
              Animations from React Bits by David Haz (MIT + Commons Clause): LaserFlow, TechText, DecryptedText, RotatingText,
              TextType, ScrollReveal, ScrollVelocity, BlurText, ShinyText, CountUp, SpotlightCard, AnimatedContent, Magnet and ClickSpark.
              Icons from Phosphor (MIT). Type set in Satoshi (Indian Type Foundry) and Plus Jakarta Sans.
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
