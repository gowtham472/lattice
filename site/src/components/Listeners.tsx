"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import DecryptedText from "@/components/bits/DecryptedText";
import TechText from "@/components/bits/TechText";
import { runtimes, trace } from "@/data/site";

const DWELL = 7;   // seconds each runtime holds the stage before the next, until someone picks one

/**
 * The runtimes `lattice trace` listens inside: a wordmark of the one in focus, and a full-width
 * tab bar over what LATTICE listens to there and what it reads. The laser lands on this panel.
 */
export default function Listeners({ aside }: { aside?: ReactNode }) {
  const [i, setI] = useState(runtimes.findIndex((r) => r.id === "rustls"));
  const [auto, setAuto] = useState(true);
  const [inView, setInView] = useState(false);
  const panel = useRef<HTMLDivElement>(null);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const r = runtimes[i];

  useEffect(() => {
    const el = panel.current;
    if (!el) return;
    const io = new IntersectionObserver((e) => setInView(e[0]?.isIntersecting ?? false), { threshold: 0.3 });
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const pick = (k: number, focus = false) => {
    const next = (k + runtimes.length) % runtimes.length;
    setI(next);
    setAuto(false);
    if (focus) tabs.current[next]?.focus();
  };

  // a spotlight that follows the cursor across the panel, after SpotlightCard in React Bits
  const onMove = (e: React.MouseEvent) => {
    const el = panel.current;
    if (!el) return;
    const b = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - b.left}px`);
    el.style.setProperty("--my", `${e.clientY - b.top}px`);
  };

  return (
    <div className="listen">
      <div className="listen-top">
      <div className="listen-word fade-in" key={r.id}>
        <TechText align="left"
          text={r.name} fontFamily="Satoshi, sans-serif" fontWeight={700} fontSize={300} letterSpacing={-0.045}
          color="#EDEDEA" accentColor="#FF5B1A" reach={180} dashLength={5} dashGap={3} strokeWidth={1.4} specks={14}
        />
      </div>
      {aside && <div className="listen-aside">{aside}</div>}
      </div>

      <div className="runtime-panel" id="runtime-panel" ref={panel} onMouseMove={onMove}>
        <div
          className={`runtime-tabs${auto ? "" : " manual"}${inView ? "" : " paused"}`}
          role="tablist"
          aria-label="Runtimes lattice trace listens inside"
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") { e.preventDefault(); pick(i + 1, true); }
            if (e.key === "ArrowLeft") { e.preventDefault(); pick(i - 1, true); }
          }}
        >
          {runtimes.map((x, k) => (
            <button
              key={x.id}
              ref={(el) => { tabs.current[k] = el; }}
              type="button" role="tab" id={`rt-${x.id}`} aria-selected={k === i} aria-controls="rt-panel" tabIndex={k === i ? 0 : -1}
              onClick={() => pick(k)}
            >
              <span className="rt-n">{String(k + 1).padStart(2, "0")}</span>
              <b>{x.name}</b>
              <small>{x.how}</small>
              {k === i && auto && (
                <i className="rt-progress" style={{ animationDuration: `${DWELL}s` }} onAnimationEnd={() => setI((n) => (n + 1) % runtimes.length)} />
              )}
            </button>
          ))}
        </div>

        <div className="runtime-body" role="tabpanel" id="rt-panel" aria-labelledby={`rt-${r.id}`} key={r.id}>
          <div className="rb-col fade-in">
            <span className="rb-label">Listens through</span>
            <h3>{r.how}</h3>
            <p>{r.detail}</p>
          </div>
          <div className="rb-col fade-in">
            <span className="rb-label">Listens to</span>
            <ul className={`rb-probes${r.id === "java" ? " events" : ""}`}>
              {r.listens.map((f, k) => (
                <li key={f} style={{ animationDelay: `${k * 60}ms` }}>
                  <DecryptedText text={f} animateOn="view" sequential speed={12} characters="abcdef0123456789_" encryptedClassName="enc" />
                </li>
              ))}
            </ul>
          </div>
          <div className="rb-col fade-in">
            {r.id === "rustls" ? (
              <>
                <span className="rb-label">Recorded live, lattice-srv, 12 s</span>
                <ul className="rb-recorded">
                  {trace.map((t) => (
                    <li key={t.fn}><span className="alg"><i className={t.kind} />{t.alg}</span><em>{t.calls}</em></li>
                  ))}
                </ul>
              </>
            ) : (
              <>
                <span className="rb-label">Reads</span>
                <p className="rb-reads">{r.reads}</p>
              </>
            )}
            <p className="rb-note">{r.note}</p>
          </div>
        </div>
      </div>
    </div>
  );
}
