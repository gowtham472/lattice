"use client";

import { useRef, useState } from "react";
import { CaretLeft, CaretRight } from "@phosphor-icons/react";
import { DEMO_LENGTH, scenes } from "@/data/site";

const clock = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

/** The three-minute demo video, scene by scene: a scrubber over the real running order. */
export default function Storyboard() {
  const [i, setI] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const s = scenes[i];
  const end = scenes[i + 1]?.at ?? DEMO_LENGTH;

  const go = (k: number) => {
    const next = Math.max(0, Math.min(scenes.length - 1, k));
    setI(next);
    tabs.current[next]?.focus();
  };

  return (
    <div className="card board">
      <div className="scrubber">
        <div
          className="segments"
          role="tablist"
          aria-label="Scenes of the demo video"
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") { e.preventDefault(); go(i + 1); }
            if (e.key === "ArrowLeft") { e.preventDefault(); go(i - 1); }
          }}
        >
          {scenes.map((x, k) => {
            const len = (scenes[k + 1]?.at ?? DEMO_LENGTH) - x.at;
            return (
              <button
                key={x.at}
                ref={(el) => { tabs.current[k] = el; }}
                role="tab"
                aria-selected={k === i}
                aria-label={`${clock(x.at)} ${x.title}`}
                tabIndex={k === i ? 0 : -1}
                className={x.key ? "key" : undefined}
                style={{ flex: `${len} 1 0` }}
                onClick={() => setI(k)}
                onMouseEnter={() => setI(k)}
              >
                <span>{k + 1}</span>
              </button>
            );
          })}
        </div>
        <div className="ticks" aria-hidden="true">
          {[0, 30, 60, 90, 120, 150, 180].map((t) => <span key={t} style={{ left: `${(t / DEMO_LENGTH) * 100}%` }}>{clock(t)}</span>)}
        </div>
      </div>

      <div className="scene" role="tabpanel" aria-live="polite">
        <time>
          {clock(s.at)}
          <small>to {clock(end)}</small>
        </time>
        <div>
          <h3>{s.title}</h3>
          <dl>
            <dt>On screen</dt><dd>{s.screen}</dd>
            <dt>The point</dt><dd>{s.point}</dd>
            {s.key && (<><dt>Weight</dt><dd style={{ color: "var(--accent-deep)", fontWeight: 600 }}>One of the two moments the video is built around.</dd></>)}
          </dl>
        </div>
      </div>
      <div className="board-nav">
        <button type="button" aria-label="Previous scene" disabled={i === 0} onClick={() => go(i - 1)}><CaretLeft size={18} weight="bold" /></button>
        <button type="button" aria-label="Next scene" disabled={i === scenes.length - 1} onClick={() => go(i + 1)}><CaretRight size={18} weight="bold" /></button>
      </div>
    </div>
  );
}
