"use client";

import { useState } from "react";
import { ArrowCounterClockwise, Eye, FileArrowDown, FolderLock, Play, TerminalWindow, WifiSlash } from "@phosphor-icons/react";
import { probes } from "@/data/site";

const ICONS: Record<string, typeof Play> = {
  net: WifiSlash, exec: TerminalWindow, outside: FolderLock, modify: FolderLock, read: Eye, write: FileArrowDown,
};

type Line = { label: string; layer: string; result: string };

/** Replays the recorded results of `lattice sandbox-check`, one probe at a time. */
export default function SandboxProbe() {
  const [lines, setLines] = useState<Line[]>([]);
  const run = (ids: string[]) =>
    setLines((prev) => [...prev, ...probes.filter((p) => ids.includes(p.id)).map((p) => ({ label: p.label.toLowerCase(), layer: p.layer, result: p.expected }))].slice(-8));

  return (
    <div className="card probe-panel">
      <h3>Try to make it phone home</h3>
      <p>Each button replays what <code>lattice sandbox-check</code> recorded on a real machine.</p>
      <div className="probe-buttons">
        {probes.map((p) => {
          const Icon = ICONS[p.id];
          return (
            <button key={p.id} type="button" onClick={() => run([p.id])}>
              <Icon size={20} weight="duotone" />
              {p.label}
            </button>
          );
        })}
      </div>
      <div className="term" aria-live="polite">
        <div className="cmd">$ lattice sandbox-check</div>
        {lines.length === 0 && <div># press a probe above</div>}
        {lines.map((l, i) => (
          <div key={i} className="fresh">
            <span className="ok">ok</span>{"   "}{l.label.padEnd(32, " ")} {l.layer.padEnd(12, " ")} observed{" "}
            <span className={l.result === "denied" ? "denied" : "allowed"}>{l.result}</span>
          </div>
        ))}
        <span className="cursor" />
      </div>
      <div className="cta">
        <button type="button" className="btn" onClick={() => run(probes.map((p) => p.id))}><Play size={16} weight="fill" />Run all six</button>
        <button type="button" className="btn" onClick={() => setLines([])}><ArrowCounterClockwise size={16} weight="bold" />Clear</button>
      </div>
    </div>
  );
}
