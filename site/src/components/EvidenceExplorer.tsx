"use client";

import { useState } from "react";
import {
  CaretRight, Certificate, Cloud, Code, Cpu, GearSix, LockKey, Package, Pulse, SealCheck, ShieldWarning, Warning, WaveSine, Info,
} from "@phosphor-icons/react";
import { surfaces } from "@/data/site";

const ICONS: Record<string, typeof Code> = {
  source: Code, binary: Cpu, pki: Certificate, config: GearSix, iac: Cloud, container: Package, capture: WaveSine, trace: Pulse, custody: LockKey,
};
const TONE_ICON = { late: ShieldWarning, urgent: Warning, safe: SealCheck, info: Info };

/** The nine kinds of evidence, each with a real finding from the demo estate or a recorded run. */
export default function EvidenceExplorer() {
  const [selected, setSelected] = useState("source");
  const s = surfaces.find((x) => x.id === selected) ?? surfaces[0];
  const ToneIcon = TONE_ICON[s.tone];

  return (
    <div className="explorer">
      <div className="card surface-list" role="tablist" aria-label="Kinds of evidence" aria-orientation="vertical">
        {surfaces.map((x) => {
          const Icon = ICONS[x.id];
          return (
            <button
              key={x.id}
              role="tab"
              id={`tab-${x.id}`}
              aria-selected={x.id === selected}
              aria-controls="evidence-panel"
              onClick={() => setSelected(x.id)}
              onMouseEnter={() => setSelected(x.id)}
            >
              <span className="ico"><Icon size={18} weight="duotone" /></span>
              {x.name}
              <CaretRight className="chev" size={16} weight="bold" />
            </button>
          );
        })}
      </div>
      <div className="card evidence" role="tabpanel" id="evidence-panel" aria-labelledby={`tab-${s.id}`}>
        <h3>{s.name}</h3>
        <p className="evidence-what">{s.what}</p>
        <div className="file" key={s.id}>
          <span className="k">read</span> <span className="v">{s.path}</span>
          <span className="scan" aria-hidden="true" />
          <span className="k">rule</span> {s.rule}
          <br />
          <span className="k">matched</span> {s.token}
        </div>
        <div className={`result tone-${s.tone}`}>
          <span className="glyph"><ToneIcon size={22} weight="duotone" /></span>
          <div>
            <h3>{s.finding}</h3>
            <p>{s.verdict}</p>
          </div>
        </div>
        <dl className="proven">
          <div>
            <dt>Liveness</dt>
            <dd><b className={`live-${s.liveness.toLowerCase()}`}>{s.liveness}</b>{s.reason}</dd>
          </div>
          <div>
            <dt>Evidence grade</dt>
            <dd><b>{s.grade ?? "n/a"}</b>{s.grade === "B" ? "two independent layers agree" : s.grade === "C" ? "one layer of evidence" : "not graded in this run"}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
