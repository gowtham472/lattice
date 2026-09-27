"use client";

import { useState } from "react";
import { HourglassMedium, SealCheck, ShieldWarning } from "@phosphor-icons/react";
import { dataClasses, policy } from "@/data/site";

const SPAN = 30;                                  // years shown: 2026 to 2056
const pct = (years: number) => (Math.min(Math.max(years, 0), SPAN) / SPAN) * 100;
const zEarliest = policy.qDayEarliest - policy.assessmentYear;   // 4
const zLatest = policy.qDayLatest - policy.assessmentYear;       // 9

const PRESETS = [
  { label: "RSA-2048 on /v1/payments", cls: "financial", cas: 10 },
  { label: "Session tokens, config-driven", cls: "credential", cas: 85 },
  { label: "Public checksums", cls: "public", cas: 85 },
];

/** Mosca's inequality, X + Y > Z, with the engine's own inputs (knowledge/policy.toml). */
export default function MoscaLab() {
  const [cls, setCls] = useState<string>("financial");
  const [cas, setCas] = useState(10);
  const data = dataClasses.find((d) => d.id === cls) ?? dataClasses[2];
  const X = data.years;
  const Y = Math.round((policy.baseYears + (100 - cas) * policy.yearsPerPoint) * 100) / 100;
  const total = Math.round((X + Y) * 100) / 100;
  const verdict = total > zLatest ? "late" : total > zEarliest ? "urgent" : "safe";
  const Icon = verdict === "safe" ? SealCheck : verdict === "late" ? ShieldWarning : HourglassMedium;

  return (
    <div className="card lab">
      <div className="presets">
        Try
        {PRESETS.map((p) => (
          <button key={p.label} type="button" onClick={() => { setCls(p.cls); setCas(p.cas); }}>{p.label}</button>
        ))}
      </div>
      <div className="lab-controls">
        <div className="control">
          <div className="control-top"><span id="mosca-data">What the cryptography protects (X)</span><output className="num">{X} years</output></div>
          <div className="seg" role="group" aria-labelledby="mosca-data">
            {dataClasses.map((d) => (
              <button key={d.id} type="button" aria-pressed={d.id === cls} onClick={() => setCls(d.id)} title={d.example}>{d.name}</button>
            ))}
          </div>
        </div>
        <div className="control">
          <div className="control-top">
            <label htmlFor="mosca-cas">Crypto-agility score, measured from code</label>
            <output htmlFor="mosca-cas" className="num">{cas}</output>
          </div>
          <input id="mosca-cas" type="range" min={0} max={100} step={5} value={cas} onChange={(e) => setCas(Number(e.target.value))} />
          <p className="equation">Migration time Y = 0.25 + (100 − {cas}) × 0.04 = <b>{Y.toFixed(2)} years</b></p>
        </div>
      </div>

      <div className="timeline" aria-hidden="true">
        <div className="track"><span>Y migrate<small>{Y.toFixed(2)} years</small></span><div className="bar"><i className="y" style={{ left: 0, width: `${pct(Y)}%` }} /></div></div>
        <div className="track"><span>X stay secret<small>{X} years after</small></span><div className="bar"><i className="x" style={{ left: `${pct(Y)}%`, width: `${pct(Y + X) - pct(Y)}%` }} /></div></div>
        <div className="track"><span>Z Q-day<small>{policy.qDayEarliest} to {policy.qDayLatest}</small></span><div className="bar"><i className="z" style={{ left: `${pct(zEarliest)}%`, width: `${pct(zLatest) - pct(zEarliest)}%` }} /></div></div>
        <div className="scale">
          {[0, 4, 9, 14, 19, 24, 30].map((y) => <span key={y} style={{ left: `${pct(y)}%` }}>{policy.assessmentYear + y}</span>)}
        </div>
      </div>

      <div className={`verdict ${verdict}`} aria-live="polite">
        <span className="glyph"><Icon size={26} weight="duotone" /></span>
        <div>
          <b>
            {verdict === "late" ? "Already late" : verdict === "urgent" ? "Migrate now" : "Safe margin"}: X + Y = {total} years
          </b>
          <p>
            {verdict === "late"
              ? `Even the latest Q-day, ${zLatest} years away, arrives while this data must still be secret.`
              : verdict === "urgent"
                ? `The earliest Q-day, ${zEarliest} years away, arrives first. There is still time before the latest.`
                : `The migration and the secrecy both end before the earliest Q-day, ${zEarliest} years away.`}
          </p>
        </div>
      </div>
    </div>
  );
}
