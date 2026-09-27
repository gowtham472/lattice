"use client";

import { useState } from "react";
import { dataClasses, policy } from "@/data/site";

const FROM = policy.assessmentYear;       // traffic recorded now
const TO = 2041;                           // the axis ends here; longer secrets run off it
const pct = (year: number) => ((Math.min(Math.max(year, FROM), TO) - FROM) / (TO - FROM)) * 100;

/** Traffic recorded in 2026, by data class: when does a quantum computer read it while it still matters? */
export default function Harvest() {
  const [year, setYear] = useState(2032);
  const [qday, setQday] = useState<number>(policy.qDayEarliest);

  const rows = dataClasses.map((c) => {
    const end = FROM + c.years;
    const state = c.years === 0 ? "expired" : year < qday ? (year < end ? "sealed" : "expired") : year < end ? "exposed" : "expired";
    return { ...c, end, state };
  });
  const exposed = rows.filter((r) => r.state === "exposed").length;

  return (
    <div className="card harvest">
      <div className="harvest-controls">
        <div className="control">
          <div className="control-top">
            <label htmlFor="harvest-year">Looking back from</label>
            <output htmlFor="harvest-year" className="num">{year}</output>
          </div>
          <input id="harvest-year" type="range" min={FROM} max={TO} step={1} value={year} onChange={(e) => setYear(Number(e.target.value))} />
        </div>
        <div className="control">
          <div className="control-top"><span>Q-day</span></div>
          <div className="seg" role="group" aria-label="When a quantum computer arrives">
            <button type="button" aria-pressed={qday === policy.qDayEarliest} onClick={() => setQday(policy.qDayEarliest)}>{policy.qDayEarliest}, earliest</button>
            <button type="button" aria-pressed={qday === policy.qDayLatest} onClick={() => setQday(policy.qDayLatest)}>{policy.qDayLatest}, latest</button>
          </div>
        </div>
      </div>

      <div className="lanes-wrap">
        <div className="lanes">
          {rows.map((r) => (
            <div className="lane-row" key={r.id}>
              <div className="who"><b>{r.name}</b><span>{r.years === 0 ? "no secrecy needed" : `secret for ${r.years} years`}</span></div>
              <div className="lane" aria-hidden="true">
                {r.years > 0 && <span className="secret" style={{ left: 0, width: `${pct(r.end)}%` }} />}
                {r.end > qday && <span className="open" style={{ left: `${pct(qday)}%`, width: `${pct(r.end) - pct(qday)}%` }} />}
                {r.end > TO && <span className="more">to {r.end}</span>}
              </div>
              <span className={`state-tag ${r.state}`}>{r.state === "sealed" ? "Sealed" : r.state === "exposed" ? "Readable" : "Past secrecy"}</span>
            </div>
          ))}
        </div>
        <div className="lanes-marks" aria-hidden="true">
          <span className="qline" style={{ left: `${pct(qday)}%` }} />
          <span className="yline" style={{ left: `${pct(year)}%` }} />
        </div>
        <div className="lanes-axis" aria-hidden="true">
          {[2026, 2030, 2035, 2041].map((y) => <span key={y} style={{ left: `${pct(y)}%` }}>{y}</span>)}
        </div>
      </div>

      <div className={`harvest-summary${exposed === 0 ? " calm" : ""}`} aria-live="polite">
        <b>{exposed}</b>
        <span>
          {year < qday
            ? `In ${year} the recording is still sealed. It is already stored, waiting for ${qday}.`
            : exposed === 0
              ? `By ${year} nothing recorded in ${FROM} still needs to stay secret.`
              : `of six kinds of data recorded in ${FROM} can be read in ${year}, while they still have to stay secret.`}
        </span>
      </div>
      <div className="legend">
        <span><i style={{ background: "#E4E3DD" }} />how long it must stay secret</span>
        <span><i style={{ background: "var(--accent)" }} />readable after Q-day, still secret</span>
        <span><i style={{ background: "transparent", borderLeft: "2px dashed var(--pq)", width: 2, borderRadius: 0 }} />Q-day</span>
      </div>
    </div>
  );
}
