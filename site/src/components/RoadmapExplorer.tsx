"use client";

import { useState } from "react";
import { UsersThree } from "@phosphor-icons/react";
import { waves } from "@/data/site";

const MAX = Math.max(...waves.map((w) => w.weeks));

/** The demo estate's real roadmap: four waves, each due against the DST timeline. */
export default function RoadmapExplorer() {
  const [n, setN] = useState(1);
  const w = waves.find((x) => x.n === n) ?? waves[0];

  return (
    <div className="roadmap">
      <div className="card wave-tabs" role="tablist" aria-label="Roadmap waves">
        {waves.map((x) => (
          <button key={x.n} role="tab" aria-selected={x.n === n} aria-controls="wave-panel" id={`wave-${x.n}`} onClick={() => setN(x.n)}>
            <span className="wname">Wave {x.n} · {x.name}</span>
            <span className="wdue">{x.due === "no deadline" ? "no deadline" : `due ${x.due}`}</span>
            <span className="wbar"><i style={{ width: `${(x.weeks / MAX) * 100}%` }} /></span>
          </button>
        ))}
      </div>
      <div className="card wave-detail" role="tabpanel" id="wave-panel" aria-labelledby={`wave-${w.n}`}>
        <div className="wave-detail-head">
          <b className="num">{w.weeks} person-weeks</b>
          <span>{w.count} changes · {w.due === "no deadline" ? "no deadline" : `due ${w.due}`}</span>
        </div>
        <ul className="items">
          {w.items.map((i, k) => (
            <li key={k}>
              <b>{i.name}{i.where && <small>{i.where}</small>}</b>
              {i.action && <span>{i.action}</span>}
              <em>{i.weeks} pw</em>
            </li>
          ))}
        </ul>
        <div className="team">
          <UsersThree size={22} weight="duotone" />
          <span><b>0.7 engineers working full time</b> meet every DST deadline for this estate: 34 changes, 167.5 person-weeks.</span>
        </div>
      </div>
    </div>
  );
}
