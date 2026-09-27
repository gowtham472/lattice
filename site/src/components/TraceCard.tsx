"use client";

import { useEffect, useRef, useState } from "react";
import { CheckCircle, Pulse } from "@phosphor-icons/react";
import DecryptedText from "@/components/bits/DecryptedText";
import { trace } from "@/data/site";

/** What `lattice trace` recorded inside LATTICE's own server while curl connected (a real test run). */
export default function TraceCard() {
  const [lit, setLit] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setInterval(() => setLit((i) => (i + 1) % trace.length), 1600);
    return () => clearInterval(id);
  }, []);

  // a spotlight that follows the cursor across the card, after SpotlightCard in React Bits
  const onMove = (e: React.MouseEvent) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${e.clientX - r.left}px`);
    el.style.setProperty("--my", `${e.clientY - r.top}px`);
  };

  return (
    <div className="trace" id="trace-card" ref={ref} onMouseMove={onMove}>
      <div className="trace-head">
        <Pulse size={18} weight="bold" />
        lattice trace
        <span className="rec"><i />recorded live</span>
      </div>
      <div className="trace-sub">lattice-srv · rustls on AWS-LC · 12 s · 4 TLS 1.3 connections from curl</div>
      <div className="trace-table">
        <table>
          <thead><tr><th>function called</th><th>algorithm</th><th>calls</th></tr></thead>
          <tbody>
            {trace.map((row, i) => (
              <tr key={row.fn} className={i === lit ? "lit" : undefined}>
                <td className="fn">
                  {i === lit
                    ? <DecryptedText key={`d${lit}`} text={row.fn} animateOn="view" sequential speed={14} characters="0123456789abcdef_" encryptedClassName="enc" />
                    : row.fn}
                </td>
                <td><span className="alg"><i className={row.kind} />{row.alg}</span></td>
                <td>{row.calls}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="trace-foot">
        <CheckCircle size={18} weight="fill" />
        <span>Hybrid X25519MLKEM768, seen inside the running server. No source, no restart, no agent.</span>
      </div>
    </div>
  );
}
