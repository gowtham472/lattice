"use client";

import { useEffect, useState } from "react";
import { CheckCircle, Pulse } from "@phosphor-icons/react";
import { trace } from "@/data/site";

/** What `lattice trace` recorded inside LATTICE's own server while curl connected (a real test run). */
export default function TraceCard() {
  const [lit, setLit] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setInterval(() => setLit((i) => (i + 1) % trace.length), 1400);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="trace" id="trace-card">
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
                <td className="fn">{row.fn}</td>
                <td><span className="alg"><i className={row.kind} />{row.alg}</span></td>
                <td>{row.calls}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="trace-foot">
        <CheckCircle size={18} weight="fill" />
        <span>X25519 with ML-KEM-768 is the hybrid X25519MLKEM768 key exchange, seen inside the running server with no source code, restart or agent.</span>
      </div>
    </div>
  );
}
