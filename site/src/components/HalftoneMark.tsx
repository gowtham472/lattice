"use client";

import { useEffect, useRef } from "react";

type Dot = { x: number; y: number; shape: boolean; core: boolean; line: boolean };

const TONES = { risk: "#FF5B1A", safe: "#2E6BFF" };
const INK = "#121212";
const PAPER = "#D9D7D0";

/**
 * The lattice mark drawn in dots. A lens follows the cursor and magnifies the dots under it;
 * without a cursor (touch, or at rest) the lens drifts on its own. Draws only while visible.
 * `tone` colours it: orange for cryptography at risk, blue once it is post-quantum.
 */
export default function HalftoneMark({ tone = "risk" }: { tone?: keyof typeof TONES }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const readout = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const ACCENT = TONES[tone];
    let tick = 0;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let W = 0, H = 0, spacing = 9;
    let dots: Dot[] = [];
    let center = { x: 0, y: 0 };
    const pointer = { x: 0, y: 0, active: false };
    const lens = { x: 0, y: 0 };

    function build() {
      const c = canvas!;
      W = c.clientWidth;
      H = c.clientHeight;
      if (!W || !H) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      c.width = Math.round(W * dpr);
      c.height = Math.round(H * dpr);
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      spacing = W < 420 ? 7.5 : 9;

      // the mark, drawn once off screen, then sampled at every grid point
      const off = document.createElement("canvas");
      off.width = Math.ceil(W);
      off.height = Math.ceil(H);
      const o = off.getContext("2d", { willReadFrequently: true })!;
      const s = Math.min(W * 0.66, H * 0.64);
      center = { x: W / 2, y: H * 0.43 };
      const x0 = center.x - s / 2, y0 = center.y - s / 2, step = s / 2;
      o.lineCap = "round";
      o.strokeStyle = "#000";
      o.lineWidth = s * 0.07;
      for (let i = 0; i < 3; i++) {
        o.beginPath(); o.moveTo(x0, y0 + i * step); o.lineTo(x0 + s, y0 + i * step); o.stroke();
        o.beginPath(); o.moveTo(x0 + i * step, y0); o.lineTo(x0 + i * step, y0 + s); o.stroke();
      }
      o.beginPath(); o.moveTo(x0, y0); o.lineTo(x0 + s, y0 + s); o.stroke();
      const lines = o.getImageData(0, 0, off.width, off.height).data;
      const nodeR = s * 0.115;
      for (let i = 0; i < 3; i++) for (let j = 0; j < 3; j++) {
        o.beginPath(); o.arc(x0 + i * step, y0 + j * step, nodeR, 0, Math.PI * 2); o.fill();
      }
      const all = o.getImageData(0, 0, off.width, off.height).data;

      dots = [];
      for (let y = spacing / 2; y < H; y += spacing) {
        for (let x = spacing / 2; x < W; x += spacing) {
          const i = ((y | 0) * off.width + (x | 0)) * 4 + 3;
          const shape = all[i] > 128;
          const line = lines[i] > 128;
          const core = Math.hypot(x - center.x, y - center.y) < nodeR;
          dots.push({ x, y, shape, core, line });
        }
      }
      // start on a corner node, so the first frame shows the centre node clearly
      lens.x = x0;
      lens.y = y0;
    }

    function draw(t: number) {
      const c = ctx!;
      c.clearRect(0, 0, W, H);
      if (pointer.active) {
        lens.x += (pointer.x - lens.x) * 0.18;
        lens.y += (pointer.y - lens.y) * 0.18;
      } else if (!reduce) {
        const tx = center.x + Math.cos(t * 0.00035) * W * 0.26;
        const ty = center.y + Math.sin(t * 0.00047) * H * 0.2;
        lens.x += (tx - lens.x) * 0.04;
        lens.y += (ty - lens.y) * 0.04;
      }
      const R = Math.min(W, H) * (reduce ? 0 : 0.21);
      const batches: Record<string, Path2D> = { [ACCENT]: new Path2D(), [INK]: new Path2D(), [PAPER]: new Path2D() };
      for (const d of dots) {
        const dx = d.x - lens.x, dy = d.y - lens.y;
        const dist = Math.hypot(dx, dy) || 1;
        const k = R > 0 && dist < R ? 1 - dist / R : 0;
        const e = k * k * (3 - 2 * k);
        let r: number;
        let colour: string;
        if (d.shape) {
          r = (d.line && !d.core ? 2.15 : 2.75) * (1 + 1.25 * e);
          colour = d.core ? INK : ACCENT;
        } else {
          if (e <= 0.02) continue;          // paper dots appear only under the lens
          r = 0.9 + 1.1 * e;
          colour = PAPER;
        }
        const push = e * spacing * 0.7;
        const px = d.x + (dx / dist) * push;
        const py = d.y + (dy / dist) * push;
        const p = batches[colour];
        p.moveTo(px + r, py);
        p.arc(px, py, r, 0, Math.PI * 2);
      }
      c.fillStyle = PAPER; c.fill(batches[PAPER]);
      c.fillStyle = ACCENT; c.fill(batches[ACCENT]);
      c.fillStyle = INK; c.fill(batches[INK]);
      if (readout.current && (tick++ % 4 === 0) && W && H) {
        readout.current.textContent = `x ${(lens.x / W).toFixed(2)}  y ${(lens.y / H).toFixed(2)}`;
      }
    }

    let raf = 0;
    let visible = true;
    const loop = (t: number) => {
      raf = requestAnimationFrame(loop);
      if (visible) draw(t);
    };

    const onMove = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      pointer.x = e.clientX - r.left;
      pointer.y = e.clientY - r.top;
      pointer.active = e.pointerType !== "touch";
      if (reduce) draw(0);
    };
    const onLeave = () => { pointer.active = false; };
    canvas.addEventListener("pointermove", onMove, { passive: true });
    canvas.addEventListener("pointerleave", onLeave, { passive: true });

    const ro = new ResizeObserver(() => { build(); draw(performance.now()); });
    ro.observe(canvas);
    const io = new IntersectionObserver((entries) => { visible = entries[0]?.isIntersecting ?? true; });
    io.observe(canvas);
    build();
    draw(0);
    if (!reduce) raf = requestAnimationFrame(loop);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      canvas.removeEventListener("pointermove", onMove);
      canvas.removeEventListener("pointerleave", onLeave);
    };
  }, [tone]);

  return (
    <>
      <canvas ref={ref} aria-label="The LATTICE mark in dots. Move the cursor over it to look closer." role="img" />
      <span className="lens-readout" ref={readout} aria-hidden="true" />
    </>
  );
}
