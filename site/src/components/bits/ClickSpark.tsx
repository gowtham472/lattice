"use client";

// ClickSpark from React Bits (https://reactbits.dev), by David Haz. MIT + Commons Clause License
// Condition v1.0: used as part of this website; not redistributed on its own.
// Adapted: one fixed canvas the size of the viewport listens to every click on the page, and it
// draws only while sparks are alive, instead of a canvas the height of the whole page.

import { useEffect, useRef } from "react";

type Spark = { x: number; y: number; angle: number; start: number };

export default function ClickSpark({
  sparkColor = "#FF5B1A", sparkSize = 11, sparkRadius = 22, sparkCount = 9, duration = 460,
}: { sparkColor?: string; sparkSize?: number; sparkRadius?: number; sparkCount?: number; duration?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let sparks: Spark[] = [];
    let raf = 0;
    const size = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(window.innerWidth * dpr);
      canvas.height = Math.round(window.innerHeight * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const draw = (now: number) => {
      ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
      sparks = sparks.filter((s) => {
        const t = (now - s.start) / duration;
        if (t >= 1) return false;
        const e = t * (2 - t);
        const d = e * sparkRadius, len = sparkSize * (1 - e);
        ctx.strokeStyle = sparkColor;
        ctx.lineWidth = 2;
        ctx.lineCap = "round";
        ctx.beginPath();
        ctx.moveTo(s.x + d * Math.cos(s.angle), s.y + d * Math.sin(s.angle));
        ctx.lineTo(s.x + (d + len) * Math.cos(s.angle), s.y + (d + len) * Math.sin(s.angle));
        ctx.stroke();
        return true;
      });
      raf = sparks.length ? requestAnimationFrame(draw) : 0;
    };
    const onClick = (e: MouseEvent) => {
      const now = performance.now();
      for (let i = 0; i < sparkCount; i++) sparks.push({ x: e.clientX, y: e.clientY, angle: (2 * Math.PI * i) / sparkCount, start: now });
      if (!raf) raf = requestAnimationFrame(draw);
    };
    size();
    window.addEventListener("resize", size);
    window.addEventListener("click", onClick);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", size);
      window.removeEventListener("click", onClick);
    };
  }, [sparkColor, sparkSize, sparkRadius, sparkCount, duration]);

  return <canvas ref={ref} className="click-spark" aria-hidden="true" />;
}
