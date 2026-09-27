"use client";

// Magnet from React Bits (https://reactbits.dev), by David Haz. MIT + Commons Clause License
// Condition v1.0: used as part of this website; not redistributed on its own.
// Adapted: the offset is written straight to the element instead of through React state, so a
// mouse move does not re-render anything.

import { useEffect, useRef, type ReactNode } from "react";

type Props = { children: ReactNode; padding?: number; magnetStrength?: number; className?: string };

export default function Magnet({ children, padding = 30, magnetStrength = 14, className = "" }: Props) {
  const outer = useRef<HTMLDivElement>(null);
  const inner = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const o = outer.current, i = inner.current;
    if (!o || !i) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce), (pointer: coarse)").matches) return;
    let active = false;
    const onMove = (e: MouseEvent) => {
      const { left, top, width, height } = o.getBoundingClientRect();
      const cx = left + width / 2, cy = top + height / 2;
      const near = Math.abs(cx - e.clientX) < width / 2 + padding && Math.abs(cy - e.clientY) < height / 2 + padding;
      if (near) {
        active = true;
        i.style.transition = "transform 0.3s ease-out";
        i.style.transform = `translate3d(${(e.clientX - cx) / magnetStrength}px, ${(e.clientY - cy) / magnetStrength}px, 0)`;
      } else if (active) {
        active = false;
        i.style.transition = "transform 0.5s ease-in-out";
        i.style.transform = "translate3d(0, 0, 0)";
      }
    };
    window.addEventListener("mousemove", onMove, { passive: true });
    return () => window.removeEventListener("mousemove", onMove);
  }, [padding, magnetStrength]);

  return (
    <div ref={outer} className={`magnet ${className}`}>
      <div ref={inner} style={{ willChange: "transform" }}>{children}</div>
    </div>
  );
}
