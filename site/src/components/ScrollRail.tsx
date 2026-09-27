"use client";

import { useEffect, useRef, useState } from "react";

type Item = { id: string; label: string };

/**
 * A scroll bar for the story: a thin track at the right edge that fills as the page is read, with a
 * mark where each chapter begins. The marks are links; the one being read is lit. The same
 * progress also fills a hairline under the navigation bar (.nav-progress).
 */
export default function ScrollRail({ items }: { items: Item[] }) {
  const fill = useRef<HTMLElement>(null);
  const [marks, setMarks] = useState<number[]>([]);
  const [active, setActive] = useState(-1);

  useEffect(() => {
    const bar = document.querySelector<HTMLElement>(".nav-progress i");
    let raf = 0;
    const measure = () => {
      const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      setMarks(items.map(({ id }) => {
        const el = document.getElementById(id);
        return el ? Math.min(1, (el.getBoundingClientRect().top + window.scrollY) / max) : 0;
      }));
    };
    const update = () => {
      raf = 0;
      const max = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
      const p = Math.min(1, Math.max(0, window.scrollY / max));
      if (fill.current) fill.current.style.transform = `scaleY(${p})`;
      if (bar) bar.style.transform = `scaleX(${p})`;
      let a = -1;
      items.forEach(({ id }, k) => {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top < window.innerHeight * 0.5) a = k;
      });
      setActive(a);
    };
    const onScroll = () => { if (!raf) raf = requestAnimationFrame(update); };
    const ro = new ResizeObserver(() => { measure(); update(); });
    ro.observe(document.body);
    window.addEventListener("scroll", onScroll, { passive: true });
    measure();
    update();
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener("scroll", onScroll);
    };
  }, [items]);

  return (
    <nav className="rail" aria-label="Chapters">
      <span className="rail-track" aria-hidden="true"><i ref={fill} /></span>
      {items.map((c, k) => (
        <a key={c.id} href={`#${c.id}`} className={k === active ? "on" : k < active ? "past" : undefined} style={{ top: `${(marks[k] ?? 0) * 100}%` }}>
          <span>{c.label}</span>
        </a>
      ))}
    </nav>
  );
}
