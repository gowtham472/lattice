"use client";

// A chapter opening: one short line that holds the screen while it is scrolled into focus.
// The word reveal is adapted from ScrollReveal in React Bits (https://reactbits.dev) by David Haz,
// MIT + Commons Clause License Condition v1.0, used as part of this website.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import DecryptedText from "@/components/bits/DecryptedText";

gsap.registerPlugin(ScrollTrigger);

type Props = {
  id: string;
  /** The line itself; wrap a word in asterisks to set it in the accent colour. */
  text?: string;
  /** A short technical line that decrypts once the words are in. */
  note?: string;
  tone?: "light" | "dark";
  children?: ReactNode;
};

export default function Chapter({ id, text, note, tone = "light", children }: Props) {
  const outer = useRef<HTMLDivElement>(null);
  const [noteOn, setNoteOn] = useState(false);

  useEffect(() => {
    const el = outer.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;   // the CSS shows everything at rest
    const words = el.querySelectorAll<HTMLElement>(".cw");
    const body = el.querySelector<HTMLElement>(".chapter-body");
    const grid = el.querySelector<HTMLElement>(".chapter-grid");
    const bar = el.querySelector<HTMLElement>(".chapter-progress i");
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({
        defaults: { ease: "none" },
        scrollTrigger: {
          trigger: el, start: "top top", end: "bottom bottom", scrub: 0.6,
          onUpdate: (st) => {
            if (st.progress > 0.42) setNoteOn(true);
            else if (st.progress < 0.08) setNoteOn(false);
          },
        },
      });
      if (words.length) {
        tl.fromTo(words, { opacity: 0.08, filter: "blur(10px)", yPercent: 35 }, { opacity: 1, filter: "blur(0px)", yPercent: 0, stagger: 0.05, duration: 0.3 }, 0);
      }
      if (grid) tl.fromTo(grid, { scale: 1.18, opacity: 0.2 }, { scale: 1, opacity: 1, duration: 0.7 }, 0);
      if (bar) tl.fromTo(bar, { scaleX: 0 }, { scaleX: 1, duration: 1 }, 0);
      if (body) tl.to(body, { yPercent: -5, scale: 0.97, opacity: 0.7, duration: 0.15 }, 0.85);
    }, el);
    return () => ctx.revert();
  }, []);

  const tokens = text ? text.split(" ") : [];

  return (
    <div className={`chapter ${tone}`} id={id} ref={outer}>
      <div className="chapter-stage">
        <div className="chapter-grid" aria-hidden="true" />
        <div className="wrap chapter-body">
          {children ?? (
            <h2 className="chapter-line">
              {tokens.map((t, i) => {
                const accent = t.startsWith("*");
                const word = t.replace(/\*/g, "");
                return (
                  <span key={i}>
                    <span className={`cw${accent ? " hot" : ""}`}>{word}</span>
                    {i < tokens.length - 1 ? " " : ""}
                  </span>
                );
              })}
            </h2>
          )}
          {note && (
            <p className="chapter-note">
              {noteOn
                ? <DecryptedText text={note} animateOn="view" sequential revealDirection="start" speed={22} characters="ABCDEF0123456789{}[]<>/\\#*+=" encryptedClassName="enc" />
                : <span className="ghost">{note}</span>}
            </p>
          )}
        </div>
        <div className="chapter-progress" aria-hidden="true"><i /></div>
      </div>
    </div>
  );
}
