"use client";

import { useEffect, useState } from "react";
import { ArrowRight } from "@phosphor-icons/react";
import DecryptedText from "@/components/bits/DecryptedText";

// Replacements from the demo estate's real roadmap
const PAIRS = [
  ["RSA-2048", "X25519 + ML-KEM-768"],
  ["3DES-CBC", "AES-256-GCM"],
  ["TLS 1.0", "TLS 1.3, X25519MLKEM768"],
  ["ECDSA P-256", "ML-DSA-65"],
  ["MD5", "SHA-384"],
  ["AES-ECB", "AES-256-GCM"],
] as const;

const CHARS = "ABCDEF0123456789/+=#<>";

/** The fixes LATTICE proposes, one after another, each one decrypting into place. */
export default function CipherTicker() {
  const [i, setI] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setInterval(() => setI((k) => (k + 1) % PAIRS.length), 3200);
    return () => clearInterval(id);
  }, []);
  const [from, to] = PAIRS[i];

  return (
    <p className="ticker" aria-live="off">
      <span className="from"><DecryptedText key={`f${i}`} text={from} animateOn="view" sequential speed={28} characters={CHARS} encryptedClassName="enc" /></span>
      <ArrowRight size={15} weight="bold" aria-hidden="true" />
      <span className="to"><DecryptedText key={`t${i}`} text={to} animateOn="view" sequential speed={28} characters={CHARS} encryptedClassName="enc" /></span>
    </p>
  );
}
