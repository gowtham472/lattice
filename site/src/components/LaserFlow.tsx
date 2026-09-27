"use client";

import { useEffect, useRef } from "react";
import { LASER_FRAG, LASER_VERT } from "./laserShader";

// LaserFlow's defaults from React Bits, tuned for a beam that lands on a card.
const PARAMS: Record<string, number> = {
  uWispDensity: 1.0, uTiltScale: 0.02, uFlowSpeed: 0.35, uWSpeed: 15.0, uWIntensity: 5.5,
  uFogIntensity: 0.55, uFogScale: 0.3, uFlowStrength: 0.25, uDecay: 1.1, uFalloffStart: 1.2, uFogFallSpeed: 0.6, uCore: 0.85,
};
const UNITS = 204.8;        // shader units across the canvas height (512 × 0.4)
const DROP = 0.8;           // seconds for the beam to fall
const R = 150;              // the shader's beam radius in units

type Spark = { x: number; y: number; vx: number; vy: number; age: number; life: number };

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.replace("#", ""), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/**
 * React Bits' LaserFlow, ported to plain WebGL (no three.js) and staged: when the card with id
 * `targetId` comes into view, the beam falls from the top of the section, lands on the card's top
 * edge with a flash and a burst of sparks, and keeps burning there. The card gets data-lit="1" at
 * the moment of impact, so its styles can react. Pauses off screen; a still frame for reduced motion.
 */
export default function LaserFlow({ targetId, color = "#FF5B1A" }: { targetId: string; color?: string }) {
  const mountRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const mount = mountRef.current;
    const target = document.getElementById(targetId);
    if (!mount || !target) return;
    const host = mount.parentElement ?? mount;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl", {
      antialias: false, alpha: false, depth: false, stencil: false, premultipliedAlpha: false, powerPreference: "high-performance",
    });
    if (!gl) { target.dataset.lit = "1"; return; }
    gl.getExtension("OES_standard_derivatives");
    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
    };
    const vs = compile(gl.VERTEX_SHADER, LASER_VERT);
    const fs = compile(gl.FRAGMENT_SHADER, LASER_FRAG);
    const prog = gl.createProgram()!;
    if (vs && fs) { gl.attachShader(prog, vs); gl.attachShader(prog, fs); gl.linkProgram(prog); }
    if (!vs || !fs || !gl.getProgramParameter(prog, gl.LINK_STATUS)) { target.dataset.lit = "1"; return; }
    gl.useProgram(prog);

    const sparkCanvas = document.createElement("canvas");
    sparkCanvas.className = "sparks";
    const sx = sparkCanvas.getContext("2d")!;
    mount.append(canvas, sparkCanvas);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "position");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 3, gl.FLOAT, false, 0, 0);

    const U = (name: string) => gl.getUniformLocation(prog, name);
    for (const [k, v] of Object.entries(PARAMS)) gl.uniform1f(U(k), v);
    gl.uniform3f(U("uColor"), ...hexToRgb(color));

    const baseDpr = Math.min(window.devicePixelRatio || 1, 2);
    let dpr = baseDpr;
    let flow = 0, mx = 0, my = 0, tx = 0, ty = 0;
    let W = 1, H = 1, ix = 0, iy = 0;          // css size, and the impact point in css pixels

    // the staging: idle, then falling, then burning
    let phase: "idle" | "fall" | "burn" = "idle";
    let phaseT = 0, drop = 0, head = 0, impact = 0;
    const sparks: Spark[] = [];
    let trickle = 0;

    const aim = () => {
      const m = mount.getBoundingClientRect(), t = target.getBoundingClientRect();
      W = Math.max(1, m.width); H = Math.max(1, m.height);
      ix = t.left + t.width / 2 - m.left;
      iy = t.top - m.top;
      const upp = UNITS / H;                    // shader units per css pixel
      const above = Math.max(80, iy) * upp / R; // from the impact to the top edge, in beam radii
      gl.uniform1f(U("uBeamXFrac"), ix / W - 0.5);
      gl.uniform1f(U("uBeamYFrac"), 0.5 - iy / H);
      gl.uniform1f(U("uHLenFactor"), Math.min(0.9, Math.max(0.22, (t.width / 2) * upp * 1.08 / R)));
      gl.uniform1f(U("uVLenFactor"), Math.max(1.0, above * 1.05));
      gl.uniform1f(U("uReach"), Math.max(0.6, above * 1.15));
    };
    const draw = () => {
      gl.uniform1f(U("iTime"), flow);
      gl.uniform1f(U("uFlowTime"), flow);
      gl.uniform1f(U("uFogTime"), flow);
      gl.uniform1f(U("uFade"), 1);
      gl.uniform1f(U("uDrop"), drop);
      gl.uniform1f(U("uHead"), head);
      gl.uniform1f(U("uImpact"), impact);
      gl.uniform4f(U("iMouse"), mx, my, 0, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };
    const resize = () => {
      const w = mount.clientWidth || 1, h = mount.clientHeight || 1;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      sparkCanvas.width = Math.round(w * baseDpr);
      sparkCanvas.height = Math.round(h * baseDpr);
      sx.setTransform(baseDpr, 0, 0, baseDpr, 0, 0);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform3f(U("iResolution"), canvas.width, canvas.height, dpr);
      aim();
      draw();
    };

    const burst = (n: number, fast: boolean) => {
      for (let i = 0; i < n; i++) {
        const a = -Math.PI / 2 + (Math.random() - 0.5) * Math.PI * (fast ? 1.05 : 0.8);
        const v = fast ? 160 + Math.random() * 360 : 70 + Math.random() * 170;
        sparks.push({
          x: ix + (Math.random() - 0.5) * 6, y: iy - 1,
          vx: Math.cos(a) * v * 1.35, vy: Math.sin(a) * v,
          age: 0, life: (fast ? 0.45 : 0.3) + Math.random() * (fast ? 0.7 : 0.45),
        });
      }
    };
    const land = () => {
      phase = "burn"; phaseT = 0; drop = 1;
      target.dataset.lit = "1";
      if (!reduce) burst(90, true);
    };
    const reset = () => {
      phase = "idle"; phaseT = 0; drop = 0; head = 0; impact = 0; sparks.length = 0;
      delete target.dataset.lit;
    };

    const stepSparks = (dt: number) => {
      sx.clearRect(0, 0, W, H);
      if (!sparks.length) return;
      sx.globalCompositeOperation = "lighter";
      sx.lineCap = "round";
      for (let i = sparks.length - 1; i >= 0; i--) {
        const p = sparks[i];
        p.age += dt;
        if (p.age >= p.life || p.y > iy + 2) { sparks.splice(i, 1); continue; }
        p.vy += 1150 * dt;
        p.vx *= 1 - 1.4 * dt;
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        const k = 1 - p.age / p.life;
        const g = Math.round(150 + 105 * k), b = Math.round(60 + 170 * k * k);
        sx.strokeStyle = `rgba(255, ${g}, ${b}, ${Math.min(1, k * 1.4)})`;
        sx.lineWidth = 0.8 + 1.1 * k;
        sx.beginPath();
        sx.moveTo(p.x, p.y);
        sx.lineTo(p.x - p.vx * 0.018, p.y - p.vy * 0.018);
        sx.stroke();
      }
    };

    let raf = 0, last = performance.now(), visible = false, hidden = false;
    let frames: number[] = [], lastCheck = last;
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      const dt = Math.min(0.033, Math.max(0.001, (now - last) / 1000));
      last = now;
      if (!visible || hidden) return;
      flow += dt;
      phaseT += dt;
      if (phase === "fall") {
        const p = Math.min(1, phaseT / DROP);
        drop = p * p;                             // it accelerates as it falls
        head = 1;
        if (p >= 1) land();
      } else if (phase === "burn") {
        head = Math.max(0, 1 - phaseT / 0.6);   // the streak fades into the steady beam
        impact = 1 + 1.3 * Math.exp(-phaseT * 3.2) + 0.05 * Math.sin(flow * 9);
        trickle += dt * 26;
        const n = Math.floor(trickle);
        if (n) { burst(n, false); trickle -= n; }
      }
      mx += (tx - mx) * 0.08;
      my += (ty - my) * 0.08;
      draw();
      stepSparks(dt);
      // keep it smooth on slow machines: lower the resolution, raise it again when there is room
      frames.push(1 / dt);
      if (now - lastCheck > 900) {
        const fps = frames.reduce((a, v) => a + v, 0) / frames.length;
        let next = dpr;
        if (fps < 48) next = Math.max(0.6, dpr * 0.85);
        else if (fps > 58 && dpr < baseDpr) next = Math.min(baseDpr, dpr * 1.1);
        if (Math.abs(next - dpr) > 0.01) { dpr = next; resize(); }
        frames = [];
        lastCheck = now;
      }
    };

    const onMove = (e: PointerEvent) => {
      const m = mount.getBoundingClientRect();
      tx = (e.clientX - m.left) * dpr;
      ty = (m.height - (e.clientY - m.top)) * dpr;
    };
    const onLeave = () => { tx = 0; ty = 0; };
    const onVis = () => { hidden = document.hidden; };
    host.addEventListener("pointermove", onMove, { passive: true });
    host.addEventListener("pointerleave", onLeave, { passive: true });
    document.addEventListener("visibilitychange", onVis);

    // the section on screen at all: run the loop; gone completely: set the stage again
    const ioMount = new IntersectionObserver((e) => {
      visible = e[0]?.isIntersecting ?? true;
      if (!visible && !reduce) reset();
    });
    ioMount.observe(mount);
    // most of the card on screen: drop the beam
    const ioTarget = new IntersectionObserver((e) => {
      if (e[0]?.isIntersecting && phase === "idle" && !reduce) { phase = "fall"; phaseT = 0; }
    }, { threshold: 0.55 });
    ioTarget.observe(target);

    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    ro.observe(target);
    document.fonts?.ready.then(resize);
    resize();
    if (reduce) { flow = 3.2; drop = 1; impact = 1; target.dataset.lit = "1"; draw(); }
    else raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ioMount.disconnect();
      ioTarget.disconnect();
      ro.disconnect();
      host.removeEventListener("pointermove", onMove);
      host.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVis);
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      canvas.remove();
      sparkCanvas.remove();
    };
  }, [targetId, color]);

  return <div ref={mountRef} className="laser" aria-hidden="true" />;
}
