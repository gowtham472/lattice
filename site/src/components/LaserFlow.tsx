"use client";

import { useEffect, useRef } from "react";
import { LASER_FRAG, LASER_VERT } from "./laserShader";

// LaserFlow's defaults from React Bits, tuned slightly for a beam that lands on a card.
const PARAMS: Record<string, number> = {
  uWispDensity: 1.0, uTiltScale: 0.01, uFlowSpeed: 0.35, uVLenFactor: 2.2, uHLenFactor: 0.55,
  uFogIntensity: 0.5, uFogScale: 0.3, uWSpeed: 15.0, uWIntensity: 5.5, uFlowStrength: 0.25,
  uDecay: 1.1, uFalloffStart: 1.2, uFogFallSpeed: 0.6,
};

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.replace("#", ""), 16);
  return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
}

/**
 * React Bits' LaserFlow, ported to plain WebGL (no three.js): the same shader, drawn on one
 * full-screen triangle. The beam is aimed at the top edge of the element with id `targetId`,
 * so the light lands on it. It pauses off screen and holds a still frame for reduced motion.
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
    if (!gl) return;
    gl.getExtension("OES_standard_derivatives");
    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return gl.getShaderParameter(s, gl.COMPILE_STATUS) ? s : null;
    };
    const vs = compile(gl.VERTEX_SHADER, LASER_VERT);
    const fs = compile(gl.FRAGMENT_SHADER, LASER_FRAG);
    if (!vs || !fs) return;
    const prog = gl.createProgram()!;
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
    gl.useProgram(prog);
    mount.appendChild(canvas);

    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 0, 3, -1, 0, -1, 3, 0]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "position");
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 3, gl.FLOAT, false, 0, 0);

    const U = (name: string) => gl.getUniformLocation(prog, name);
    for (const [k, v] of Object.entries(PARAMS)) gl.uniform1f(U(k), v);
    const [r, g, b] = hexToRgb(color);
    gl.uniform3f(U("uColor"), r, g, b);

    const baseDpr = Math.min(window.devicePixelRatio || 1, 2);
    let dpr = baseDpr;
    let flow = 0, fade = reduce ? 1 : 0;
    let mx = 0, my = 0, tx = 0, ty = 0;

    const aim = () => {
      const m = mount.getBoundingClientRect(), t = target.getBoundingClientRect();
      gl.uniform1f(U("uBeamXFrac"), (t.left + t.width / 2 - m.left) / Math.max(m.width, 1) - 0.5);
      gl.uniform1f(U("uBeamYFrac"), 0.5 - (t.top - m.top) / Math.max(m.height, 1));
      gl.uniform1f(U("uHLenFactor"), m.width < 700 ? 0.42 : PARAMS.uHLenFactor);
    };
    const draw = () => {
      gl.uniform1f(U("iTime"), flow);
      gl.uniform1f(U("uFlowTime"), flow);
      gl.uniform1f(U("uFogTime"), flow);
      gl.uniform1f(U("uFade"), fade);
      gl.uniform4f(U("iMouse"), mx, my, 0, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    };
    const resize = () => {
      const w = mount.clientWidth || 1, h = mount.clientHeight || 1;
      canvas.width = Math.max(1, Math.round(w * dpr));
      canvas.height = Math.max(1, Math.round(h * dpr));
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform3f(U("iResolution"), canvas.width, canvas.height, dpr);
      aim();
      draw();
    };

    let raf = 0, last = performance.now(), visible = true, hidden = false;
    let frames: number[] = [], lastCheck = last;
    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      const dt = Math.min(0.033, Math.max(0.001, (now - last) / 1000));
      last = now;
      if (!visible || hidden) return;
      flow += dt;
      fade = Math.min(1, fade + dt);
      mx += (tx - mx) * 0.08;
      my += (ty - my) * 0.08;
      draw();
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
    const io = new IntersectionObserver((e) => { visible = e[0]?.isIntersecting ?? true; });
    io.observe(mount);
    const ro = new ResizeObserver(resize);
    ro.observe(mount);
    ro.observe(target);
    document.fonts?.ready.then(resize);
    resize();
    if (reduce) { flow = 3.2; draw(); } else raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      ro.disconnect();
      host.removeEventListener("pointermove", onMove);
      host.removeEventListener("pointerleave", onLeave);
      document.removeEventListener("visibilitychange", onVis);
      gl.getExtension("WEBGL_lose_context")?.loseContext();
      canvas.remove();
    };
  }, [targetId, color]);

  return <div ref={mountRef} className="laser" aria-hidden="true" />;
}
