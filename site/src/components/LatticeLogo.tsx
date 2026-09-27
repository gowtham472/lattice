/** The LATTICE mark: a lattice of nodes, the one that matters in orange. */
export default function LatticeLogo({ size = 24 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true">
      <g fill="none" stroke="#C9C7C0" strokeWidth="1.5" strokeLinecap="round">
        <path d="M4 4h16M4 12h16M4 20h16M4 4v16M12 4v16M20 4v16M4 4l16 16" />
      </g>
      <g fill="#121212">
        <circle cx="4" cy="4" r="2.2" />
        <circle cx="12" cy="4" r="2.2" />
        <circle cx="20" cy="4" r="2.2" />
        <circle cx="4" cy="12" r="2.2" />
        <circle cx="20" cy="12" r="2.2" />
        <circle cx="4" cy="20" r="2.2" />
        <circle cx="12" cy="20" r="2.2" />
        <circle cx="20" cy="20" r="2.2" />
      </g>
      <circle cx="12" cy="12" r="3" fill="#FF5B1A" />
    </svg>
  );
}
