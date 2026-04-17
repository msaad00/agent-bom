"use client";

export function BrandMark({ className = "h-8 w-8" }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      role="img"
      aria-label="agent-bom logo"
      className={className}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <rect x="2" y="2" width="60" height="60" rx="16" fill="url(#agent-bom-bg)" stroke="#124C3A" strokeWidth="2" />
      <path
        d="M32 14L44 19V28C44 38.5 38.4 46.4 32 50C25.6 46.4 20 38.5 20 28V19L32 14Z"
        fill="#0C1713"
        stroke="#19C37D"
        strokeWidth="2.5"
      />
      <path d="M32 23V36" stroke="#19C37D" strokeWidth="2.5" strokeLinecap="round" />
      <circle cx="32" cy="41" r="2.5" fill="#19C37D" />
      <path d="M26.5 28H37.5" stroke="#19C37D" strokeWidth="2.5" strokeLinecap="round" />
      <defs>
        <linearGradient id="agent-bom-bg" x1="8" y1="6" x2="58" y2="58" gradientUnits="userSpaceOnUse">
          <stop stopColor="#0D2A21" />
          <stop offset="1" stopColor="#07110D" />
        </linearGradient>
      </defs>
    </svg>
  );
}
