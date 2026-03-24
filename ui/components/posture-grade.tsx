"use client";

interface PostureGradeProps {
  grade: string;  // A, B, C, D, F, or N/A
  score: number;  // 0-100
  dimensions?: Record<string, { score: number; label: string }>;
}

export function PostureGrade({ grade, score, dimensions }: PostureGradeProps) {
  // Color based on grade — matches architecture diagram semantics
  const gradeColor = {
    A: "#3fb950", // green  — output/governance layer
    B: "#58a6ff", // blue   — discover layer
    C: "#d29922", // amber  — analyze layer
    D: "#f97316", // orange — degraded
    F: "#f85149", // red    — scan/critical layer
  }[grade] ?? "#71717a";

  // SVG radial progress ring (120px)
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative w-[120px] h-[120px]">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#27272a" strokeWidth="8" />
          <circle cx="60" cy="60" r={radius} fill="none" stroke={gradeColor} strokeWidth="8"
            strokeDasharray={circumference} strokeDashoffset={dashOffset}
            strokeLinecap="round" className="transition-all duration-700" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold" style={{ color: gradeColor }}>{grade}</span>
          <span className="text-xs text-zinc-500">{score}/100</span>
        </div>
      </div>
      {dimensions && Object.keys(dimensions).length > 0 && (
        <div className="grid grid-cols-3 gap-2 w-full max-w-xs">
          {Object.entries(dimensions).map(([key, dim]) => (
            <div key={key} className="flex flex-col items-center gap-1">
              <div className="w-full h-1.5 rounded-full bg-zinc-800">
                <div className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${dim.score}%`, backgroundColor: dim.score >= 80 ? "#22c55e" : dim.score >= 60 ? "#eab308" : "#ef4444" }} />
              </div>
              <span className="text-[10px] text-zinc-500 truncate">{dim.label}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
