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
  const orderedDimensions = Object.entries(dimensions ?? {})
    .sort((left, right) => right[1].score - left[1].score)
    .slice(0, 6);

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
      {orderedDimensions.length > 0 && (
        <div className="w-full min-w-[240px] max-w-sm rounded-2xl border border-zinc-800 bg-zinc-950/70 p-3">
          <div className="mb-2 text-[10px] uppercase tracking-[0.18em] text-zinc-500">
            Score breakdown
          </div>
          <div className="space-y-2">
            {orderedDimensions.map(([key, dim]) => (
              <div key={key} className="space-y-1">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-medium text-zinc-300">{dim.label}</span>
                  <span className="font-mono text-xs text-zinc-400">{dim.score}/100</span>
                </div>
                <div className="h-1.5 rounded-full bg-zinc-800">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${dim.score}%`,
                      backgroundColor: dim.score >= 80 ? "#22c55e" : dim.score >= 60 ? "#eab308" : "#ef4444",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
