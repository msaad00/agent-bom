"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { type Edge, type Node } from "@xyflow/react";
import { chooseContextDirection, contextFitScore, contextLayoutCandidates, type CanvasSize, type ContextDirection, type ContextLayoutMode } from "@/lib/context-layout";

export function useContextLayout(nodes: Node[], edges: Edge[], focused: boolean, scope: string, settled: boolean) {
  const canvasRef = useRef<HTMLDivElement>(null);
  const [canvas, setCanvas] = useState<CanvasSize>({ width: 0, height: 0 });
  const [mode, setMode] = useState<ContextLayoutMode>("auto");
  const [automatic, setAutomatic] = useState<{ scope: string; direction: ContextDirection } | null>(null);
  useEffect(() => {
    const element = canvasRef.current;
    if (!element) return;
    const update = () => {
      const { width, height } = element.getBoundingClientRect();
      setCanvas(current => current.width === width && current.height === height ? current : { width, height });
    };
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const candidates = useMemo(() => contextLayoutCandidates(nodes, edges, focused), [nodes, edges, focused]);
  const proposed = chooseContextDirection(contextFitScore(candidates.LR.nodes, canvas, focused), contextFitScore(candidates.TB.nodes, canvas, focused));
  const chosen = automatic?.scope === scope ? automatic.direction : proposed;
  useEffect(() => {
    // Wait for the initial page and real canvas size. Preserve the decision as
    // pages expand, the inspector changes, and the canvas resizes. Choosing
    // Auto again or a different investigation scope re-evaluates the fit.
    if (mode === "auto" && automatic?.scope !== scope && settled && nodes.length > 0 && canvas.width > 0 && canvas.height > 0) {
      setAutomatic({ scope, direction: proposed });
    }
  }, [mode, automatic, scope, settled, nodes.length, canvas.width, canvas.height, proposed]);
  const direction = mode === "horizontal" ? "LR" : mode === "vertical" ? "TB" : chosen;
  function selectMode(next: ContextLayoutMode) {
    setMode(next);
    if (next === "auto") setAutomatic(null);
  }
  return { ...candidates[direction], direction, mode, selectMode, canvasRef };
}
