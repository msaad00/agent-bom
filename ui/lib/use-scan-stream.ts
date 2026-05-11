"use client";

import { useEffect, useState } from "react";
import { api, type SSEEvent, type StepEvent } from "@/lib/api";

export interface UseScanStreamOptions {
  enabled?: boolean;
  onEvent?: (event: SSEEvent) => void;
  onDone?: () => void;
}

export interface UseScanStreamState {
  streaming: boolean;
  messages: string[];
  pipelineSteps: Map<string, StepEvent>;
  lastEvent: SSEEvent | null;
}

export function useScanStream(jobId: string, options: UseScanStreamOptions = {}): UseScanStreamState {
  const { enabled = true, onDone, onEvent } = options;
  const [streaming, setStreaming] = useState(false);
  const [messages, setMessages] = useState<string[]>([]);
  const [pipelineSteps, setPipelineSteps] = useState<Map<string, StepEvent>>(new Map());
  const [lastEvent, setLastEvent] = useState<SSEEvent | null>(null);

  useEffect(() => {
    setMessages([]);
    setPipelineSteps(new Map());
    setLastEvent(null);

    if (!jobId || !enabled) {
      setStreaming(false);
      return undefined;
    }

    let closed = false;
    setStreaming(true);

    const cleanup = api.streamScan(
      jobId,
      (event) => {
        if (closed) return;
        setLastEvent(event);
        if (event.type === "step") {
          const step = event as StepEvent;
          setPipelineSteps((prev) => {
            const next = new Map(prev);
            next.set(step.step_id, step);
            return next;
          });
          setMessages((prev) => [...prev, step.message]);
        } else if (event.type === "progress" && event.message) {
          setMessages((prev) => [...prev, event.message]);
        }
        onEvent?.(event);
      },
      () => {
        if (closed) return;
        setStreaming(false);
        onDone?.();
      }
    );

    return () => {
      closed = true;
      cleanup();
    };
  }, [enabled, jobId, onDone, onEvent]);

  return { streaming, messages, pipelineSteps, lastEvent };
}
