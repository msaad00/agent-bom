"use client";

import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { api, type TraceIngestResponse } from "@/lib/api";
import { MAX_TRACE_PREVIEW_BYTES, parseTraceInput } from "@/lib/trace-intake";

export function useTraceIntake(sample: string) {
  const [payload, setPayload] = useState(sample);
  const [source, setSource] = useState("Bundled sample");
  const [result, setResult] = useState<TraceIngestResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const reader = useRef<FileReader | null>(null);
  useEffect(() => () => { generation.current += 1; reader.current?.abort(); }, []);

  function replacePayload(next: string, origin = "Edited payload") {
    generation.current += 1;
    reader.current?.abort();
    reader.current = null;
    setPayload(next);
    setSource(origin);
    setResult(null);
    setError(null);
    setLoading(false);
    setReading(false);
  }

  function handleFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    replacePayload("", "Local file");
    if (file.size > MAX_TRACE_PREVIEW_BYTES) {
      setError("Trace input exceeds the 10 MB browser limit.");
      return;
    }
    const epoch = generation.current;
    const next = new FileReader();
    reader.current = next;
    setReading(true);
    next.onerror = () => {
      if (epoch !== generation.current) return;
      setReading(false);
      setError("Failed to read trace export. Choose the file again.");
    };
    next.onload = () => {
      if (epoch !== generation.current) return;
      setReading(false);
      if (typeof next.result !== "string") { setError("Could not read trace export."); return; }
      setPayload(next.result);
    };
    next.readAsText(file);
  }

  async function submit() {
    if (loading || reading) return;
    const epoch = generation.current;
    setError(null);
    setResult(null);
    let body: Record<string, unknown>;
    try { body = parseTraceInput(payload); }
    catch (validationError) {
      setError(validationError instanceof Error ? validationError.message : "Invalid trace input.");
      return;
    }
    setLoading(true);
    try {
      const next = await api.ingestTraces(body);
      if (epoch === generation.current) setResult(next);
    } catch {
      if (epoch === generation.current) setError("Trace correlation failed. Check access and control-plane availability, then retry.");
    } finally {
      if (epoch === generation.current) setLoading(false);
    }
  }
  return { payload, source, result, loading, reading, error, replacePayload, handleFile, submit };
}
