/** Require readiness from our spawned Next server, never an unrelated listener. */
export function waitForOwnedServer(url, child, { timeoutMs = 120_000 } = {}) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      reject(new Error("Capture server exited before readiness"));
      return;
    }
    let output = "";
    let probing = false;
    let settled = false;
    let retry;
    const controller = new AbortController();
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(retry);
      controller.abort();
      child.stdout.off("data", onData);
      child.off("exit", onExit);
      child.off("error", onError);
      if (error) reject(error);
      else resolve();
    };
    const onExit = () => finish(new Error("Capture server exited before readiness"));
    const onError = () => finish(new Error("Could not launch capture server"));
    const probe = async () => {
      try {
        const response = await fetch(url, { signal: controller.signal });
        await response.body?.cancel();
        if (child.exitCode !== null || child.signalCode !== null) return onExit();
        if (response.ok) return finish();
      } catch {
        // Readiness output alone does not prove the HTTP listener is healthy.
      }
      if (!settled) retry = setTimeout(probe, 500);
    };
    const onData = (chunk) => {
      output = (output + chunk.toString()).slice(-2048);
      if (!probing && /\bReady in\b/.test(output)) {
        probing = true;
        void probe();
      }
    };
    const timer = setTimeout(() => finish(new Error("Timed out waiting for capture server readiness")), timeoutMs);
    child.stdout.on("data", onData);
    child.once("exit", onExit);
    child.once("error", onError);
  });
}
