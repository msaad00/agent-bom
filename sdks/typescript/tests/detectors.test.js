import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(
  readFileSync(resolve(__dirname, "../../shared/test-fixtures.json"), "utf-8"),
);

import {
  ToolDriftDetector,
  ArgumentAnalyzer,
  CredentialLeakDetector,
  RateLimitTracker,
  SequenceAnalyzer,
  ResponseInspector,
  VectorDBInjectionDetector,
  scoreSemanticInjection,
} from "../dist/index.js";

// ── Tool Drift ──────────────────────────────────────────────────────────────

describe("ToolDriftDetector", () => {
  for (const tc of fixtures.tool_drift) {
    it(tc.name, () => {
      const d = new ToolDriftDetector();
      if (tc.baseline) d.setBaseline(tc.baseline);
      const alerts = d.check(tc.current_tools);
      if (tc.expected_alert_count !== undefined) {
        assert.equal(alerts.length, tc.expected_alert_count, `expected ${tc.expected_alert_count} alerts`);
      }
      if (tc.expected_severity) {
        assert.ok(alerts.some((a) => a.severity === tc.expected_severity));
      }
      if (tc.expected_message_contains) {
        assert.ok(alerts.some((a) => a.message.includes(tc.expected_message_contains)));
      }
      if (tc.expected_severities) {
        const sevs = alerts.map((a) => a.severity).sort();
        assert.deepEqual(sevs, [...tc.expected_severities].sort());
      }
    });
  }
});

// ── Argument Analyzer ───────────────────────────────────────────────────────

describe("ArgumentAnalyzer", () => {
  const analyzer = new ArgumentAnalyzer();
  for (const tc of fixtures.argument_analyzer) {
    it(tc.name, () => {
      const alerts = analyzer.check(tc.tool, tc.arguments);
      if (tc.expected_alert_count !== undefined) {
        assert.equal(alerts.length, tc.expected_alert_count);
      }
      if (tc.min_alert_count !== undefined) {
        assert.ok(alerts.length >= tc.min_alert_count, `expected >= ${tc.min_alert_count}, got ${alerts.length}`);
      }
      if (tc.expected_pattern_contains) {
        assert.ok(
          alerts.some((a) => a.details.pattern?.toString().includes(tc.expected_pattern_contains)),
          `no alert with pattern containing "${tc.expected_pattern_contains}"`,
        );
      }
    });
  }
});

// ── Credential Leak ─────────────────────────────────────────────────────────

describe("CredentialLeakDetector", () => {
  const detector = new CredentialLeakDetector();
  for (const tc of fixtures.credential_leak) {
    it(tc.name, () => {
      const alerts = detector.check(tc.tool, tc.text);
      if (tc.expected_alert_count !== undefined) {
        assert.equal(alerts.length, tc.expected_alert_count);
      }
      if (tc.min_alert_count !== undefined) {
        assert.ok(alerts.length >= tc.min_alert_count, `expected >= ${tc.min_alert_count}, got ${alerts.length}`);
      }
      if (tc.expected_severity) {
        assert.ok(alerts.some((a) => a.severity === tc.expected_severity));
      }
      if (tc.expected_message_contains) {
        assert.ok(alerts.some((a) => a.message.includes(tc.expected_message_contains)));
      }
    });
  }
});

// ── Rate Limit ──────────────────────────────────────────────────────────────

describe("RateLimitTracker", () => {
  for (const tc of fixtures.rate_limit) {
    it(tc.name, () => {
      const tracker = new RateLimitTracker(tc.threshold, tc.window_seconds);
      let lastAlerts = [];
      for (let i = 0; i < tc.call_count; i++) {
        lastAlerts = tracker.record(tc.tool);
      }
      if (tc.expected_alert_on_last) {
        assert.ok(lastAlerts.length > 0, "expected alert on last call");
        if (tc.expected_severity) {
          assert.equal(lastAlerts[0].severity, tc.expected_severity);
        }
      } else {
        assert.equal(lastAlerts.length, 0, "expected no alert on last call");
      }
    });
  }
});

// ── Sequence Analyzer ───────────────────────────────────────────────────────

describe("SequenceAnalyzer", () => {
  for (const tc of fixtures.sequence_analyzer) {
    it(tc.name, () => {
      const analyzer = new SequenceAnalyzer();
      let lastAlerts = [];
      for (const call of tc.calls) {
        lastAlerts = analyzer.record(call);
      }
      if (tc.expected_alert_on_last) {
        assert.ok(lastAlerts.length > 0, "expected alert on last call");
        if (tc.expected_message_contains) {
          assert.ok(
            lastAlerts.some((a) => a.message.toLowerCase().includes(tc.expected_message_contains.toLowerCase())),
            `no alert containing "${tc.expected_message_contains}"`,
          );
        }
      } else {
        assert.equal(lastAlerts.length, 0);
      }
    });
  }
});

// ── Response Inspector ──────────────────────────────────────────────────────

describe("ResponseInspector", () => {
  const inspector = new ResponseInspector();
  for (const tc of fixtures.response_inspector) {
    it(tc.name, () => {
      const alerts = inspector.check(tc.tool, tc.text);
      const injectionAlerts = alerts.filter(
        (a) => a.details.category === "prompt_injection" || a.details.category === "semantic_injection",
      );
      if (tc.expected_injection_alerts !== undefined) {
        assert.equal(injectionAlerts.length, tc.expected_injection_alerts);
      }
      if (tc.min_injection_alerts !== undefined) {
        assert.ok(
          injectionAlerts.length >= tc.min_injection_alerts,
          `expected >= ${tc.min_injection_alerts} injection alerts, got ${injectionAlerts.length}`,
        );
      }
      if (tc.expected_severity) {
        assert.ok(alerts.some((a) => a.severity === tc.expected_severity));
      }
    });
  }
});

// ── Vector DB Injection ─────────────────────────────────────────────────────

describe("VectorDBInjectionDetector", () => {
  const detector = new VectorDBInjectionDetector();

  for (const tc of fixtures.vector_db_injection) {
    if (tc.tools) {
      it(tc.name, () => {
        for (const tool of tc.tools) {
          assert.equal(detector.isVectorTool(tool), tc.expected_is_vector, `isVectorTool("${tool}")`);
        }
      });
    } else {
      it(tc.name, () => {
        const alerts = detector.check(tc.tool, tc.text);
        if (tc.expected_alert_count !== undefined) {
          assert.equal(alerts.length, tc.expected_alert_count);
        }
        if (tc.min_alert_count !== undefined) {
          assert.ok(alerts.length >= tc.min_alert_count, `expected >= ${tc.min_alert_count}, got ${alerts.length}`);
        }
        if (tc.expected_severity) {
          assert.ok(alerts.some((a) => a.severity === tc.expected_severity));
        }
        if (tc.expected_category_contains) {
          assert.ok(
            alerts.some((a) => a.details.category?.toString().includes(tc.expected_category_contains)),
          );
        }
      });
    }
  }
});

// ── Semantic Injection Scoring ──────────────────────────────────────────────

describe("scoreSemanticInjection", () => {
  for (const tc of fixtures.semantic_injection) {
    it(tc.name, () => {
      const [score, signals] = scoreSemanticInjection(tc.text);
      if (tc.expected_score_below !== undefined) {
        assert.ok(score < tc.expected_score_below, `score ${score} should be < ${tc.expected_score_below}`);
      }
      if (tc.expected_min_score !== undefined) {
        assert.ok(score >= tc.expected_min_score, `score ${score} should be >= ${tc.expected_min_score}`);
      }
      if (tc.expected_score !== undefined) {
        assert.equal(score, tc.expected_score);
      }
      if (tc.expected_signals) {
        assert.deepEqual(signals, tc.expected_signals);
      }
      if (tc.expected_signals_contain) {
        for (const sig of tc.expected_signals_contain) {
          assert.ok(signals.includes(sig), `signals should contain "${sig}", got: ${signals}`);
        }
      }
    });
  }
});
