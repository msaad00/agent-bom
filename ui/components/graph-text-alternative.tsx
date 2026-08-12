"use client";

import { useMemo } from "react";

import {
  buildGraphTextAlternative,
  type GraphTextAlternativeOptions,
} from "@/lib/graph-text-alternative";
import type {
  LargeGraphOverviewModel,
  LargeGraphOverviewSummary,
} from "@/lib/large-graph-overview";

interface GraphTextAlternativeProps extends GraphTextAlternativeOptions {
  /** Referenced by the canvas's `aria-describedby`. */
  id: string;
  /** Which renderer this describes, so the reading names the surface. */
  renderer: string;
  model: LargeGraphOverviewModel;
  summary: LargeGraphOverviewSummary;
}

/**
 * The screen-reader equivalent of a canvas graph: a named region carrying the
 * same census, nodes, and relationships the canvas paints. Visually hidden —
 * sighted users have the canvas itself, and the design language keeps the
 * content the hero rather than stacking a second representation beside it.
 */
export function GraphTextAlternative({
  id,
  renderer,
  model,
  summary,
  maxRows,
  maxConnections,
}: GraphTextAlternativeProps) {
  const text = useMemo(
    () => buildGraphTextAlternative(model, summary, { maxRows, maxConnections }),
    [maxConnections, maxRows, model, summary],
  );

  return (
    <section id={id} className="sr-only" aria-label="Graph contents, text equivalent">
      <p>
        {renderer}. {text.headline}
      </p>

      <h3>Nodes by type</h3>
      <ul>
        {text.nodeTypes.map((item) => (
          <li key={item.nodeType}>
            {item.nodeType}: {item.count.toLocaleString()}
          </li>
        ))}
      </ul>

      <h3>Relationships by kind</h3>
      <ul>
        {text.relationships.map((item) => (
          <li key={item.relationship}>
            {item.relationship.replace(/[_-]+/g, " ")}: {item.count.toLocaleString()}
          </li>
        ))}
      </ul>

      <table>
        <caption>Nodes drawn on the graph. {text.rowsNote}</caption>
        <thead>
          <tr>
            <th scope="col">Node</th>
            <th scope="col">Type</th>
            <th scope="col">Severity</th>
            <th scope="col">Connections</th>
          </tr>
        </thead>
        <tbody>
          {text.rows.map((row) => (
            <tr key={row.id}>
              <th scope="row">{row.label}</th>
              <td>{row.nodeType}</td>
              <td>{row.severity}</td>
              <td>{row.connections.toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Connections</h3>
      <p>{text.connectionsNote}</p>
      <ul>
        {text.connections.map((sentence) => (
          <li key={sentence}>{sentence}</li>
        ))}
      </ul>
    </section>
  );
}
