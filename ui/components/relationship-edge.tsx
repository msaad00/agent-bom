"use client";

import { BaseEdge, EdgeLabelRenderer, SmoothStepEdge, getSmoothStepPath, type EdgeProps } from "@xyflow/react";
import {
  ArrowRightLeft, Box, Bug, CirclePlay, Database, Eye, Fingerprint,
  GitBranch, KeyRound, Link2, LogIn, Plug, ShieldCheck, UserRoundCheck, Wrench,
  type LucideIcon,
} from "lucide-react";

// Icons supplement the recorded verb; they never replace its meaning or imply
// that a recorded permission has actually been exercised.
const RELATIONSHIP_ICONS: Record<string, LucideIcon> = {
  owns: UserRoundCheck,
  belongs_to: UserRoundCheck,
  uses: Plug,
  uses_framework: Plug,
  contains: Box,
  part_of: Box,
  hosts: Box,
  has_permission: KeyRound,
  can_access: KeyRound,
  used_credential: KeyRound,
  exposes_cred: KeyRound,
  shares_cred: KeyRound,
  authenticates_as: Fingerprint,
  acted_as: Fingerprint,
  assumes: LogIn,
  vulnerable_to: Bug,
  exploitable_via: Bug,
  depends_on: GitBranch,
  inherits: GitBranch,
  delegated_to: GitBranch,
  called: CirclePlay,
  invoked: CirclePlay,
  runs: CirclePlay,
  triggers: CirclePlay,
  stores: Database,
  accessed: Database,
  protects: ShieldCheck,
  governs: ShieldCheck,
  trusts: ShieldCheck,
  observes: Eye,
  remediates: Wrench,
  configures: Wrench,
  manages: Wrench,
  lateral_path: ArrowRightLeft,
  cross_account_trust: ArrowRightLeft,
};

export function RelationshipBadge({ relationship, children }: {
  relationship: string;
  children: React.ReactNode;
}) {
  const Icon = RELATIONSHIP_ICONS[relationship] ?? Link2;
  return <span className="relationship-badge">
    <Icon aria-hidden="true" width="1em" height="1em" strokeWidth={1.8} />
    <span>{children}</span>
  </span>;
}

export function RelationshipEdge(props: EdgeProps) {
  if (props.data?.isClusterEdge) return <SmoothStepEdge {...props} />;
  const [path, x, y] = getSmoothStepPath(props);
  const relationship = typeof props.data?.relationship === "string" ? props.data.relationship : "";
  return <>
    <BaseEdge id={props.id} path={path} style={props.style}
      {...(props.markerStart ? { markerStart: props.markerStart } : {})}
      {...(props.markerEnd ? { markerEnd: props.markerEnd } : {})}
      {...(props.interactionWidth !== undefined ? { interactionWidth: props.interactionWidth } : {})} />
    {props.label != null && <EdgeLabelRenderer>
      <div className="nodrag nopan" style={{
        position: "absolute",
        transform: `translate(-50%, -50%) translate(${x}px, ${y}px)`,
        fontSize: props.labelStyle?.fontSize ?? 12,
        pointerEvents: "none",
      }}>
        <RelationshipBadge relationship={relationship}>{props.label}</RelationshipBadge>
      </div>
    </EdgeLabelRenderer>}
  </>;
}

export const relationshipEdgeTypes = { smoothstep: RelationshipEdge };
