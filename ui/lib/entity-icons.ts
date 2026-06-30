import type { ComponentType, CSSProperties } from "react";
import {
  Activity,
  BadgeCheck,
  Bot,
  Box,
  Boxes,
  BrainCircuit,
  Bug,
  Building2,
  Cloud,
  Container,
  Database,
  FileCode,
  FileCog,
  Fingerprint,
  Folder,
  IdCard,
  KeyRound,
  Landmark,
  Layers,
  Link2,
  Network,
  Package,
  ScrollText,
  Server,
  Share2,
  ShieldCheck,
  Ticket,
  TriangleAlert,
  User,
  UserCog,
  Users,
  Warehouse,
  Wrench,
} from "lucide-react";

export type LineageNodeType =
  | "provider"
  | "agent"
  | "server"
  | "package"
  | "vulnerability"
  | "misconfiguration"
  | "credential"
  | "tool"
  | "model"
  | "dataset"
  | "container"
  | "cloudResource"
  | "org"
  | "account"
  | "user"
  | "group"
  | "role"
  | "policy"
  | "serviceAccount"
  | "servicePrincipal"
  | "federatedIdentity"
  | "environment"
  | "fleet"
  | "cluster"
  | "sharedServer"
  | "managedIdentity"
  | "accessGrant"
  | "accessPolicy"
  | "driftIncident"
  | "dataStore"
  | "directory"
  | "sourceFile"
  | "configFile";

export type EntityIcon = ComponentType<{
  className?: string;
  style?: CSSProperties;
}>;

/**
 * Single source of truth for entity-type → icon. The lineage node renderers,
 * the cluster pills, the on-canvas legend, and the graph chrome all read from
 * this map so the glyph shown on a node is byte-for-byte the glyph shown in the
 * legend row for the same type. Every type gets a DISTINCT, on-meaning Lucide
 * icon.
 */
export const ENTITY_ICONS: Record<LineageNodeType, EntityIcon> = {
  provider: Cloud,
  agent: Bot,
  server: Server,
  sharedServer: Share2,
  package: Package,
  vulnerability: Bug,
  misconfiguration: TriangleAlert,
  credential: KeyRound,
  tool: Wrench,
  model: BrainCircuit,
  dataset: Database,
  container: Container,
  cloudResource: Box,
  org: Building2,
  account: Landmark,
  user: User,
  group: Users,
  role: IdCard,
  policy: ScrollText,
  serviceAccount: UserCog,
  servicePrincipal: Fingerprint,
  federatedIdentity: Link2,
  environment: Layers,
  fleet: Boxes,
  cluster: Network,
  managedIdentity: BadgeCheck,
  accessGrant: Ticket,
  accessPolicy: ShieldCheck,
  driftIncident: Activity,
  dataStore: Warehouse,
  directory: Folder,
  sourceFile: FileCode,
  configFile: FileCog,
};

export function entityIcon(
  nodeType: LineageNodeType | string | undefined,
): EntityIcon {
  if (nodeType && nodeType in ENTITY_ICONS) {
    return ENTITY_ICONS[nodeType as LineageNodeType];
  }
  return Box;
}
