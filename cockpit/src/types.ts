// Mirrors the JSON the LATTICE engine emits (crates/lattice-engine, lattice-risk, lattice-core).

export type Tier = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Threat = 'harvest' | 'forge' | 'integrity';
export type Liveness = 'Capable' | 'Configured' | 'Confirmed';
export type Surface = 'source' | 'binary' | 'container' | 'certificate' | 'config' | 'cloud' | 'runtime';
export type ClassicalStatus = 'acceptable' | 'legacy' | 'disallowed' | 'broken';

export interface Params {
  keyBits?: number;
  parameterSet?: string;
  curve?: string;
  mode?: string;
  padding?: string;
  digest?: string;
}

export interface AlgorithmRef {
  id: string;
  params?: Params;
}

export type Finding =
  | { assetType: 'algorithm'; algorithm: AlgorithmRef; primitive?: string; function?: string }
  | {
      assetType: 'certificate';
      subject: string;
      issuer: string;
      notBefore: string;
      notAfter: string;
      serial: string;
      publicKey: AlgorithmRef;
      signature: AlgorithmRef;
      selfSigned: boolean;
      isCa: boolean;
      fingerprintSha256: string;
    }
  | { assetType: 'protocol'; protocol: string; version?: string; cipherSuites?: string[]; groups?: string[] }
  | {
      assetType: 'related-crypto-material';
      materialType: string;
      algorithm?: AlgorithmRef;
      sizeBits?: number;
      format: string;
      encrypted: boolean;
      identity: string;
    };

export interface Location {
  path: string;
  line?: number;
  column?: number;
  byteOffset?: number;
}

export interface Occurrence {
  surface: Surface;
  location: Location;
  evidence: { collector: string; ruleId: string; ruleVersion: string; kind: string; matchedToken: string };
  usage?: {
    language: string;
    api: string;
    function?: string;
    identifiers?: string[];
    algorithmSource: string;
    apiStyle: string;
  };
  refinedFrom?: string;
}

export interface CryptoAsset {
  id: string;
  component: string;
  finding: Finding;
  occurrences: Occurrence[];
  surfaces: Surface[];
  liveness: Liveness;
  livenessReason: string;
  evidenceGrade: 'A' | 'B' | 'C' | 'D';
  gradeReason: string;
  dependsOn?: string[];
}

export interface EntryPoint {
  kind: 'http-route' | 'main' | 'library-export' | 'listener';
  detail: string;
}

export interface DataClassification {
  dataAssetId: string;
  class: string;
  secrecyLifetimeYears: number;
  criticality: string;
  rule: string;
  confidence: number;
  explanation: string;
  matches: { source: string; name: string; term: string }[];
}

export interface AssetContext {
  reachable: boolean;
  entry?: EntryPoint | null;
  path: string[];
  exposure: number;
  exposureReason: string;
  data: DataClassification;
  dataInherited: boolean;
  pqcReadyLibrary?: string | null;
}

export interface Term {
  name: string;
  value: number;
  reason: string;
}

export interface Mosca {
  applicable: boolean;
  xYears: number;
  xReason: string;
  yYears: number;
  zEarliestYears: number;
  zLatestYears: number;
  urgent: boolean;
  urgentEvenIfLate: boolean;
  urgencyYears: number;
  verdict: string;
}

export interface Assessment {
  quantumBreakability: number;
  quantumReason: string;
  classicalStatus: ClassicalStatus;
  classicalReasons: string[];
  brokenNow: boolean;
  threat: Threat;
  indexKind: 'hndl' | 'tnfl';
  exposureIndex: number;
  indexTerms: Term[];
  agility: { score: number; factors: { name: string; points: number; max: number; reason: string }[] };
  mosca: Mosca;
  priority: number;
  tier: Tier;
  priorityReasons: string[];
}

export interface Recommendation {
  action: string;
  target: string;
  rationale: string;
  sizeDelta?: { beforeBytes: number; afterBytes: number; basis: string } | null;
}

export interface AssetReport {
  /** Display name, identical to the CBOM component name. */
  name: string;
  asset: CryptoAsset;
  context: AssetContext;
  assessment: Assessment;
  recommendation: Recommendation;
  /** Absent when the asset is retained. */
  effort?: Effort;
}

export interface Effort {
  personWeeks: number;
  factors: { name: 'action' | 'surface' | 'agility' | 'spread' | 'criticality'; value: number; reason: string }[];
}

export interface WavePlan {
  wave: number;
  name: string;
  items: number;
  personWeeks: number;
  dueYear?: number;
  cumulativePersonWeeks: number;
  weeksAvailable?: number;
  engineersNeeded?: number;
  overdue: boolean;
}

export interface MigrationPlan {
  timeline: string;
  reference: string;
  assessmentYear: number;
  totalPersonWeeks: number;
  waves: WavePlan[];
  engineersNeeded?: number;
  overdue: boolean;
}

export interface Summary {
  assets: number;
  quantumVulnerable: number;
  brokenNow: number;
  moscaUrgent: number;
  critical: number;
  high: number;
}

export interface RoadmapItem {
  wave: number;
  waveName: string;
  assetId: string;
  name: string;
  component: string;
  tier: Tier;
  priority: number;
  agility: number;
  migrationYears: number;
  action: string;
  target: string;
  effortPersonWeeks: number;
  dueYear?: number;
}

export interface Report {
  format: string;
  subject: string;
  generated: string;
  provenance: {
    toolVersion: string;
    knowledgeVersion: string;
    rulesVersion: string;
    policyVersion: string;
    assessmentYear: number;
    qDayEarliest: number;
    qDayLatest: number;
  };
  summary: Summary;
  stats: { filesSeen: number; filesScanned: number; bytesScanned: number; skippedTooLarge: number; byCollector: Record<string, number> };
  graph: { functions: number; entryPoints: number; callsResolved: number; callsUnresolved: number; reachableFunctions: number; reachableAssets: number };
  failures: { path: string; collector: string; reason: string }[];
  assets: AssetReport[];
  libraries: { component: string; name: string; version?: string; pqcCapable: boolean; basis: string }[];
  roadmap: RoadmapItem[];
  plan: MigrationPlan;
}

export type GraphNode =
  | { type: 'component'; id: string }
  | { type: 'entry'; id: string; kind: EntryPoint['kind']; detail: string }
  | { type: 'function'; id: string; name: string; path: string; line: number }
  | { type: 'crypto'; id: string; name: string; assetType: string }
  | { type: 'data'; id: string; class: string; secrecyLifetimeYears: number; criticality: string }
  | { type: 'library'; id: string; name: string; version?: string; pqcCapable: boolean };

export type EdgeKind = 'contains' | 'exposes' | 'calls' | 'uses' | 'protects' | 'depends-on' | 'links';

export interface Graph {
  nodes: GraphNode[];
  edges: { source: string; target: string; kind: EdgeKind }[];
}

export type ScanStatus = 'queued' | 'running' | 'done' | 'failed';

export interface ScanMeta {
  id: string;
  subject: string;
  root: string;
  path: string;
  status: ScanStatus;
  error?: string;
  requested: string;
  finished?: string;
  durationMs?: number;
  summary?: Summary;
  failures: number;
  requestedBy?: string;
}

export type Role = 'viewer' | 'operator' | 'admin';

export interface Principal {
  name: string;
  role: Role;
}

export interface AuditEntry {
  seq: number;
  time: string;
  actor: string;
  role?: Role;
  method: string;
  path: string;
  status: number;
  peer?: string;
  prev: string;
}

export interface AuditPage {
  entries: number;
  head: string;
  recent: AuditEntry[];
}

export interface Health {
  status: string;
  version: string;
  knowledgeVersion: string;
  knowledgeSequence: number;
  knowledgeSigner?: string | null;
  policyVersion: string;
  qDay: [number, number];
  activeScans: number;
  authentication?: boolean;
  sandbox?: {
    mode: 'off' | 'best-effort' | 'required';
    filesystem: { state: 'enforced' | 'partial' | 'unavailable' | 'off'; detail?: string };
    syscalls: { state: 'enforced' | 'partial' | 'unavailable' | 'off'; detail?: string };
  } | null;
}

export interface Change {
  kind: 'added' | 'worsened' | 'improved' | 'removed';
  bomRef: string;
  name: string;
  component: string;
  tier?: Tier | null;
  previousTier?: Tier | null;
  regression: boolean;
  reason: string;
}

export interface Comparison {
  threshold: Tier;
  changes: Change[];
}
