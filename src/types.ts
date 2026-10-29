import type { ProcessIdentity } from './process-identity.js';
import type { ProcessVerification } from './process-verification.js';
import type { LookupState } from './geolocation.js';
export interface Connection {
  pid: number;
  processName: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
}

export interface GeoInfo {
  country: string;
  countryCode: string;
  city: string;
  isp: string;
  lat: number;
  lon: number;
}

export interface HostInfo {
  localIP: string;
  publicIP: string;
  hostname: string;
  geo: GeoInfo | null;
  publicIPStatus?: 'ready' | 'unavailable';
  geoStatus?: LookupState;
  geoRetryAt?: number;
  checkedAt?: number | null;
}

export interface EnrichedConnection {
  enrichment?: { geo: LookupState; dns: LookupState };
  protocol: string;
  remoteAddress: string;
  remotePort: number;
  localAddress: string;
  localPort: number;
  state: string;
  geo: GeoInfo | null;
  domain: string;
  bytesIn?: number;
  bytesOut?: number;
  /**
   * Server-computed traffic-stream key — matches the SSE delta key so the
   * frontend can look up live bytes without recomputing the key per-conn
   * per-render. Keeps the canonical IP-normalization logic in one place.
   */
  trafficKey: string;
}

export interface ProcessInfo {
  identity: ProcessIdentity | null;
  verification?: ProcessVerification;
  pid: number;
  processName: string;
  description: string;
  isSystemProcess: boolean;
  connections: EnrichedConnection[];
}

export interface BlockRecord {
  ip: string;
  country: string | null;
  countryCode?: string | null;
  isp?: string | null;
  blockedAt: number;
  /** Boot epoch-second in which this IP was last added to the pf table.
   *  Stale (not enforced) when it differs from the current boot id. */
  appliedBoot?: number | null;
}

export interface BlockEvent {
  ip: string;
  action: 'block' | 'unblock';
  at: number;
  country?: string | null;
  countryCode?: string | null;
  isp?: string | null;
}

export interface BlockHistoryResponse {
  active: BlockRecord[];
  history: BlockEvent[];
}

/** Standard result for state-changing actions (block/unblock/kill/etc.). */
export interface ActionResult {
  partial?: boolean;
  stages?: { tableUpdated: boolean; stateCleanup: boolean | null; persisted: boolean };
  trafficVerified?: false;
  success: boolean;
  message: string;
}
