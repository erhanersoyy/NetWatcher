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
}

export interface EnrichedConnection {
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
  pid: number;
  processName: string;
  description: string;
  isSystemProcess: boolean;
  connections: EnrichedConnection[];
}

export interface BlockRecord {
  ip: string;
  country: string | null;
  blockedAt: number;
}

export interface BlockEvent {
  ip: string;
  action: 'block' | 'unblock';
  at: number;
  country?: string | null;
}

export interface BlockHistoryResponse {
  active: BlockRecord[];
  history: BlockEvent[];
}
