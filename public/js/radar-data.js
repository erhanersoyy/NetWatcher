// Pure view model shared by the map, its accessible list, and regression tests.
export function validGeo(geo) {
  return !!geo && geo.countryCode !== 'LO' && Number.isFinite(geo.lat) && Number.isFinite(geo.lon)
    && Math.abs(geo.lat) <= 90 && Math.abs(geo.lon) <= 180;
}

export function processKey(proc) {
  return JSON.stringify([proc.pid, proc.identity?.token ?? null,
    proc.identity?.startedAt ?? null, proc.identity?.executable ?? null]);
}

export function filterMapProcesses(processes, selection) {
  if (!selection) return processes;
  const ips = new Set(selection.ips);
  return processes.map(proc => ({ ...proc, connections: proc.connections.filter(c => ips.has(c.remoteAddress)) }))
    .filter(proc => proc.connections.length);
}

export function mapRatesAvailable(state, now = Date.now()) {
  return !state.paused && !state.connectionsError && state.streamHealthy && state.hasRateSample
    && state.lastDeltaAt > 0 && now - state.lastDeltaAt <= 3000
    && (!state.connectionsUpdatedAt || now - state.connectionsUpdatedAt <= Math.max(30000, (state.refreshIntervalMs || 10000) * 2));
}

const number = value => Number.isFinite(value) && value >= 0 ? value : null;

export function collectTargets(processes, traffic, ratesAvailable) {
  const targets = new Map();
  for (const proc of processes) {
    const key = processKey(proc);
    for (const conn of proc.connections) {
      const ip = conn.remoteAddress;
      let target = targets.get(ip);
      if (!target) {
        target = { ip, geo: null, processes: new Map(), connections: 0, bytesIn: null, bytesOut: null,
          rxBps: null, txBps: null, trafficKeys: new Set(), connectionKeys: new Set(), missing: new Set() };
        targets.set(ip, target);
      }
      if (!target.geo && validGeo(conn.geo)) target.geo = conn.geo;
      target.processes.set(key, { key, pid: proc.pid, name: proc.processName });
      const connectionKey = JSON.stringify([key, conn.protocol, conn.localAddress, conn.localPort, ip, conn.remotePort]);
      if (!target.connectionKeys.has(connectionKey)) {
        target.connectionKeys.add(connectionKey);
        target.connections++;
      }
      // A traffic sample can be attributed to more than one process/socket row.
      // Count its bytes once per destination; never turn a missing sample into zero.
      const trafficKey = conn.trafficKey || connectionKey;
      if (target.trafficKeys.has(trafficKey)) continue;
      target.trafficKeys.add(trafficKey);
      const live = traffic.get(conn.trafficKey);
      for (const field of ['bytesIn', 'bytesOut', 'rxBps', 'txBps']) {
        const rate = field.endsWith('Bps');
        const value = number(rate ? (ratesAvailable ? live?.[field] : null) : (live?.[field] ?? conn[field]));
        if (value !== null) target[field] = (target[field] ?? 0) + value;
        else target.missing.add(field);
      }
    }
  }
  return [...targets.values()].map(({ trafficKeys, connectionKeys, missing, processes, ...target }) => ({
    ...target, ...Object.fromEntries([...missing].map(field => [field, null])), processes: [...processes.values()],
  })).sort((a, b) => a.ip.localeCompare(b.ip));
}

export function targetFeatures(targets) {
  return { type: 'FeatureCollection', features: targets.filter(t => t.geo).map(t => ({
    type: 'Feature', id: t.ip, properties: { ip: t.ip },
    // Mercator cannot represent the poles. Preserve original coordinates in the view model.
    geometry: { type: 'Point', coordinates: [t.geo.lon, Math.max(-85, Math.min(85, t.geo.lat))] },
  })) };
}

// Unwrap world-atlas rings across the dateline (Fiji/Russia). GeoJSON tiling
// then clips/wraps the polygon, instead of drawing a transcontinental edge.
// Leave a ring that actually winds around the entire world (Antarctica) intact.
export function prepareCountryAtlas(collection) {
  const ring = coordinates => {
    let previous = coordinates[0][0];
    const unwrapped = coordinates.map(([lon, lat]) => {
      while (lon - previous > 180) lon -= 360;
      while (lon - previous < -180) lon += 360;
      previous = lon;
      return [lon, lat];
    });
    return Math.abs(unwrapped.at(-1)[0] - unwrapped[0][0]) > 180 ? coordinates : unwrapped;
  };
  return { ...collection, features: collection.features.map(feature => ({ ...feature, geometry: {
    ...feature.geometry, coordinates: feature.geometry.type === 'Polygon'
      ? feature.geometry.coordinates.map(ring) : feature.geometry.coordinates.map(polygon => polygon.map(ring)),
  } })) };
}
