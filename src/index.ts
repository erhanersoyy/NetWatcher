import express, { type Request, type Response, type NextFunction } from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { router } from './routes.js';
import { shutdownTrafficStream } from './traffic-stream.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3847;
const HOST = '127.0.0.1';
const ALLOWED_ORIGIN = `http://localhost:${PORT}`;
const ALLOWED_ORIGIN_LOOPBACK = `http://127.0.0.1:${PORT}`;
const ALLOWED_HOSTS = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`]);

app.use(express.json());

app.use('/api', (req: Request, res: Response, next: NextFunction) => {
  // Host header allowlist — defeats DNS rebinding. A malicious page that
  // rebinds attacker.example -> 127.0.0.1 still sends Host: attacker.example.
  const host = req.headers.host;
  if (!host || !ALLOWED_HOSTS.has(host)) {
    res.status(403).json({ success: false, message: 'Forbidden host' });
    return;
  }
  const origin = req.headers.origin;
  if (origin && origin !== ALLOWED_ORIGIN && origin !== ALLOWED_ORIGIN_LOOPBACK) {
    res.status(403).json({ success: false, message: 'Forbidden origin' });
    return;
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (req.headers['x-requested-by'] !== 'netwatcher') {
      res.status(403).json({ success: false, message: 'Missing CSRF header' });
      return;
    }
  }
  next();
});

app.use(express.static(join(__dirname, '..', 'public')));
app.use(router);

const server = app.listen(PORT, HOST, () => {
  // Defense-in-depth: refuse to run if we somehow ended up bound to a
  // non-loopback address. We passed HOST='127.0.0.1' explicitly, so the
  // kernel can only bind there — but server.address() is occasionally
  // flaky immediately inside the listen callback (returns null). Trust
  // the bind when address() is unavailable; only reject when we can
  // *prove* it went somewhere unexpected.
  const addr = server.address();
  if (typeof addr === 'string') {
    console.error(`NetWatcher refused to start: bound to unix socket ${addr}`);
    process.exit(1);
  }
  if (addr && addr.address !== HOST && addr.address !== '::1' && addr.address !== '::ffff:127.0.0.1') {
    console.error(`NetWatcher refused to start: bound to ${addr.address}, expected ${HOST}`);
    process.exit(1);
  }
  console.log(`\n  NetWatcher running at http://${HOST}:${PORT}\n`);
});

server.on('error', (err) => {
  console.error(`NetWatcher listen error: ${(err as Error).message}`);
  process.exit(1);
});

// Graceful shutdown. Without this, `tsx watch` restarts and plain Ctrl+C
// can leave the HTTP listener holding port 3847 (EADDRINUSE on next start)
// and orphan the in-flight `nettop` child spawned by the traffic stream.
//
// Flow: stop the traffic sampler so no new nettop gets spawned → close
// the HTTP server (stops accepting new connections, waits for in-flight
// to drain) → force-close any long-lived SSE sockets → exit. A 2s
// watchdog covers the pathological case where a client keeps an SSE
// connection open despite server.close().
let shuttingDown = false;
function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n  ${signal} received — shutting down…`);
  shutdownTrafficStream();
  // Express 5 doesn't auto-drop open keep-alive sockets; force them first
  // so `server.close()` can actually complete instead of hanging on idle
  // keep-alives / long-lived SSE streams.
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 2000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
