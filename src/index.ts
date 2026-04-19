import express, { type Request, type Response, type NextFunction } from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { router } from './routes.js';

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
  // Defense-in-depth: refuse to run if we somehow didn't land on loopback.
  const addr = server.address();
  if (!addr || typeof addr === 'string' || addr.address !== HOST) {
    console.error(`NetWatcher refused to start: bound to ${JSON.stringify(addr)}, expected ${HOST}`);
    process.exit(1);
  }
  console.log(`\n  NetWatcher running at http://${HOST}:${PORT}\n`);
});
