import express, { type ErrorRequestHandler } from 'express';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { router } from './routes.js';

export const CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
const COOKIE = 'netwatcher_session';
const SESSION_MS = 12 * 60 * 60 * 1000;
function equalSecret(value: string, expected: string): boolean {
  const a = Buffer.from(value), b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function createApp(accessKey: string, apiRouter: ReturnType<typeof express.Router> = router): ReturnType<typeof express> {
  if (accessKey.length < 32) throw new Error('Access key must contain at least 32 characters');
  const app = express();
  const sessions = new Map<string, number>();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    if (!['127.0.0.1:3847', 'localhost:3847'].includes(req.headers.host ?? '')) {
      res.status(403).json({ success: false, message: 'Forbidden host' }); return;
    }
    if ((req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) || req.headers['sec-fetch-site'] === 'cross-site') {
      res.status(403).json({ success: false, message: 'Forbidden origin' }); return;
    }
    next();
  });
  app.use('/api', (req, res, next) => {
    if (req.path !== '/traffic-stream' && req.headers['x-requested-by'] !== 'netwatcher') {
      res.status(403).json({ success: false, message: 'Missing CSRF header' }); return;
    }
    // Authorization happens BEFORE parsing any request body, including compressed bodies.
    if (req.path === '/session' && req.method === 'POST') {
      if (!equalSecret(req.headers.authorization ?? '', `Bearer ${accessKey}`)) {
        res.status(401).json({ success: false, message: 'Open the access link printed by this server' }); return;
      }
      for (const [key, expires] of sessions) if (expires <= Date.now()) sessions.delete(key);
      if (sessions.size >= 8) sessions.delete(sessions.keys().next().value!);
      const token = randomBytes(32).toString('base64url');
      sessions.set(token, Date.now() + SESSION_MS);
      // HTTP loopback: Secure cookies are not portable across localhost browsers.
      // HttpOnly + Strict + exact Origin + custom mutation header remain mandatory.
      res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'strict', path: '/api', maxAge: SESSION_MS });
      res.json({ success: true }); return;
    }
    const cookie = (req.headers.cookie ?? '').split(';').map(part => part.trim()).find(part => part.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1);
    if (!cookie || (sessions.get(cookie) ?? 0) <= Date.now()) {
      res.status(401).json({ success: false, message: 'Session expired or missing. Open the access link printed by this server.' }); return;
    }
    if (req.path === '/traffic-stream') {
      const expiry = setTimeout(() => res.end(), Math.max(1, sessions.get(cookie)! - Date.now()));
      expiry.unref();
      res.once('close', () => clearTimeout(expiry));
    }
    next();
  });
  app.get('/api/session', (_req, res) => res.json({ success: true }));
  app.use('/api', express.json({ limit: '8kb', inflate: false }));
  app.use(express.static(join(dirname(fileURLToPath(import.meta.url)), '..', 'public')));
  app.use(apiRouter);
  const errors: ErrorRequestHandler = (err: unknown, _req, res, _next) => {
    const e = err as { status?: number; type?: string };
    const status = e.status && e.status >= 400 && e.status < 500 ? e.status : 500;
    // Parser errors can contain the submitted password in `body`; never log/echo them.
    res.status(status).json({ success: false, message: status === 500 ? 'Request failed' : 'Request body rejected' });
  };
  app.use(errors);
  return app;
}
