require('dotenv').config();

const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const WebSocket = require('ws');
const helmet = require('helmet');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const {
  SERVER_HOST = 'localhost',
  SERVER_WSS_PORT = 8443,
  SERVER_API_PORT = 8080,
  CLIENT_PORT = 3001,
  WSS_SECRET_TOKEN = 'dev-token',
  LOG_LEVEL = 'info',
} = process.env;

// --- Resolve paths for Electron -------------------------------------------
// Dev:      __dirname = project root, templates/ and static/ are siblings
// Packaged: files are in app.asar, extraResources land at process.resourcesPath
//           so templates/ = process.resourcesPath/templates
const isElectron = !!(process.versions && process.versions.electron);

// process.resourcesPath exists in both dev electron and packaged
// In dev it points to node_modules/electron/dist/resources — no templates there
// Detect packaged by checking if app.asar exists in resourcesPath
let basePath;
if (isElectron && process.resourcesPath) {
  const asarPath = path.join(process.resourcesPath, 'app.asar');
  if (fs.existsSync(asarPath)) {
    // Packaged — extraResources are at resourcesPath level
    basePath = process.resourcesPath;
  } else {
    // Dev electron (npm start)
    basePath = __dirname;
  }
} else {
  basePath = __dirname;
}

// --- Writable data dir (APPDATA on Windows, home on Linux/Mac) ------------
// Never write to Program Files — no permissions there
const appDataDir = process.env.APPDATA
  ? path.join(process.env.APPDATA, 'MISTRAL Defense')
  : path.join(require('os').homedir(), '.mistral-defense');

// --- Logging --------------------------------------------------------------
const logDir = path.join(appDataDir, 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(({ level, message, timestamp, ...meta }) => {
    const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
    return `${timestamp} [${level.toUpperCase()}] ${message}${metaStr}`;
  })
);

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: logFormat,
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({
      filename: path.join(logDir, 'client-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxFiles: '30d',
      zippedArchive: true,
    }),
  ],
});

// --- In-memory caches -----------------------------------------------------
const cache = {
  incidents: [],
  logs: [],
  botLogs: [],
  cveLogs: [],
  stats: null,
  metrics: null,
  aiResults: [],
  reviewQueue: [],
  cveReviewQueue: [],
  model: 'deepseek-v4-pro',
  connectedAt: null,
  lastPing: null,
};

// --- Express Client Server ------------------------------------------------
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10mb' }));

// Static files — resolve for both dev and Electron packaged
const staticPath = path.join(basePath, 'static');
const templatesPath = path.join(basePath, 'templates');

app.use('/static', express.static(staticPath));
app.get('/', (_req, res) => {
  res.sendFile(path.join(templatesPath, 'index.html'));
});

// Health
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    connectedToServer: wsClient && wsClient.readyState === WebSocket.OPEN,
    model: cache.model,
    uptime: process.uptime(),
    cachedIncidents: cache.incidents.length,
    cachedLogs: cache.logs.length,
  });
});

// Cached data endpoints
app.get('/api/cache/incidents', (_req, res) => res.json(cache.incidents));
app.get('/api/cache/logs', (req, res) => {
  const { type = 'server', limit = 100 } = req.query;
  const data = type === 'bot' ? cache.botLogs : type === 'cve' ? cache.cveLogs : cache.logs;
  res.json(data.slice(0, Number(limit)));
});
app.get('/api/cache/stats', (_req, res) => res.json(cache.stats || {}));
app.get('/api/cache/metrics', (_req, res) => res.json(cache.metrics || {}));
app.get('/api/cache/review', (_req, res) => res.json({ logs: cache.reviewQueue, cves: cache.cveReviewQueue }));
app.get('/api/cache/ai-results', (_req, res) => res.json(cache.aiResults.slice(-50)));

// ── Auth endpoint for client login ──
const { CLIENT_LOGIN, CLIENT_PASSWORD } = process.env;
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!CLIENT_LOGIN || !CLIENT_PASSWORD) {
    // Fallback: allow any if not configured (dev mode)
    return res.json({ success: true, token: 'dev-token' });
  }
  if (username === CLIENT_LOGIN && password === CLIENT_PASSWORD) {
    const token = Buffer.from(`${username}:${Date.now()}:${Math.random().toString(36).slice(2)}`).toString('base64');
    return res.json({ success: true, token });
  }
  res.status(401).json({ success: false, error: 'Invalid credentials' });
});

// ── Server URL config (set from browser during login) ──
let configuredServerUrl = '';

app.post('/api/set-server', (req, res) => {
  const { url } = req.body || {};
  if (url) configuredServerUrl = url;
  res.json({ ok: true, url: configuredServerUrl });
});

app.post('/api/check-server', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ ok: false, error: 'No URL provided' });
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(`${url.replace(/\/$/, '')}/api/health`, { timeout: 5000 });
    const data = await response.json();
    if (data.status === 'ok') {
      configuredServerUrl = url;
      res.json({ ok: true, url });
    } else {
      res.json({ ok: false, error: 'Server responded but not ok' });
    }
  } catch (err) {
    logger.error('check-server error', { error: err.message });
    res.json({ ok: false, error: 'Server unreachable: ' + err.message });
  }
});

// Proxy login to actual server
app.post('/api/proxy-login', async (req, res) => {
  const serverUrl = configuredServerUrl || `http://${SERVER_HOST}:${SERVER_API_PORT}`;
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(`${serverUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    logger.error('proxy-login error', { error: err.message });
    res.status(502).json({ success: false, error: 'Server unreachable' });
  }
});

app.post('/api/connect-ws', (req, res) => {
  const { host, port } = req.body;
  connectToServer(host, port);
  res.json({ ok: true });
});

// Proxy to server REST API
app.all('/api/proxy/*', async (req, res) => {
  try {
    const serverPath = req.path.replace('/api/proxy', '');
    const serverUrl = `http://${SERVER_HOST}:${SERVER_API_PORT}${serverPath}`;
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(serverUrl, {
      method: req.method,
      headers: { 'Content-Type': 'application/json' },
      body: req.method !== 'GET' && req.method !== 'HEAD' ? JSON.stringify(req.body) : undefined,
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    logger.error('Proxy error', { error: err.message });
    res.status(502).json({ error: 'Server unreachable', details: err.message });
  }
});

// --- WebSocket Client to Mistral Server ------------------------------------
let wsClient = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_DELAY = 30000;

function connectToServer(host, port = 8443) {
  const wssUrl = `wss://${host}:${port}/ws`;
  logger.info(`Connecting to Mistral Server at ${wssUrl}`);

  try {
    wsClient = new WebSocket(wssUrl, {
      rejectUnauthorized: false,
    });
  } catch (err) {
    logger.error('WS creation failed', { error: err.message });
    return;
  }

  wsClient.on('open', () => {
    logger.info('Connected to Mistral Server');
    reconnectAttempts = 0;
    cache.connectedAt = new Date().toISOString();
    // Authenticate immediately
    wsClient.send(JSON.stringify({
      event: 'auth',
      data: { token: WSS_SECRET_TOKEN, nonce: Date.now().toString(36) + Math.random().toString(36).slice(2, 8) }
    }));
    wsClient.send(JSON.stringify({ event: 'get_stats' }));
    wsClient.send(JSON.stringify({ event: 'get_incidents' }));
    wsClient.send(JSON.stringify({ event: 'get_logs', data: { type: 'server', limit: 200 } }));
  });

  wsClient.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      logger.debug('WS message from server', { event: msg.event });

      switch (msg.event) {
        case 'auth_success':
          cache.model = msg.data?.model || cache.model;
          logger.info('WS authenticated with server');
          break;
        case 'auth_error':
          logger.error('WS authentication failed', msg.data);
          break;
        case 'stats':
          cache.stats = msg.data;
          break;
        case 'incidents_list':
          cache.incidents = msg.data || [];
          break;
        case 'logs_list':
          cache.logs = msg.data || [];
          break;
        case 'log':
          if (msg.data) {
            if (msg.data.type === 'bot') cache.botLogs.unshift(msg.data);
            else if (msg.data.type === 'cve') cache.cveLogs.unshift(msg.data);
            else cache.logs.unshift(msg.data);
            trimCache();
          }
          break;
        case 'incident':
          if (msg.data) cache.incidents.unshift(msg.data);
          if (cache.incidents.length > 5000) cache.incidents.pop();
          break;
        case 'incident_updated':
          if (msg.data) {
            const idx = cache.incidents.findIndex(i => i.id === msg.data.id);
            if (idx !== -1) cache.incidents[idx] = msg.data;
          }
          break;
        case 'metrics':
          cache.metrics = msg.data;
          break;
        case 'model_changed':
          cache.model = msg.data?.model || cache.model;
          break;
        case 'ai_result':
          cache.aiResults.push({ ...msg.data, receivedAt: new Date().toISOString() });
          if (cache.aiResults.length > 200) cache.aiResults.shift();
          break;
        case 'ai_error':
          cache.aiResults.push({ ...msg.data, receivedAt: new Date().toISOString(), error: true });
          break;
        case 'review_queue':
          if (msg.data?.log) cache.reviewQueue.unshift(msg.data.log);
          if (cache.reviewQueue.length > 500) cache.reviewQueue.pop();
          break;
        case 'cve_review_queue':
          if (msg.data?.cve) cache.cveReviewQueue.unshift(msg.data.cve);
          if (cache.cveReviewQueue.length > 500) cache.cveReviewQueue.pop();
          break;
        case 'bot_action':
          if (msg.data) {
            cache.botLogs.unshift({
              id: msg.data.id || Date.now().toString(),
              timestamp: msg.data.timestamp || new Date().toISOString(),
              type: 'bot',
              level: 'info',
              message: `Bot action: ${msg.data.type}`,
              meta: msg.data,
            });
            trimCache();
          }
          break;
        case 'pong':
          cache.lastPing = Date.now();
          break;
        default:
          logger.debug('Unhandled WS event', { event: msg.event });
      }

      relayToBrowserClients(msg);
    } catch (err) {
      logger.error('WS message parse error', { error: err.message, raw: raw.toString().slice(0, 200) });
    }
  });

  wsClient.on('close', (code, reason) => {
    logger.warn('WS connection closed', { code, reason: reason?.toString() });
    wsClient = null;
    scheduleReconnect();
  });

  wsClient.on('error', (err) => {
    logger.error('WS error', { error: err.message });
    wsClient = null;
    scheduleReconnect();
  });
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_RECONNECT_DELAY);
  reconnectAttempts++;
  logger.info(`Reconnecting in ${delay}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectToServer();
  }, delay);
}

function trimCache() {
  if (cache.logs.length > 5000) cache.logs = cache.logs.slice(0, 5000);
  if (cache.botLogs.length > 5000) cache.botLogs = cache.botLogs.slice(0, 5000);
  if (cache.cveLogs.length > 5000) cache.cveLogs = cache.cveLogs.slice(0, 5000);
}

// Keep-alive ping
setInterval(() => {
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify({ event: 'ping' }));
  }
}, 30000);

// --- Browser WebSocket Server ---------------------------------------------
const browserClients = new Map();

function relayToBrowserClients(msg) {
  const data = JSON.stringify(msg);
  for (const [ws] of browserClients) {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(data); } catch (e) { logger.error('Browser relay error', e); }
    }
  }
}

function startBrowserWSS(server) {
  const wss = new WebSocket.Server({ server, path: '/client-ws' });
  wss.on('connection', (ws) => {
    const clientId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    browserClients.set(ws, { id: clientId, connectedAt: new Date().toISOString() });
    logger.info('Browser client connected', { clientId });

    ws.send(JSON.stringify({ event: 'cache_snapshot', data: { stats: cache.stats, metrics: cache.metrics, model: cache.model } }));

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.event === 'ping') {
          ws.send(JSON.stringify({ event: 'pong', timestamp: Date.now() }));
          return;
        }
        if (msg.event === 'get_incidents') {
          ws.send(JSON.stringify({ event: 'incidents_list', data: cache.incidents.slice(0, 100) }));
          return;
        }
        if (msg.event === 'get_logs') {
          const { type = 'server', limit = 100 } = msg.data || {};
          const data = type === 'bot' ? cache.botLogs : type === 'cve' ? cache.cveLogs : cache.logs;
          ws.send(JSON.stringify({ event: 'logs_list', data: data.slice(0, limit) }));
          return;
        }
        if (msg.event === 'get_stats') {
          ws.send(JSON.stringify({ event: 'stats', data: cache.stats }));
          return;
        }
        if (msg.event === 'get_review') {
          ws.send(JSON.stringify({ event: 'review_queue', data: { logs: cache.reviewQueue, cves: cache.cveReviewQueue } }));
          return;
        }
        if (msg.event === 'get_ai_results') {
          ws.send(JSON.stringify({ event: 'ai_results', data: cache.aiResults.slice(-50) }));
          return;
        }
        if (['ai_task', 'switch_model', 'run_scan'].includes(msg.event)) {
          if (wsClient && wsClient.readyState === WebSocket.OPEN) {
            wsClient.send(JSON.stringify(msg));
          }
          return;
        }
      } catch (err) {
        logger.error('Browser message error', { error: err.message });
      }
    });

    ws.on('close', () => {
      const info = browserClients.get(ws);
      browserClients.delete(ws);
      logger.info('Browser client disconnected', { clientId: info?.id });
    });

    ws.on('error', (err) => {
      logger.error('Browser WS error', { error: err.message });
    });
  });
  return wss;
}

// --- Start Client Server --------------------------------------------------
let clientServer = null;
let browserWss = null;

function startClientServer(callback) {
  clientServer = http.createServer(app);
  clientServer.listen(CLIENT_PORT, () => {
    logger.info(`MISTRAL Client dashboard HTTP on http://localhost:${CLIENT_PORT}`);
    browserWss = startBrowserWSS(clientServer);
    logger.info(`Browser WebSocket endpoint: ws://localhost:${CLIENT_PORT}/client-ws`);
    connectToServer();
    if (callback) callback();
  });

  process.on('SIGINT', () => {
    logger.info('Shutting down client server...');
    if (wsClient) wsClient.close();
    clientServer.close(() => process.exit(0));
  });
}

module.exports = { app, cache, connectToServer, relayToBrowserClients, startClientServer };

// Auto-start if run directly (not required by Electron main.js)
if (require.main === module) {
  startClientServer();
}
