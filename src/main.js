const { app, BrowserWindow, ipcMain, Notification, Tray, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const Store = require('electron-store');

const store = new Store();

// ═══════════════════════════════════════════════════════════════════════════
//  MISTRAL Defense — Electron Desktop Application (IPC mode)
// ═══════════════════════════════════════════════════════════════════════════

let mainWindow;
let splashWindow;
let tray = null;

// --- Data Dir & Logging ---
const appDataDir = process.env.APPDATA
  ? path.join(process.env.APPDATA, 'MISTRAL Defense')
  : path.join(require('os').homedir(), '.mistral-defense');

const logDir = path.join(appDataDir, 'logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ level, message, timestamp }) => `${timestamp} [${level.toUpperCase()}] ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile({ filename: path.join(logDir, 'client-%DATE%.log'), datePattern: 'YYYY-MM-DD', maxFiles: '14d' })
  ]
});

// --- State ---
let wsClient = null;
let reconnectTimer = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_DELAY = 30000;
let serverConfig = { host: '', port: 8080, url: '', token: '' };

const cache = {
  incidents: [], logs: [], botLogs: [], cveLogs: [],
  stats: null, metrics: null, model: 'deepseek-v4-pro'
};

function trimCache() {
  if (cache.logs.length > 5000) cache.logs = cache.logs.slice(0, 5000);
  if (cache.botLogs.length > 5000) cache.botLogs = cache.botLogs.slice(0, 5000);
  if (cache.cveLogs.length > 5000) cache.cveLogs = cache.cveLogs.slice(0, 5000);
  if (cache.incidents.length > 5000) cache.incidents = cache.incidents.slice(0, 5000);
}

// --- Windows ---
function createSplash() {
  splashWindow = new BrowserWindow({
    width: 500, height: 320, frame: false, transparent: true,
    alwaysOnTop: true, resizable: false,
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });
  splashWindow.loadURL(`data:text/html,${encodeURIComponent(`
    <!DOCTYPE html>
    <html>
    <head><style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{background:#080808;color:#f5f5f5;font-family:'Segoe UI',system-ui;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;}
      .logo{font-size:48px;margin-bottom:16px;text-shadow:0 0 20px rgba(229,9,20,.4)}
      .title{font-size:24px;font-weight:800;letter-spacing:3px;margin-bottom:8px}
      .title span{color:#e50914}
      .loader{width:200px;height:2px;background:#2a2a2a;border-radius:1px;overflow:hidden;margin-top:24px;}
      .loader-fill{height:100%;width:0%;background:#e50914;animation:load 2s ease forwards}
      @keyframes load{to{width:100%}}
      .status{margin-top:16px;font-size:11px;color:#999}
    </style></head>
    <body>
      <div class="logo">⚔️</div>
      <div class="title">MIST<span>RAL</span></div>
      <div class="loader"><div class="loader-fill"></div></div>
      <div class="status">Инициализация системы...</div>
    </body>
    </html>
  `)}`);
  splashWindow.center();
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1600, height: 900, minWidth: 1200, minHeight: 700,
    title: 'MISTRAL Defense Command Center',
    icon: path.join(__dirname, 'static', 'icon.png'),
    backgroundColor: '#080808', show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: false // To allow loading local resources directly via file://
    }
  });

  // Защита от захвата экрана и скриншотов (для Enterprise)
  mainWindow.setContentProtection(true);

  mainWindow.loadFile(path.join(__dirname, 'templates', 'index.html'));

  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.control && input.shift && input.key.toLowerCase() === 'i') {
      mainWindow.webContents.toggleDevTools();
    }
  });

  mainWindow.once('ready-to-show', () => {
    if (splashWindow) splashWindow.close();
    mainWindow.show();
    mainWindow.maximize();
  });
  mainWindow.on('closed', () => { mainWindow = null; });
}

// --- WebSocket logic ---
function connectToServer(host, port, token) {
  if (wsClient) { try { wsClient.terminate(); } catch(_) {} wsClient = null; }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  serverConfig = { host, port, token, url: `http://${host}:${port}` };

  const wsUrl = `ws://${host}:${port}/ws`;
  logger.info(`Connecting to ${wsUrl}`);
  
  if (mainWindow) mainWindow.webContents.send('conn-status', 'connecting', `Подключение... (${host}:${port})`);

  try { wsClient = new WebSocket(wsUrl); } 
  catch (err) { logger.error('WS Error: ' + err.message); scheduleReconnect(); return; }

  wsClient.on('open', () => {
    logger.info('Connected to Mistral Server');
    reconnectAttempts = 0;
    if (mainWindow) mainWindow.webContents.send('conn-status', 'connected', 'Подключён');
    wsClient.send(JSON.stringify({ event: 'auth', data: { token, nonce: Date.now().toString(36) } }));
    wsClient.send(JSON.stringify({ event: 'get_stats' }));
    wsClient.send(JSON.stringify({ event: 'get_incidents' }));
    wsClient.send(JSON.stringify({ event: 'get_logs', data: { type: 'server', limit: 200 } }));
  });

  wsClient.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      if (mainWindow) mainWindow.webContents.send('ws-message', msg);
      
      // Cache data
      switch (msg.event) {
        case 'stats': cache.stats = msg.data; break;
        case 'incidents_list': cache.incidents = msg.data || []; break;
        case 'logs_list': cache.logs = msg.data || []; break;
        case 'log':
          if (msg.data) cache.logs.unshift(msg.data);
          trimCache();
          break;
        case 'incident':
          if (msg.data) {
             cache.incidents.unshift(msg.data);
             if ((msg.data.severity === 'CRITICAL' || msg.data.severity === 'HIGH') && Notification.isSupported()) {
                new Notification({
                  title: `Угроза ${msg.data.severity}: ${msg.data.type}`,
                  body: msg.data.description || 'Обнаружена новая атака',
                  icon: path.join(__dirname, 'static', 'icon.png')
                }).show();
             }
          }
          trimCache();
          break;
        case 'incident_updated':
          if (msg.data) {
            const idx = cache.incidents.findIndex(i => i.id === msg.data.id);
            if (idx !== -1) cache.incidents[idx] = msg.data;
          }
          break;
        case 'metrics': cache.metrics = msg.data; break;
      }
    } catch (err) {
      logger.error('WS parse error', err);
    }
  });

  wsClient.on('close', (code, reason) => {
    logger.warn(`WS closed: ${code}`);
    wsClient = null;
    if (mainWindow) mainWindow.webContents.send('conn-status', 'error', `Отключён (${code})`);
    scheduleReconnect();
  });
  
  wsClient.on('error', (err) => {
    logger.error('WS error: ' + err.message);
    wsClient = null;
    if (mainWindow) mainWindow.webContents.send('conn-status', 'error', 'Ошибка сети');
    scheduleReconnect();
  });
}

function scheduleReconnect() {
  if (reconnectTimer || !serverConfig.host) return;
  const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), MAX_RECONNECT_DELAY);
  reconnectAttempts++;
  logger.info(`Reconnecting in ${delay}ms...`);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectToServer(serverConfig.host, serverConfig.port, serverConfig.token);
  }, delay);
}

setInterval(() => {
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify({ event: 'ping' }));
  }
}, 30000);

// --- IPC Handlers ---
ipcMain.handle('get-app-version', () => app.getVersion());

ipcMain.handle('connect-server', async (event, { host, port, username, password }) => {
  try {
    const url = `http://${host}:${port}/api/auth/login`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(5000)
    });
    const data = await res.json();
    if (data.success) {
      store.set('serverConfig', { host, port }); // Store config
      connectToServer(host, port, data.token);
      setTimeout(() => {
        if (mainWindow) mainWindow.webContents.send('initial-cache', cache);
      }, 500);
      return { success: true, base: `http://${host}:${port}` };
    }
    return { success: false, error: data.error || 'Login failed' };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

ipcMain.handle('disconnect-server', () => {
  if (wsClient) { wsClient.terminate(); wsClient = null; }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  serverConfig = { host: '', port: 8080, url: '', token: '' };
  return true;
});

ipcMain.handle('send-api-request', async (event, path, method, body) => {
  if (!serverConfig.url) return { error: 'Not connected' };
  try {
    const res = await fetch(`${serverConfig.url}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined
    });
    return await res.json();
  } catch (err) {
    return { error: err.message };
  }
});

ipcMain.on('send-ws-message', (event, msg) => {
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify(msg));
  }
});

// --- App Lifecycle ---
function createTray() {
  tray = new Tray(path.join(__dirname, 'static', 'logo.ico')); // Needs a proper icon
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Показать MISTRAL', click: () => { if(mainWindow) mainWindow.show(); } },
    { type: 'separator' },
    { label: 'Выход', click: () => { app.isQuitting = true; app.quit(); } }
  ]);
  tray.setToolTip('MISTRAL Defense');
  tray.setContextMenu(contextMenu);
  tray.on('click', () => { if(mainWindow) mainWindow.show(); });
}

app.whenReady().then(() => {
  createSplash();
  createTray();
  setTimeout(createMainWindow, 1000);
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
