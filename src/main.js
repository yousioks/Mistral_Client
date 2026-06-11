const { app, BrowserWindow, ipcMain, Notification, Tray, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const WebSocket = require('ws');
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
let notificationsEnabled = true;
import('electron-store').then((module) => {
  const Store = module.default;
  store = new Store();
  notificationsEnabled = store.get('notificationsEnabled', true);
}).catch(err => console.error("Failed to load electron-store", err));

// ═══════════════════════════════════════════════════════════════════════════
//  MISTRAL Defense — Electron Desktop Application (IPC mode)
// ═══════════════════════════════════════════════════════════════════════════

let mainWindow;
let splashWindow;
let tray = null;
let isAppQuitting = false; // prevents notifications during shutdown

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
let userDisconnected = false;
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
  splashWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <style>
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
      <div class="logo" style="display:flex; justify-content:center; align-items:center;"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#e50914" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
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
    icon: path.join(__dirname, 'static', 'totem.ico'),
    backgroundColor: '#080808', show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: false // To allow loading local resources directly via file://
    }
  });

  // Защита от захвата экрана и скриншотов (для Enterprise)
  mainWindow.setContentProtection(false);

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
  userDisconnected = false;
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
             const typeLower = (msg.data.type || "").toLowerCase();
             const descLower = (msg.data.description || "").toLowerCase();
             const isDdos = typeLower.includes("ddos") || typeLower.includes("flood") || descLower.includes("ddos") || descLower.includes("flood");
             if ((msg.data.severity === 'CRITICAL' || msg.data.severity === 'HIGH') && !isDdos && Notification.isSupported() && !isAppQuitting && notificationsEnabled) {
                 let attackerIp = msg.data.ip;
                 if (!attackerIp && msg.data.details) {
                     const det = msg.data.details;
                     if (det.sourceIp) attackerIp = det.sourceIp;
                     else if (det.ip) attackerIp = det.ip;
                     else if (det.ddos && det.ddos.top_ips && Array.isArray(det.ddos.top_ips) && det.ddos.top_ips.length > 0) {
                         attackerIp = det.ddos.top_ips[0].ip;
                     }
                 }
                 if (!attackerIp) {
                     const desc = msg.data.description || "";
                     const ipMatch = desc.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
                     if (ipMatch) attackerIp = ipMatch[0];
                 }
                 if (!attackerIp) attackerIp = 'Локальная система';
                 const notification = new Notification({
                   title: `Угроза ${msg.data.severity}: ${msg.data.type}`,
                   body: `IP: ${attackerIp}\n${msg.data.description || 'Обнаружена новая атака'}`,
                   icon: path.join(__dirname, 'static', 'totem.ico')
                 });
                 notification.on('click', () => {
                     if (mainWindow) {
                         if (mainWindow.isMinimized()) mainWindow.restore();
                         mainWindow.focus();
                         mainWindow.webContents.send('notification-click-ip', attackerIp);
                         mainWindow.webContents.send('notification-click-incident', msg.data.id);
                     }
                 });
                 notification.show();
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
    if (mainWindow) {
      if (userDisconnected) {
        mainWindow.webContents.send('conn-status', 'error', 'Отключён пользователем');
      } else {
        mainWindow.webContents.send('conn-status', 'error', `Отключён (${code})`);
      }
    }
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
  if (userDisconnected) return;
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

ipcMain.handle('set-notifications-enabled', (event, enabled) => {
  notificationsEnabled = !!enabled;
  if (store) {
    store.set('notificationsEnabled', notificationsEnabled);
  }
  return true;
});

ipcMain.handle('get-notifications-enabled', () => {
  return notificationsEnabled;
});

ipcMain.handle('connect-server', async (event, { host, port, username, password }) => {
  try {
    const url = `http://${host}:${port}/api/auth/login`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(5000)
    });
    const contentType = res.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      const text = await res.text();
      return { success: false, error: `Сервер вернул некорректный формат ответа (HTTP ${res.status}): ${text.substring(0, 100)}` };
    }
    const data = await res.json();
    if (data.success) {
      store.set('serverConfig', { host, port }); // Store config
      connectToServer(host, port, data.token);
      setTimeout(() => {
        if (mainWindow) mainWindow.webContents.send('initial-cache', cache);
      }, 500);
      return { success: true, base: `http://${host}:${port}`, token: data.token };
    }
    return { success: false, error: data.error || 'Login failed' };
  } catch (err) {
    let errorMsg = err.message;
    if (err.name === 'AbortError' || err.name === 'TimeoutError') {
      errorMsg = 'Превышено время ожидания ответа от сервера (5 сек)';
    } else if (err.cause) {
      const cause = err.cause;
      if (cause.code === 'ECONNREFUSED') {
        errorMsg = `Соединение отклонено сервером (ECONNREFUSED). Проверьте, запущен ли сервер на порту ${port}`;
      } else if (cause.code === 'ENOTFOUND') {
        errorMsg = `Адрес сервера не найден (ENOTFOUND). Проверьте правильность ввода хоста "${host}"`;
      } else if (cause.code === 'ETIMEDOUT') {
        errorMsg = 'Таймаут сетевого соединения (ETIMEDOUT)';
      } else {
        errorMsg += ` (${cause.message || cause.code || String(cause)})`;
      }
    }
    return { success: false, error: errorMsg };
  }
});

ipcMain.handle('disconnect-server', () => {
  userDisconnected = true;
  if (wsClient) {
    try { wsClient.terminate(); } catch(_) {}
    wsClient = null;
  }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  serverConfig = { host: '', port: 8080, url: '', token: '' };
  return true;
});

ipcMain.handle('disconnect-ws', () => {
  userDisconnected = true;
  if (wsClient) {
    try { wsClient.terminate(); } catch(_) {}
    wsClient = null;
  }
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (mainWindow) mainWindow.webContents.send('conn-status', 'error', 'Отключён пользователем');
  return true;
});

ipcMain.handle('reconnect-server', () => {
  if (serverConfig.host) {
    userDisconnected = false;
    connectToServer(serverConfig.host, serverConfig.port, serverConfig.token);
    return { success: true };
  }
  return { success: false, error: 'Конфигурация подключения отсутствует' };
});

ipcMain.handle('send-api-request', async (event, path, method, body) => {
  if (!serverConfig.url) return { error: 'Not connected' };
  try {
    const res = await fetch(`${serverConfig.url}${path}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Auth-Token': serverConfig.token,
        'X-API-Key': serverConfig.token
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const contentType = res.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await res.json();
    } else {
      const text = await res.text();
      return { error: `Server returned non-JSON response (${res.status}): ${text.substring(0, 100)}` };
    }
  } catch (err) {
    let errorMsg = err.message;
    if (err.cause) {
      errorMsg += ` (${err.cause.message || err.cause.code || String(err.cause)})`;
    }
    return { error: errorMsg };
  }
});

ipcMain.on('send-ws-message', (event, msg) => {
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify(msg));
  }
});

// --- App Lifecycle ---
function createTray() {
  tray = new Tray(path.join(__dirname, 'static', 'totem.ico')); // Needs a proper icon
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

app.on('before-quit', () => {
  isAppQuitting = true;
  // Gracefully close WebSocket so no more messages arrive
  if (wsClient) {
    try { wsClient.terminate(); } catch(_) {}
    wsClient = null;
  }
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
});

app.on('window-all-closed', () => {
  isAppQuitting = true;
  if (process.platform !== 'darwin') app.quit();
});
