const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { startClientServer } = require('./client-server.js');

// ═══════════════════════════════════════════════════════════════════════════
//  MISTRAL Defense — Electron Desktop Application
//  Entry point: starts client-server.js BEFORE loading the window
// ═══════════════════════════════════════════════════════════════════════════

let mainWindow;
let splashWindow;

function createSplash() {
  splashWindow = new BrowserWindow({
    width: 500,
    height: 320,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    resizable: false,
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
      .subtitle{font-size:11px;color:#666;letter-spacing:4px;text-transform:uppercase;margin-bottom:24px}
      .loader{width:200px;height:2px;background:#2a2a2a;border-radius:1px;overflow:hidden}
      .loader-fill{height:100%;width:0%;background:#e50914;animation:load 2s ease forwards}
      @keyframes load{to{width:100%}}
      .status{margin-top:16px;font-size:11px;color:#999}
    </style></head>
    <body>
      <div class="logo">⚔️</div>
      <div class="title">MIST<span>RAL</span></div>
      <div class="subtitle">Defense Command Center</div>
      <div class="loader"><div class="loader-fill"></div></div>
      <div class="status">Инициализация системы...</div>
    </body>
    </html>
  `)}`);

  splashWindow.center();
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 900,
    minWidth: 1200,
    minHeight: 700,
    title: 'MISTRAL Defense Command Center',
    icon: path.join(__dirname, 'static', 'icon.png'),
    backgroundColor: '#080808',
    show: false,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
    },
  });

  // Load from local HTTP server (client-server.js serves on localhost:3001)
  mainWindow.loadURL('http://localhost:3001');

  // Open DevTools in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }

  mainWindow.once('ready-to-show', () => {
    if (splashWindow) splashWindow.close();
    mainWindow.show();
    mainWindow.maximize();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  App Lifecycle — start client-server.js first, then open window
// ═══════════════════════════════════════════════════════════════════════════

app.whenReady().then(() => {
  createSplash();

  // Start the embedded Node.js client-server BEFORE opening the window
  startClientServer(() => {
    createMainWindow();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createMainWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// IPC handlers
ipcMain.handle('get-app-version', () => app.getVersion());
