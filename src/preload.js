const { contextBridge, ipcRenderer } = require('electron');

// ═══════════════════════════════════════════════════════════════════════════
//  Preload — безопасный мост между main и renderer процессами Electron
// ═══════════════════════════════════════════════════════════════════════════

contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  platform: process.platform,
  
  // IPC for Mistral Backend communication
  connectServer: (credentials) => ipcRenderer.invoke('connect-server', credentials),
  disconnectServer: () => ipcRenderer.invoke('disconnect-server'),
  disconnectWs: () => ipcRenderer.invoke('disconnect-ws'),
  reconnectServer: () => ipcRenderer.invoke('reconnect-server'),
  sendApiRequest: (path, method, body) => ipcRenderer.invoke('send-api-request', path, method, body),
  sendWsMessage: (msg) => ipcRenderer.send('send-ws-message', msg),
  
  // Event listeners
  onWsMessage: (callback) => ipcRenderer.on('ws-message', (_event, msg) => callback(msg)),
  onConnStatus: (callback) => ipcRenderer.on('conn-status', (_event, state, label) => callback(state, label)),
  onInitialCache: (callback) => ipcRenderer.on('initial-cache', (_event, cache) => callback(cache)),
  onNotificationClickIp: (callback) => ipcRenderer.on('notification-click-ip', (_event, ip) => callback(ip)),
});
