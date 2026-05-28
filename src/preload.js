const { contextBridge, ipcRenderer } = require('electron');

// ═══════════════════════════════════════════════════════════════════════════
//  Preload — безопасный мост между main и renderer процессами Electron
// ═══════════════════════════════════════════════════════════════════════════

contextBridge.exposeInMainWorld('electronAPI', {
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  platform: process.platform,
});
