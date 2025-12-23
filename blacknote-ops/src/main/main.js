const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const dbManager = require('./database/db-manager');
const cryptoEngine = require('./security/crypto-engine');
const { verifyApplicationIntegrity } = require('./security/integrity');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false // For simplicity in this demo. Production should use preload.js
    },
    title: "BLACKNOTE OPS - LOCKED"
  });

  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));

  // Anti-Analysis: Hide window on blur (Paranoia Mode option)
  // mainWindow.on('blur', () => { if(PARANOIA_MODE) mainWindow.hide(); });
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  dbManager.close();
  if (process.platform !== 'darwin') app.quit();
});

// --- IPC HANDLERS ---

ipcMain.handle('vault:create', async (event, password) => {
  try {
    const isSecure = await verifyApplicationIntegrity();
    if (!isSecure) throw new Error("Security Violation: Application Integrity Check Failed.");

    await dbManager.createVault(password);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('vault:unlock', async (event, password) => {
  try {
    const isSecure = await verifyApplicationIntegrity();
    if (!isSecure) throw new Error("Security Violation: Application Integrity Check Failed.");

    await dbManager.openVault(password);
    mainWindow.setTitle("BLACKNOTE OPS - UNLOCKED");
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('note:save', (event, { id, content }) => {
  try {
    dbManager.saveNote(id, content);
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('note:list', () => {
  try {
    return { success: true, notes: dbManager.getAllNotes() };
  } catch (e) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('app:panic', () => {
    console.log("PANIC MODE ACTIVATED: WIPING MEMORY");
    dbManager.close();
    // In production, we might also delete the key file or overwrite RAM aggressively
    app.quit();
});
