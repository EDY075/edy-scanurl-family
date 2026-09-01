// The managed build environment can deny Win32 account lookup. Capacitor only
// needs the shell field, so provide the minimum non-identifying fallback.
const os = require('node:os');
const originalUserInfo = os.userInfo;
os.userInfo = (...args) => {
  try { return originalUserInfo(...args); }
  catch { return { uid: -1, gid: -1, username: '', homedir: '', shell: process.env.COMSPEC || 'cmd.exe' }; }
};
