// Entitlements ala bot CV, disesuaikan untuk jasebq (kontrol akses Trial/Pro).

const store = require('./accessStore');

const ADMIN_IDS = String(process.env.ADMIN_IDS || '')
  .split(',')
  .map(s => Number(s.trim()))
  .filter(n => Number.isFinite(n));

function init() {
  store.init();
}

function ensureUserFromCtx(ctx) {
  const from = ctx.from || {};
  return store.upsertUser({
    id: from.id,
    username: from.username,
    first_name: from.first_name,
    last_name: from.last_name,
  });
}

function getUser(userId) {
  return store.getUser(userId);
}

function isAdmin(userId) {
  if (ADMIN_IDS.includes(Number(userId))) return true;
  const u = store.getUser(userId);
  return !!u && u.role === 'admin';
}

function isTrialActive(u) {
  if (!u) return false;
  if (u.role !== 'trial') return false;
  if (!u.trial_expires_at) return false;
  return Date.now() <= Number(u.trial_expires_at);
}

function isProActive(u) {
  if (!u) return false;
  if (u.role !== 'pro') return false;
  if (u.pro_expires_at == null) return true; // null = lifetime
  return Date.now() <= Number(u.pro_expires_at);
}

function isAllowed(userId) {
  const id = Number(userId);
  if (isAdmin(id)) return true;
  const u = store.getUser(id);
  if (!u) return false;
  if (u.status === 'blocked') return false;
  if (u.role === 'allowed') return true;
  if (isTrialActive(u)) return true;
  if (isProActive(u)) return true;
  return false;
}

// Pastikan trial hanya sekali
function canStartTrial(userId) {
  const u = store.getUser(userId);
  if (!u) return true;
  if (u.trial_used) return false;
  // juga blokir bila saat ini masih trial/pro aktif
  if (isTrialActive(u) || isProActive(u)) return false;
  return true;
}

// Trial default 2 jam
function startTrialHours(userId, hours = 2) {
  const u = store.getUser(userId) || store.upsertUser({ id: userId });
  // jika sudah pernah trial -> tolak
  if (u.trial_used) {
    return { ok: false, reason: 'trial_used', user: u };
  }
  const now = Date.now();
  const expires = now + Number(hours) * 60 * 60 * 1000;
  store.setFields(userId, { trial_expires_at: expires, trial_used: true, trial_started_at: now });
  store.setRole(userId, 'trial');
  const nu = store.getUser(userId);
  return { ok: true, expires_at: expires, user: nu };
}

function allowUser(userId) {
  const u = store.getUser(userId) || store.upsertUser({ id: userId });
  if (!u) return null;
  return store.setRole(userId, 'allowed');
}

function blockUser(userId) {
  const u = store.getUser(userId) || store.upsertUser({ id: userId });
  if (!u) return null;
  store.setStatus(userId, 'blocked');
  return store.setRole(userId, 'blocked');
}

function grantPro(userId, days = 31) {
  const u = store.getUser(userId) || store.upsertUser({ id: userId });
  const now = Date.now();
  const expires = days && Number.isFinite(Number(days))
    ? now + Number(days) * 24 * 60 * 60 * 1000
    : null; // null = lifetime
  store.setFields(userId, { pro_expires_at: expires });
  return store.setRole(userId, 'pro');
}

function revokePro(userId) {
  store.setFields(userId, { pro_expires_at: null });
  return store.setRole(userId, 'allowed');
}

module.exports = {
  init,
  ensureUserFromCtx,
  getUser,
  isAdmin,
  isAllowed,
  isTrialActive,
  isProActive,
  canStartTrial,
  startTrialHours,
  allowUser,
  blockUser,
  grantPro,
  revokePro,
};
