const fs = require('fs');
const path = require('path');
const { sessionsDir } = require('../config/setting');

const statePath = path.join(sessionsDir, 'state.json');

function loadState() {
  try {
    if (!fs.existsSync(statePath)) return { users: {} };
    const raw = fs.readFileSync(statePath, 'utf8');
    const json = JSON.parse(raw);
    if (!json || typeof json !== 'object') return { users: {} };
    return json;
  } catch (e) {
    console.error('[persist] loadState error:', e.message);
    return { users: {} };
  }
}

function slimEntities(entities) {
  if (!Array.isArray(entities)) return [];
  return entities.map(e => {
    const base = { type: e.type, offset: e.offset, length: e.length };
    if (e.url) base.url = e.url;
    if (e.language) base.language = e.language;
    // Pastikan custom_emoji_id disimpan sebagai string (JSON tidak support BigInt)
    if (e.custom_emoji_id !== undefined && e.custom_emoji_id !== null) base.custom_emoji_id = String(e.custom_emoji_id);
    if (e.user && e.user.id) base.user = { id: e.user.id };
    return base;
  });
}

// Safe stringify: konversi BigInt => string agar JSON.stringify tidak throw.
// Juga men-convert Buffer/Uint8Array ke string jika ada (safety).
function safeStringify(obj, spaces = 2) {
  const seen = new WeakSet();
  return JSON.stringify(obj, function replacer(key, value) {
    // Avoid circular
    if (value && typeof value === 'object') {
      if (seen.has(value)) return;
      seen.add(value);
    }
    if (typeof value === 'bigint') return value.toString();
    if (value instanceof Buffer) return value.toString('base64');
    if (value instanceof Uint8Array) return Buffer.from(value).toString('base64');
    return value;
  }, spaces);
}

function saveState(usersMap) {
  try {
    const out = { users: {} };
    for (const [uid, u] of usersMap.entries()) {
      const rec = { active: u.active || null, accounts: {} };
      for (const [accId, acc] of u.accounts.entries()) {
        const accOut = {
          name: acc.name || '',
          sess: acc.sess || '',
          delay: acc.delay,
          delayMode: acc.delayMode,
          delayAllGroups: acc.delayAllGroups,
          startTime: acc.startTime,
          stopTime: acc.stopTime,
          running: !!acc.running,
            idx: acc.idx || 0,
            msgIdx: acc.msgIdx || 0,
            lastBetweenTick: acc.lastBetweenTick || 0,
            lastAllTick: acc.lastAllTick || 0,
          stats: acc.stats || { sent:0, failed:0, skip:0, start:0 },
          msgs: Array.isArray(acc.msgs)
            ? acc.msgs.map(m => {
                if (typeof m === 'string') return m;
                if (m && typeof m === 'object') {
                  if (m.src !== undefined && m.mid !== undefined) {
                    return {
                      // pastikan src/mid disimpan sebagai string agar JSON valid
                      src: String(m.src),
                      mid: String(m.mid),
                      text: typeof m.text === 'string' ? m.text : (typeof m.preview === 'string' ? m.preview : undefined),
                      entities: slimEntities(m.entities)
                    };
                  }
                  if (typeof m.text === 'string') {
                    return { text: m.text, entities: slimEntities(m.entities) };
                  }
                }
                return m;
              })
            : [],
          targets: acc.targets && typeof acc.targets.size === 'number'
            ? Array.from(acc.targets.values()).map(t => ({
                id: String(t.id),
                title: t.title || String(t.id),
                type: t.type || null,
                // pastikan access_hash disimpan sebagai string atau null
                access_hash: t.access_hash != null ? String(t.access_hash) : null
              }))
            : []
        };
        rec.accounts[accId] = accOut;
      }
      out.users[String(uid)] = rec;
    }

    const tmp = statePath + '.tmp';
    // Gunakan safeStringify sehingga BigInt (atau buffer) tidak menyebabkan error.
    const txt = safeStringify(out, 2);
    fs.writeFileSync(tmp, txt, 'utf8');
    fs.renameSync(tmp, statePath);
  } catch (e) {
    console.error('[persist] saveState error:', e && e.stack ? e.stack : e);
  }
}

module.exports = { loadState, saveState, statePath };
