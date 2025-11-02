require('./config/setting');
const { Bot, session } = require('grammy');
const { startCommand } = require('./utils/menu');

const authHandler = require('./handler/auth');
const pesanHandler = require('./handler/pesan');
const targetHandler = require('./handler/target');
const jasebHandler = require('./handler/jaseb');
const tokenHandler = require('./handler/token');
const inputHandler = require('./handler/input');
const shopHandler = require('./handler/shop');
const adminHandler = require('./handler/admin');

const { loadState, saveState } = require('./utils/persist');
const { getUser, users, setBot } = require('./utils/helper');
const Akun = require('./model/Akun');

const ent = require('./entitlements');
const { entitlementGate } = require('./middleware/entitlementGate');

const bot = new Bot(process.env.BOT_TOKEN);
setBot(bot);
ent.init();

process.on('unhandledRejection', (reason) => console.error('[UNHANDLED_REJECTION]', reason));
process.on('uncaughtException', (err) => console.error('[UNCAUGHT_EXCEPTION]', err));

bot.use(session({ initial: () => ({}) }));

// Pulihkan sesi
(function restoreSessions() {
  const state = loadState();
  for (const uidStr of Object.keys(state.users || {})) {
    const uid = parseInt(uidStr, 10);
    const data = state.users[uidStr];
    const u = getUser(uid);
    u.active = data.active || null;
    for (const accId of Object.keys(data.accounts || {})) {
      const aData = data.accounts[accId] || {};
      const acc = new Akun(uid);
      acc.id = accId;
      acc.name = aData.name || 'User';
      acc.sess = aData.sess || '';
      acc.authed = !!acc.sess;
      if (typeof aData.delay === 'number') acc.delay = aData.delay;
      if (typeof aData.delayMode === 'string') acc.delayMode = aData.delayMode;
      if (typeof aData.delayAllGroups === 'number') acc.delayAllGroups = aData.delayAllGroups;
      if (aData.startTime) acc.startTime = aData.startTime;
      if (aData.stopTime) acc.stopTime = aData.stopTime;
      if (Array.isArray(aData.msgs)) {
        acc.msgs = aData.msgs.map(m => {
          if (typeof m === 'string') return m;
          if (m && typeof m === 'object') {
            return {
              src: m.src,
              mid: m.mid,
              text: typeof m.text === 'string' ? m.text : undefined,
              preview: typeof m.preview === 'string' ? m.preview : undefined,
              entities: Array.isArray(m.entities) ? m.entities : undefined
            };
          }
          return m;
        });
      }
      if (Array.isArray(aData.targets)) {
        acc.targets = new Map();
        for (const t of aData.targets) {
          if (t && (t.id !== undefined)) {
            const idStr = String(t.id);
            acc.targets.set(idStr, {
              id: t.id,
              title: t.title || idStr,
              type: t.type || null,
              access_hash: t.access_hash || null,
              entity: null
            });
          }
        }
      }
      if (aData.stats) acc.stats = aData.stats;
      if (typeof aData.idx === 'number') acc.idx = aData.idx;
      if (typeof aData.msgIdx === 'number') acc.msgIdx = aData.msgIdx;
      acc.running = !!aData.running;
      acc.lastBetweenTick = aData.lastBetweenTick || 0;
      acc.lastAllTick = aData.lastAllTick || 0;
      // Stop broadcast aktif (tanpa hapus data)
      if (acc.running) {
        try { acc.stop(true); } catch {}
        acc.running = false;
      }
      u.accounts.set(accId, acc);
    }
  }

  // DIHAPUS: Jangan kirim pesan perubahan akses saat restart
})();

// Gate entitlement
bot.use(entitlementGate());

// Handlers
authHandler(bot);
pesanHandler(bot);
targetHandler(bot);
jasebHandler(bot);
tokenHandler(bot);
shopHandler(bot);
adminHandler(bot);

const { startCommand: startCmdFromMenu } = require('./utils/menu');
bot.command('start', startCmdFromMenu);
bot.hears('⬅️ Kembali', startCmdFromMenu);

bot.on('message:text', inputHandler);

function persistNow() { saveState(users); }
setInterval(persistNow, 30_000);
process.on('SIGINT', () => { persistNow(); process.exit(0); });
process.on('SIGTERM', () => { persistNow(); process.exit(0); });
process.on('SIGUSR2', () => { persistNow(); });

bot.catch(e => console.error('ERROR UTAMA:', e));

bot.start();
console.log('Jaseb Dimulai (Gate Entitlements + Shop/Trial + Admin Panel)');
