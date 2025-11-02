const fs = require('fs');
const path = require('path');
const { getUser, getAcc, users } = require('../utils/helper');
const { mainMenu, allCommandNames, settingMenu } = require('../utils/menu');
const { saveState } = require('../utils/persist');
const { parseToken } = require('../utils/token');
const STR = require('../config/strings');
const { sessionsDir } = require('../config/setting');

const TIME_REGEX = /^([01]?\d|2[0-3]):([0-5]\d)$/;
const DEBUG = process.env.DEBUG_BROADCAST === '1';
function dbg(...a){ if (DEBUG) console.log('[ADDMSG]', ...a); }

// safe stringify replacer to avoid crash on BigInt
function safeStringify(obj) {
  const seen = new WeakSet();
  return JSON.stringify(obj, function replacer(k, v) {
    if (typeof v === 'bigint') return v.toString();
    if (v && typeof v === 'object') {
      if (seen.has(v)) return;
      seen.add(v);
    }
    return v;
  }, 2);
}

// write debug file for a specific user
function writeDebugDump(uid, label, data) {
  try {
    if (!sessionsDir) return;
    const name = `debug_msg_${uid}_${label}_${Date.now()}.json`;
    const p = path.join(sessionsDir, name);
    fs.writeFileSync(p, safeStringify(data), 'utf8');
    if (DEBUG) console.log(`[DEBUG DUMP] wrote ${p}`);
  } catch (e) {
    console.error('[DEBUG DUMP WRITE ERROR]', e && e.stack ? e.stack : e);
  }
}

/**
 * Normalisasi nomor telepon:
 * - Hapus spasi / tanda kurung / dash
 * - Jika mulai dengan 0 -> konversi ke +62 (Indonesia)
 * - Pastikan punya leading + dan 8-15 digit
 */
function normalizePhone(raw) {
  if (!raw) return '';
  let s = String(raw).trim();
  // hapus semua karakter kecuali digit dan plus
  s = s.replace(/[^\d+]/g, '');
  if (/^0\d+/.test(s)) {
    s = '+62' + s.slice(1);
  }
  return s;
}

module.exports = async (ctx) => {
  const text = ctx.message?.text?.trim?.();
  if (allCommandNames && allCommandNames.has(text)) return;

  const u = getUser(ctx.from.id);
  const a = getAcc(ctx.from.id);
  const targetAcc = u.accounts.get(ctx.session?.id) || a;
  if (targetAcc?.handleText(text, ctx)) return;

  if (!a && ctx.session?.act && ctx.session.act !== 'phone') {
    ctx.session = null;
    return ctx.reply('❌ Aksi dibatalkan. Login dulu.');
  }

  const actions = {
    phone: async () => {
      const phoneRaw = String(text || '');
      const phone = normalizePhone(phoneRaw);
      if (!/^\+\d{8,15}$/.test(phone)) {
        return ctx.reply(STR.messages.invalidPhone + '\nContoh: +6281234567890 (atau 081234567890 -> +6281234567890)');
      }

      const acc = u.accounts.get(ctx.session.id);
      if (!acc) {
        console.error('[INPUT] session phone but acc not found', { uid: ctx.from.id, session: ctx.session });
        ctx.session = null;
        return ctx.reply('❌ Sesi login tidak ditemukan, ulangi "Buat Userbot".');
      }

      u.active = ctx.session.id;

      try {
        acc.login(ctx, phone);
        await ctx.reply('📨 Kode OTP akan dikirim ke Telegram Anda. Balas di sini.');
      } catch (e) {
        console.error('[input] acc.login error:', e && e.stack ? e.stack : e);
        await ctx.reply('❌ Gagal memulai login: ' + (e.message || String(e)));
        ctx.session = null;
      }
    },

    addmsg: async () => {
      if (!a) return;
      const m = ctx.message;

      // --- DEBUG: dump raw message to file so we can inspect Premium-specific fields ---
      try {
        writeDebugDump(ctx.from.id, 'addmsg', m);
      } catch (e) {
        console.error('[addmsg debug dump error]', e);
      }
      // -----------------------------------------------------------------------------------

      try {
        const raw = (typeof m.text === 'string' ? m.text : (typeof m.caption === 'string' ? m.caption : '') );
        const entities = Array.isArray(m.entities) ? m.entities : (Array.isArray(m.caption_entities) ? m.caption_entities : []);
        dbg('SIMPAN', { length: raw.length, entities: entities.length });

        const forwardMid = m.forward_from_message_id;
        const forwardFromChat = m.forward_from_chat;
        const forwardFromUser = m.forward_from;

        if (forwardMid !== undefined && forwardMid !== null && (forwardFromChat || forwardFromUser)) {
          const srcId = forwardFromChat ? forwardFromChat.id : (forwardFromUser ? forwardFromUser.id : null);
          if (srcId !== null && srcId !== undefined) {
            a.msgs.push({ src: String(srcId), mid: String(forwardMid), text: raw, entities });
            await ctx.reply(STR.messages.messageForwardSaved);
          } else {
            a.msgs.push({ text: raw, entities });
            await ctx.reply(STR.messages.messageSaved);
          }
        } else if (raw && raw.trim().length) {
          a.msgs.push({ text: raw, entities });
          await ctx.reply(STR.messages.messageSaved);
        } else {
          a.msgs.push('[Unsupported media]');
          await ctx.reply(STR.messages.messageUnsupported);
        }
        saveState(users);
      } catch (e) {
        console.error('[addmsg] exception:', e && e.stack ? e.stack : e);
        await ctx.reply('❌ Gagal menyimpan: ' + (e.message || e));
      }
      const menu = mainMenu(ctx);
      await ctx.reply(menu.text, { reply_markup: menu.reply_markup, parse_mode: menu.parse_mode });
    },

    addtgt: async () => {
      if (!a) return;
      const m = ctx.message;

      // --- DEBUG: dump message when trying to add targets ---
      try {
        writeDebugDump(ctx.from.id, 'addtgt', m);
      } catch (e) {
        console.error('[addtgt debug dump error]', e);
      }

      try {
        const result = await a.addTargets(text);
        saveState(users);

        let msg = `📍 *Ringkasan Penambahan Target:*\n`;
        msg += `• Berhasil ditambah: *${result.added}*\n`;
        msg += `• Duplikat: ${result.duplicates.length}\n`;
        msg += `• Join baru: ${result.joined_new.length}\n`;
        msg += `• Gagal join: ${result.join_failed.length}\n`;
        msg += `• Tidak valid: ${result.invalid.length}\n`;
        msg += `• LIMIT: ${result.flood_wait.length}\n`;

        msg += `\n${STR.messages.summaryFailHeader}\n`;
        if (result.flood_wait.length) msg += STR.messages.summaryLimit(result.flood_wait.length) + '\n';
        if (result.invalid.length) msg += STR.messages.summaryInvalid(result.invalid.length) + '\n';
        if (result.duplicates.length) msg += STR.messages.summaryDuplicate(result.duplicates.length) + '\n';
        if (result.join_failed.length) msg += STR.messages.summaryJoinFail(result.join_failed.length) + '\n';

        if (result.flood_wait.length) {
          const maxWait = Math.max(...result.flood_wait.map(f=>f.seconds));
          msg += `\nTunggu ± ${maxWait}s sebelum verifikasi ulang.`;
        }

        await ctx.reply(msg, { parse_mode: 'Markdown' });
      } catch (e) {
        console.error('[addtgt] exception:', e && e.stack ? e.stack : e);
        await ctx.reply(STR.errors.addTargetFailed(e.message || e));
      }
    },

    setdelay: async () => {
      const v = +text;
      if (v >= 1 && v <= 3600) {
        a.delay = v; a.delayMode = 'antar';
        saveState(users);
        await ctx.reply(`✅ Jeda Antar Grup: ${v}s`, { reply_markup: settingMenu(a) });
      } else await ctx.reply(STR.errors.invalidDelay);
    },

    setdelayall: async () => {
      const v = +text;
      if (v >= 1 && v <= 1440) {
        a.delayAllGroups = v; a.delayMode = 'semua';
        saveState(users);
        await ctx.reply(`✅ Jeda Semua Grup: ${v}m`, { reply_markup: settingMenu(a) });
      } else await ctx.reply(STR.errors.invalidDelayAll);
    },

    setstart: async () => {
      if (text === '-' || text.toLowerCase() === 'x') {
        a.startTime = null; a.scheduleStartStop?.(); saveState(users);
        return ctx.reply(STR.messages.startTimeCleared, { reply_markup: settingMenu(a) });
      }
      if (!TIME_REGEX.test(text)) return ctx.reply(STR.errors.invalidTime);
      a.startTime = text; a.scheduleStartStop?.(); saveState(users);
      await ctx.reply(STR.messages.startTimeSet(text), { reply_markup: settingMenu(a) });
      await ctx.reply(STR.messages.autoStartInfo(text));
    },

    setstop: async () => {
      if (text === '-' || text.toLowerCase() === 'x') {
        a.stopTime = null; a.stopTimestamp=null; saveState(users);
        return ctx.reply(STR.messages.stopTimeCleared, { reply_markup: settingMenu(a) });
      }
      if (!TIME_REGEX.test(text)) return ctx.reply(STR.errors.invalidTime);
      a.stopTime = text; saveState(users);
      await ctx.reply(STR.messages.stopTimeSet(text), { reply_markup: settingMenu(a) });
    },

    input_token: async () => {
      try {
        const data = parseToken(text);
        for (const m of data.msgs || []) {
          if (typeof m === 'string') a.msgs.push({ text: m, entities: [] });
          else if (m && typeof m === 'object') {
            if (m.html) a.msgs.push({ text: m.text, entities: [], html: true });
            else if (typeof m.text === 'string')
              a.msgs.push({ text: m.text, entities: Array.isArray(m.entities)?m.entities:[] });
          }
        }
        if (!a.targets) a.targets = new Map();
        let addedT=0, dupT=0;
        for (const t of data.targets || []) {
          const idStr=String(t.id);
          if (!a.targets.has(idStr)) {
            a.targets.set(idStr,{
              id:t.id, title:t.title||idStr, type:t.type||null,
              access_hash:t.access_hash||null, entity:null
            });
            addedT++;
          } else dupT++;
        }
        saveState(users);

        const ver = await a.verifyTargets({ stopOnFlood:true });
        saveState(users);

        let msg = `${STR.messages.importDone}\n`;
        msg += `• Pesan: ${data.msgs?.length || 0}\n`;
        msg += `• Target baru: ${addedT} (duplikat: ${dupT})\n`;
        msg += `• Total target: ${a.targets.size}\n\n`;
        msg += '🔍 Verifikasi:\n';
        msg += `• Ready/Already: ${ver.already}\n`;
        msg += `• Join baru: ${ver.joined_new}\n`;
        msg += `• Gagal: ${ver.failed.length}\n`;
        if (ver.flood_wait) msg += `• LIMIT: ~${ver.flood_wait}s\n`;

        msg += `\n${STR.messages.summaryFailHeader}\n`;
        if (ver.flood_wait) msg += STR.messages.summaryLimit(1)+'\n';
        if (ver.failed.length) msg += STR.messages.summaryJoinFail(ver.failed.length)+'\n';

        if (ver.flood_wait) msg += `\nTekan ${STR.menu.verifyTarget} setelah menunggu.`; 

        await ctx.reply(msg, { parse_mode: 'Markdown' });
      } catch (e) {
        await ctx.reply(STR.errors.importFailed(e.message || e));
      }
    }
  };

  if (ctx.session?.act && actions[ctx.session.act]) {
    await actions[ctx.session.act]();
    if (ctx.session?.act !== 'phone') ctx.session = null;
  }
};
