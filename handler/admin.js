const { Keyboard } = require('grammy');
const STR = require('../config/strings');
const ent = require('../entitlements');
const store = require('../accessStore');

function adminMenuKb() {
  return new Keyboard()
    .text(STR.menu.adminListPro).row()
    .text(STR.menu.adminCheckUser).row()
    .text(STR.menu.adminGrantPro).text(STR.menu.adminExtendPro).row()
    .text(STR.menu.adminRevokePro).row()
    .text(STR.menu.adminBlockUser).text(STR.menu.adminAllowUser).row()
    .text(STR.menu.adminBroadcast).row()
    .text(STR.menu.back)
    .resized();
}

module.exports = (bot) => {
  bot.hears(STR.menu.admin, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    await ctx.reply('👑 Admin Panel', { reply_markup: adminMenuKb() });
  });

  // List Pro aktif
  bot.hears(STR.menu.adminListPro, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    const users = store.allUsers();
    const now = Date.now();
    const pro = [];
    for (const id in users) {
      const u = users[id];
      if (u.role === 'pro' && (u.pro_expires_at == null || now <= Number(u.pro_expires_at))) {
        pro.push({ id, until: u.pro_expires_at ? new Date(Number(u.pro_expires_at)).toLocaleString('id-ID', { hour12:false }) : 'lifetime' });
      }
    }
    if (!pro.length) return ctx.reply('Tidak ada PRO aktif.');
    let out = `📜 PRO aktif (${pro.length}):\n`;
    out += pro.slice(0, 100).map((x,i)=>`${i+1}. ${x.id} (${x.until})`).join('\n');
    if (pro.length > 100) out += `\n... dan ${pro.length - 100} lainnya.`;
    await ctx.reply(out);
  });

  // Cek user
  bot.hears(STR.menu.adminCheckUser, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_check' };
    await ctx.reply('Kirim UserID yang ingin dicek:');
  });

  // Grant Pro
  bot.hears(STR.menu.adminGrantPro, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_grant' };
    await ctx.reply('Format: userId hari\nContoh: 123456789 31');
  });

  // Perpanjang Pro
  bot.hears(STR.menu.adminExtendPro, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_extend' };
    await ctx.reply('Format: userId hari_ tambahan\nContoh: 123456789 30');
  });

  // Revoke Pro
  bot.hears(STR.menu.adminRevokePro, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_revoke' };
    await ctx.reply('Kirim UserID yang ingin dicabut PRO-nya:');
  });

  // Block/Allow
  bot.hears(STR.menu.adminBlockUser, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_block' };
    await ctx.reply('Kirim UserID yang ingin diblokir:');
  });

  bot.hears(STR.menu.adminAllowUser, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_allow' };
    await ctx.reply('Kirim UserID yang ingin di-allow:');
  });

  // Broadcast
  bot.hears(STR.menu.adminBroadcast, async (ctx) => {
    if (!ent.isAdmin(ctx.from.id)) return;
    ctx.session = { act: 'admin_broadcast' };
    await ctx.reply('Kirim teks yang akan dibroadcast ke semua user terdaftar (maks 3900 char per bagian).');
  });

  // Input handler untuk admin session
  bot.on('message:text', async (ctx, next) => {
    const s = ctx.session;
    if (!s || !ent.isAdmin(ctx.from.id)) return next();
    const text = ctx.message.text.trim();
    if (!s.act) return next();

    try {
      if (s.act === 'admin_check') {
        const uid = Number(text);
        const u = store.getUser(uid);
        if (!u) return ctx.reply('User tidak ditemukan.');
        const lines = [
          `ID: ${u.id}`,
          `Role: ${u.role}`,
          `Status: ${u.status}`,
          `Trial used: ${u.trial_used ? 'ya' : 'tidak'}`,
          `Trial expires: ${u.trial_expires_at ? new Date(Number(u.trial_expires_at)).toLocaleString('id-ID', {hour12:false}) : '-'}`,
          `Pro expires: ${u.pro_expires_at == null ? 'lifetime' : new Date(Number(u.pro_expires_at)).toLocaleString('id-ID', {hour12:false})}`,
        ];
        await ctx.reply(lines.join('\n'));
      } else if (s.act === 'admin_grant') {
        const [idStr, daysStr] = text.split(/\s+/);
        const uid = Number(idStr); const days = Number(daysStr||31);
        ent.grantPro(uid, days);
        await ctx.reply(`✅ Grant PRO ke ${uid} selama ${days} hari.`);
      } else if (s.act === 'admin_extend') {
        const [idStr, addDaysStr] = text.split(/\s+/);
        const uid = Number(idStr); const add = Number(addDaysStr||30);
        const u = store.getUser(uid) || store.upsertUser({ id: uid });
        const now = Date.now();
        const base = (u.pro_expires_at && Number(u.pro_expires_at) > now) ? Number(u.pro_expires_at) : now;
        const newExp = base + add*24*60*60*1000;
        store.setFields(uid, { pro_expires_at: newExp });
        store.setRole(uid, 'pro');
        await ctx.reply(`♻️ Perpanjang PRO ${uid} +${add} hari (baru exp: ${new Date(newExp).toLocaleString('id-ID',{hour12:false})}).`);
      } else if (s.act === 'admin_revoke') {
        const uid = Number(text);
        ent.revokePro(uid);
        await ctx.reply(`❌ PRO dicabut untuk ${uid}.`);
      } else if (s.act === 'admin_block') {
        const uid = Number(text);
        ent.blockUser(uid);
        await ctx.reply(`🚫 User ${uid} diblokir.`);
      } else if (s.act === 'admin_allow') {
        const uid = Number(text);
        ent.allowUser(uid);
        await ctx.reply(`✅ User ${uid} di-allow.`);
      } else if (s.act === 'admin_broadcast') {
        const users = store.allUsers();
        let sent = 0, fail = 0;
        for (const id in users) {
          try {
            await ctx.api.sendMessage(Number(id), text);
            sent++;
          } catch { fail++; }
        }
        await ctx.reply(`📩 Broadcast selesai. Terkirim: ${sent}, gagal: ${fail}.`);
      }
    } catch (e) {
      await ctx.reply('❌ Error: ' + (e.message || e));
    } finally {
      ctx.session = null;
    }
  });
};
