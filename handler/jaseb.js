const { InlineKeyboard } = require('grammy');
const { getAcc, getUser } = require('../utils/helper');
const { mainMenu, settingMenu, jedaMenu } = require('../utils/menu');
const STR = require('../config/strings');

function formatHHMM(hhmm) {
  if (!hhmm || !/^([01]?\d|2[0-3]):([0-5]\d)$/.test(hhmm)) return '00:00';
  const [h, m] = hhmm.split(':');
  return `${h.padStart(2,'0')}:${m.padStart(2,'0')}`;
}

function buildStatsText(ctx, a) {
  const u = getUser(ctx.from.id);
  const userId = ctx.from.id;
  const delayStr = a.delayMode === 'semua'
    ? `${a.delayAllGroups} Menit`
    : `${a.delay} Detik`;
  const startStr = formatHHMM(a.startTime);
  const stopStr  = formatHHMM(a.stopTime);
  const grupCount = a.targets.size;
  const msgCount  = a.msgs.length;
  const akunCount = u.accounts.size;
  const gagal = a.stats.failed || 0;
  const sukses = a.stats.sent || 0;
  return `🏷 UserID : ${userId}

⏰ *Timer*  : (Start - ${startStr}) (Stop - ${stopStr})
⏳ *Delay*  : ${delayStr}
🎄 *Grup*   : ${grupCount}
🧩 *List*   : ${msgCount}
👥 *Akun*   : ${akunCount}

📮 *Pesan Gagal*     : ${gagal}
📚 *Pesan Berhasil*  : ${sukses}

_ada pertanyaan? bisa tanya @JaeHype_`;
}

module.exports = (bot) => {
  // Jalankan / Hentikan
  bot.hears([STR.menu.run, STR.menu.stop], async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a?.authed) return ctx.reply(STR.messages.needLogin);

    if (ctx.message.text === STR.menu.run) {
      if (!a.msgs.length) return ctx.reply(STR.messages.noMessages);
      if (!a.all && !a.targets.size) return ctx.reply(STR.messages.noTargets);

      const res = await a.start(bot.api, { manual: true });
      if (!res.ok) {
        let info = '';
        switch (res.reason) {
          case 'already_running': info = 'Sudah berjalan.'; break;
          case 'scheduled_pending': info = 'Menunggu jadwal (startTime).'; break;
          case 'no_messages': info = 'Belum ada pesan.'; break;
          case 'no_targets': info = 'Belum ada target.'; break;
          case 'client_not_connected': info = 'Client belum siap.'; break;
          default: info = res.reason;
        }
        await ctx.reply('⚠️ Tidak bisa mulai: ' + info);
      } else {
        await ctx.reply(STR.messages.started);
      }
    } else {
      a.stop(true);
      await ctx.reply(STR.messages.stopped);
    }

    const menu = mainMenu(ctx);
    await ctx.reply(menu.text, { reply_markup: menu.reply_markup, parse_mode: menu.parse_mode });
  });

  // Settings
  bot.hears(STR.menu.settings, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    await ctx.reply(
      `Silakan pilih menu *Jeda*, *Timer Mulai*, atau *Timer Stop*.\n⚠️ Tips: Pakai jeda panjang biar aman.\n\n_Butuh bantuan?_ 👉 @JaeHype`,
      { parse_mode: 'Markdown', reply_markup: settingMenu(a) }
    );
  });

  bot.hears(/^(🔗 Jeda Antar Grup|⛓️ Jeda Per Semua Grup): .+/, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    if (ctx.message.text.startsWith('🔗 Jeda Antar Grup')) {
      ctx.session = { act: 'setdelay' };
      await ctx.reply(`*Jeda antar grup: 1–3600 detik*\n👉 _Hindari jeda terlalu pendek_.`, { parse_mode: 'Markdown' });
    } else {
      ctx.session = { act: 'setdelayall' };
      await ctx.reply(`*Masukkan jeda (menit): 1–1440*\n👉 _Rekomendasi ≥20 menit untuk sesi panjang_.`, { parse_mode: 'Markdown' });
    }
  });

  bot.hears(STR.menu.changeDelayMode, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    await ctx.reply(
`*Silakan pilih mode jeda* ⏳

*Jeda antar grup* = jeda antar pengiriman (detik).
*Jeda per semua grup* = jeda antar satu putaran ke semua target (menit).

⚠️ *Jeda terlalu pendek berisiko FLOOD.*`,
      { parse_mode: 'Markdown', reply_markup: jedaMenu() }
    );
  });

  bot.hears('🔗 Jeda Antar Grup', async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    a.delayMode = 'antar';
    await ctx.reply('✅ Mode diubah ke Jeda Antar Grup.', { reply_markup: settingMenu(a) });
  });

  bot.hears('⛓️ Jeda Per Semua Grup', async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    a.delayMode = 'semua';
    await ctx.reply('✅ Mode diubah ke Jeda Semua Grup.', { reply_markup: settingMenu(a) });
  });

  bot.hears(/🕒 Waktu Mulai:.*$/, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    ctx.session = { act: 'setstart' };
    await ctx.reply('Kirim waktu mulai (contoh: 14:30) atau "-" untuk hapus.', { parse_mode: 'Markdown' });
  });

  bot.hears(/🕝 Waktu Stop:.*$/, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    ctx.session = { act: 'setstop' };
    await ctx.reply('Kirim waktu stop (contoh: 18:45) atau "-" untuk hapus.', { parse_mode: 'Markdown' });
  });

  // Statistik
  bot.hears(STR.menu.stats, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    const text = buildStatsText(ctx, a);
    await ctx.reply(text, {
      parse_mode: 'Markdown',
      reply_markup: new InlineKeyboard()
        .text('🔄 Refresh', 'STAT')
        .text('Tutup', 'delete_this')
    });
  });

  bot.callbackQuery('STAT', async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.answerCallbackQuery('❌ Login dulu', { show_alert: true });
    const text = buildStatsText(ctx, a);
    try {
      await ctx.editMessageText(text, {
        parse_mode: 'Markdown',
        reply_markup: new InlineKeyboard()
          .text('🔄 Refresh', 'STAT')
          .text('Tutup', 'delete_this')
      });
    } catch {}
    await ctx.answerCallbackQuery();
  });

  bot.callbackQuery('delete_this', async (ctx) => {
    try { await ctx.deleteMessage(); } catch {}
    await ctx.answerCallbackQuery();
  });
};
