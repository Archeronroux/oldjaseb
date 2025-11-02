const { Keyboard } = require('grammy');
const { getUser, users, getAcc } = require('../utils/helper');
const { mainMenu, helpCommand } = require('../utils/menu');
const { saveState } = require('../utils/persist');
const Akun = require('../model/Akun');
const STR = require('../config/strings');

module.exports = (bot) => {
  const handleLogin = async (ctx) => {
    const u = getUser(ctx.from.id);
    const id = Date.now().toString().slice(-6);
    const acc = new Akun(ctx.from.id);
    acc.id = id;
    u.accounts.set(id, acc);
    ctx.session = { act: 'phone', id };

    const kb = new Keyboard()
      .requestContact('📂 Kirim Kontak 📂').row()
      .text(STR.menu.back)
      .resized();

    await ctx.reply(STR.messages.askPhone, { reply_markup: kb });
  };

  bot.hears(STR.menu.createUserbot, handleLogin);
  bot.hears('➕ Tambah Sesi Baru', handleLogin);

  bot.hears('👥 Akun', async (ctx) => {
    const u = getUser(ctx.from.id);
    if (!u.accounts.size) {
      return ctx.reply(`Belum ada sesi. Tekan "${STR.menu.createUserbot}" untuk membuat.`);
    }
    let text = '👥 Daftar Sesi:\n';
    for (const [id, acc] of u.accounts) {
      text += `• ${acc.name || id} ${u.active === id ? '(aktif)' : ''}\n`;
    }
    text += `\nGunakan menu ${STR.menu.tokenMenu} untuk backup/restore data.`;
    await ctx.reply(text);
  });

  bot.hears(STR.menu.help, helpCommand);

  bot.hears(/^(🟢|🔴) Aktifkan: (.+?)( ✅)?$/, async (ctx) => {
    await ctx.reply(`Fitur ganti sesi dinonaktifkan. Gunakan ${STR.menu.tokenMenu} untuk backup/restore data.`);
  });

  // Cancel flow
  bot.callbackQuery(/cancel_(.+)/, async (ctx) => {
    const userId = Number(ctx.match[1]);
    const u = getUser(userId);
    // Hapus akun yang sedang login (active)
    if (u && u.active) {
      const acc = u.accounts.get(u.active);
      try { acc?.cancel?.(ctx); } catch {}
      try { u.accounts.delete(u.active); } catch {}
      u.active = null;
    }
    if (ctx.session?.mid) {
      try { await ctx.api.deleteMessage(userId, ctx.session.mid); } catch {}
    }
    ctx.session = null;
    await ctx.deleteMessage().catch(()=>{});
    const menu = mainMenu(ctx);
    await ctx.reply(STR.messages.loginCancelled, { reply_markup: menu.reply_markup, parse_mode: menu.parse_mode });
    await ctx.answerCallbackQuery('❌ Batal');
    saveState(users);
  });

  // Resend code now (to speed up OTP arrival)
  bot.callbackQuery(/resend_(.+)/, async (ctx) => {
    const userId = Number(ctx.match[1]);
    const acc = getAcc(userId) || (() => {
      const u = getUser(userId);
      return u?.active ? u.accounts.get(u.active) : null;
    })();
    if (!acc) {
      try { await ctx.answerCallbackQuery({ text: 'Sesi tidak ditemukan.', show_alert: true }); } catch {}
      return;
    }
    try {
      await acc.resendCode(ctx);
    } catch (e) {
      try { await ctx.answerCallbackQuery({ text: e.message || 'Resend gagal', show_alert: true }); } catch {}
    }
  });
};
