const { getUser, users } = require('../utils/helper');
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
    await ctx.reply(STR.messages.askPhone);
  };

  bot.hears(STR.menu.createUserbot, handleLogin);
  bot.hears('➕ Tambah Sesi Baru', handleLogin); // fallback lama bila masih ada

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

  bot.callbackQuery(/cancel_(.+)/, async (ctx) => {
    const userId = ctx.match[1];
    const u = getUser(userId);
    for (const [id, acc] of u.accounts) {
      if (acc.uid === userId) {
        acc.cancel(ctx);
        u.accounts.delete(id);
        break;
      }
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
};
