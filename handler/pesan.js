const { InlineKeyboard } = require('grammy');
const { getAcc, users } = require('../utils/helper');
const { pesanMenu } = require('../utils/menu');
const { saveState } = require('../utils/persist');
const STR = require('../config/strings');

const snippet = (m) => {
  if (!m) return '(kosong)';
  if (typeof m === 'string') {
    const t = m.trim();
    if (!t) return '(kosong)';
    return t.length > 40 ? t.slice(0, 40) + '...' : t;
  }
  if (typeof m === 'object') {
    const baseText =
      (typeof m.text === 'string' && m.text.trim()) ? m.text.trim()
      : (typeof m.preview === 'string' && m.preview.trim()) ? m.preview.trim()
      : (m.mid !== undefined ? `[Forward ${m.mid}]` : '[Pesan]');
    return baseText.length > 40 ? baseText.slice(0, 40) + '...' : baseText;
  }
  return '(unknown)';
};

const createDeleteList = (ctx) => {
  const a = getAcc(ctx.from.id);
  if (!a || !a.msgs.length) {
    return { text: 'ℹ️ Daftar pesan kosong.', reply_markup: new InlineKeyboard().text('Tutup', 'delete_this') };
  }
  let text = "_Pilih pesan yang ingin dihapus_:\n\n";
  const kb = new InlineKeyboard();
  a.msgs.forEach((msg, i) => {
    const view = snippet(msg).replace(/\*/g, '');
    text += `${i + 1}. *${view}*\n`;
    kb.text(`❌ Hapus No.${i + 1}`, `del_msg_${i}`).row();
  });
  kb.text('💥 HAPUS SEMUA', 'delete_all_msgs').row();
  kb.text('Tutup', 'delete_this');
  return { text, reply_markup: kb, parse_mode: "Markdown" };
};

module.exports = (bot) => {
  bot.hears(STR.menu.pesanMenu, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    await ctx.reply('Kelola pesan broadcast.', { reply_markup: pesanMenu() });
  });

  bot.hears(STR.menu.addMessage, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    ctx.session = { act: 'addmsg' };
    await ctx.reply(STR.messages.addMessagePrompt, { parse_mode: 'Markdown' });
  });

  bot.hears(STR.menu.listMessage, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    if (!a.msgs.length) return ctx.reply('ℹ️ Daftar pesan kosong.');

    let out = `📝 *List Pesan Broadcast* (${a.msgs.length}):\n\n`;
    a.msgs.forEach((m, i) => {
      out += `${i + 1}. ${snippet(m)}\n`;
    });
    await ctx.reply(out, { parse_mode: 'Markdown' });
  });

  bot.hears(STR.menu.delMessage, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    if (!a.msgs.length) return ctx.reply('ℹ️ Daftar pesan kosong.');
    const { text, reply_markup, parse_mode } = createDeleteList(ctx);
    await ctx.reply(text, { reply_markup, parse_mode });
  });

  bot.callbackQuery(/del_msg_(\d+)/, async (ctx) => {
    const index = parseInt(ctx.match[1], 10);
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.answerCallbackQuery({ text: STR.messages.needLogin, show_alert: true });
    if (a.msgs[index] !== undefined) {
      a.msgs.splice(index, 1);
      saveState(users);
      await ctx.answerCallbackQuery({ text: `✅ Dihapus.` });
      const { text, reply_markup, parse_mode } = createDeleteList(ctx);
      try { await ctx.editMessageText(text, { reply_markup, parse_mode }); } catch {}
    } else {
      await ctx.answerCallbackQuery({ text: '❌ Sudah tidak ada.', show_alert: true });
    }
  });

  bot.callbackQuery('delete_all_msgs', async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (a) {
      a.msgs = [];
      saveState(users);
      await ctx.answerCallbackQuery({ text: '✅ Semua pesan dihapus.', show_alert: true });
      const { text, reply_markup, parse_mode } = createDeleteList(ctx);
      try { await ctx.editMessageText(text, { reply_markup, parse_mode }); } catch {}
    }
  });

  bot.callbackQuery('delete_this', async (ctx) => {
    try { await ctx.deleteMessage(); } catch {}
    await ctx.answerCallbackQuery();
  });
};
