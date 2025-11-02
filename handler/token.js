const { tokenMenu } = require('../utils/menu');
const { getAcc } = require('../utils/helper');
const { generateTokenFromAccount } = require('../utils/token');
const STR = require('../config/strings');

module.exports = (bot) => {
  bot.hears(STR.menu.tokenMenu, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    await ctx.reply('🔑 Menu Token', { reply_markup: tokenMenu() });
  });

  bot.hears(STR.menu.tokenMine, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    try {
      const token = generateTokenFromAccount(a); // versi ringkas (v6) default
      if (token.length <= 3900) {
        await ctx.reply(`${STR.messages.tokenHeader}\n\`\`\`\n${token}\n\`\`\``, { parse_mode: 'Markdown' });
      } else {
        await ctx.reply(`${STR.messages.tokenTooLongIntro} (total ${token.length} karakter)`);
        let part = 1;
        for (let i = 0; i < token.length; i += 3800) {
          const chunk = token.slice(i, i + 3800);
          await ctx.reply(`Part ${part}:\n\`\`\`\n${chunk}\n\`\`\``, { parse_mode: 'Markdown' });
          part++;
        }
      }
    } catch (e) {
      await ctx.reply('❌ Gagal membuat token: ' + e.message);
    }
  });

  bot.hears(STR.menu.tokenInput, async (ctx) => {
    const a = getAcc(ctx.from.id);
    if (!a) return ctx.reply(STR.messages.needLogin);
    ctx.session = { act: 'input_token' };
    await ctx.reply('Kirim token backup (isi base64).');
  });
};
