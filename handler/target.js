const { InlineKeyboard } = require('grammy');
const { getAcc, users } = require('../utils/helper');
const { targetMenu } = require('../utils/menu');
const { saveState } = require('../utils/persist');
const STR = require('../config/strings');

const createTargetDeleteList = (ctx) => {
  const a = getAcc(ctx.from.id);
  if (!a || !a.targets.size) {
    return { text: 'ℹ️ Daftar target manual Anda kosong.', reply_markup: new InlineKeyboard().text('Tutup', 'delete_this') };
  }
  let text = "Pilih target yang ingin dihapus:\n\n";
  const kb = new InlineKeyboard();
  let i = 1;
  for (const [id, target] of a.targets) {
    text += `${i}. *${target.title}*\n`;
    kb.text(`❌ Hapus No. ${i}`, `del_tgt_${id}`).row();
    i++;
    if (i > 15) { text += `\n...dan lainnya.`; break; }
  }
  kb.text('💥 HAPUS SEMUA TARGET', 'delete_all_targets').row();
  kb.text('Tutup', 'delete_this');
  return { text, reply_markup: kb, parse_mode: "Markdown" };
};

async function showLoading(ctx, msg='⏳ *Tunggu sebentar...*'){
  try { const m=await ctx.reply(msg,{parse_mode:'Markdown'}); return m.message_id; } catch { return null; }
}
async function deleteIfPossible(ctx, mid){
  if(!mid) return;
  try { await ctx.api.deleteMessage(ctx.from.id, mid); } catch {}
}

module.exports = (bot) => {
  bot.hears(STR.menu.targetMenu, async (ctx) => {
    const a=getAcc(ctx.from.id);
    if(!a?.authed) return ctx.reply(STR.messages.needLogin);
    await ctx.reply('*Silahkan Pilih Opsi Menu*',{parse_mode:'Markdown',reply_markup:targetMenu(a)});
  });

  bot.hears(STR.menu.addTarget, async (ctx) => {
    const a=getAcc(ctx.from.id);
    if(!a) return ctx.reply(STR.messages.needLogin);
    ctx.session={act:'addtgt'};
    await ctx.reply(STR.messages.addTargetPrompt,{parse_mode:'Markdown'});
  });

  bot.hears(STR.menu.grabAll, async (ctx)=>{
    const a=getAcc(ctx.from.id);
    if(!a) return ctx.reply(STR.messages.needLogin);
    const mid=await showLoading(ctx);
    try{
      const count=await a.addAll();
      await deleteIfPossible(ctx,mid);
      saveState(users);
      await ctx.reply(`✅ Berhasil mengambil ${count} target.`,{reply_markup:targetMenu(a)});
    }catch{
      await deleteIfPossible(ctx,mid);
      await ctx.reply('❌ Gagal mengambil target.');
    }
  });

  bot.hears(STR.menu.listTarget, async (ctx)=>{
    const a=getAcc(ctx.from.id);
    if(!a) return ctx.reply(STR.messages.needLogin);
    if(!a.targets.size) return ctx.reply('❌ Daftar target kosong.');
    let text=`📋 *Daftar CH/Grup saat ini* (${a.targets.size}):\n\n`;
    let i=1;
    for(const [,t] of a.targets){
      text+=`${i}. ${t.title}\n`;
      i++;
      if(i>20){ text+=`\n...dan ${a.targets.size-20} lainnya.`; break; }
    }
    await ctx.reply(text,{parse_mode:'Markdown'});
  });

  bot.hears(STR.menu.delTarget, async (ctx)=>{
    const a=getAcc(ctx.from.id);
    if(!a) return ctx.reply(STR.messages.needLogin);
    if(!a.targets.size) return ctx.reply('ℹ️ Daftar target manual kosong, tidak ada yang bisa dihapus.');
    const {text,reply_markup,parse_mode}=createTargetDeleteList(ctx);
    await ctx.reply(text,{reply_markup,parse_mode});
  });

  bot.hears(STR.menu.verifyTarget, async (ctx)=>{
    const a=getAcc(ctx.from.id);
    if(!a?.authed) return ctx.reply(STR.messages.needLogin);
    if(!a.targets.size) return ctx.reply(STR.messages.noTargets);
    const mid=await showLoading(ctx, STR.messages.verifyRunning);
    try{
      const ver=await a.verifyTargets({stopOnFlood:true});
      saveState(users);
      await deleteIfPossible(ctx,mid);
      let msg=`${STR.messages.verifyResultHeader}\n`;
      msg+=`• Total: ${ver.total}\n`;
      msg+=`• Ready/Already: ${ver.already}\n`;
      msg+=`• Join baru: ${ver.joined_new}\n`;
      msg+=`• Gagal: ${ver.failed.length}\n`;
      if(ver.flood_wait) msg+=`• LIMIT: ±${ver.flood_wait}s\n`;

      msg+=`\n${STR.messages.summaryFailHeader}\n`;
      if(ver.flood_wait) msg+=STR.messages.summaryLimit(1)+'\n';
      if(ver.failed.length) msg+=STR.messages.summaryJoinFail(ver.failed.length)+'\n';
      if(ver.flood_wait) msg+=`\nTekan lagi ${STR.menu.verifyTarget} setelah menunggu.`;

      await ctx.reply(msg,{parse_mode:'Markdown',reply_markup:targetMenu(a)});
    }catch(e){
      await deleteIfPossible(ctx,mid);
      await ctx.reply('❌ Verifikasi gagal: '+e.message);
    }
  });

  bot.callbackQuery(/del_tgt_(.+)/, async (ctx)=>{
    const targetId=ctx.match[1];
    const a=getAcc(ctx.from.id);
    if(a && a.targets.has(targetId)){
      a.targets.delete(targetId);
      saveState(users);
      await ctx.answerCallbackQuery({text:'✅ Target dihapus.'});
      const {text,reply_markup,parse_mode}=createTargetDeleteList(ctx);
      await ctx.editMessageText(text,{reply_markup,parse_mode});
    } else {
      await ctx.answerCallbackQuery({text:'❌ Target sudah tidak ada.',show_alert:true});
    }
  });

  bot.callbackQuery('delete_all_targets', async (ctx)=>{
    const a=getAcc(ctx.from.id);
    if(a){
      a.targets.clear();
      saveState(users);
      await ctx.answerCallbackQuery({text:'✅ Semua target berhasil dihapus.',show_alert:true});
      const {text,reply_markup,parse_mode}=createTargetDeleteList(ctx);
      await ctx.editMessageText(text,{reply_markup,parse_mode});
    }
  });

  bot.callbackQuery('delete_this', async (ctx)=>{
    try{ await ctx.deleteMessage(); }catch{}
    await ctx.answerCallbackQuery();
  });
};
