const { InlineKeyboard, Keyboard, InputFile } = require('grammy');
const fs = require('fs');
const path = require('path');
const ent = require('../entitlements');
const { mainMenu } = require('../utils/menu');

const ADMIN_IDS = String(process.env.ADMIN_IDS || '')
  .split(',')
  .map(s => Number(s.trim()))
  .filter(n => Number.isFinite(n));

// QR dipaksa dari path absolut ini sesuai permintaan
const QR_PATHS = ['/root/assets/qris.png'];

const STATES = {
  IDLE: 'idle',
  WAITING_SELECTION: 'waiting_selection',
  WAITING_PROOF: 'waiting_proof',
};

const sessions = new Map(); // chatId -> {state, expectingProof, days, price}

function getS(ctx) {
  const id = ctx.from.id;
  if (!sessions.has(id)) sessions.set(id, { state: STATES.IDLE, expectingProof: false, days: 31, price: 'Rp 10.000' });
  return sessions.get(id);
}
function resetS(ctx) { sessions.delete(ctx.from.id); }

function shopSelectKb() {
  return new Keyboard()
    .text('Userbot Premium bulanan 💎').row()
    .text('Kembali')
    .resized();
}
function shopDoneInline() {
  return new InlineKeyboard()
    .text('Selesai✅', 'action:shop:done').row()
    .text('Batal', 'action:shop:cancel');
}
function gateKeyboard() {
  return new Keyboard().text('🎁 Uji coba 🎁').text('🛒 Shop 🛒').resized();
}

function paymentCaption(days, userId) {
  return (
`💳 *Payment Userbot Premium (Bulanan)*

🏷️ *UserID* : ${userId}
💰 *Harga* : Rp 10.000
⏰ *Durasi* : ${days} Hari

⏳Waktu Proses : 05:00-22:00

*Scan QR dan ketik nominal yang sesuai* !`
  );
}

function donePromptText() {
  return (
`*Silahkan kirim bukti foto pembayaran anda 🧾*
Note : bukti pembayaran palsu berpotensi pada pemblokiran id sehingga tidak dapat menggunakan bot untuk selamanya.`
  );
}

function approvedUserText(days) {
  return (
`*Selamat! aktivasi anda berhasil* ✅

nikmati full acces ke Userbot Premium selama ${days} hari. fitur akan selalu dikembangkan dan jika terjadi eror mohon hubungi @Jaehype.

*Terimakasih sudah berlangganan, Have a nice day!* 🔥`
  );
}

function rejectedUserText() {
  return (
`*Maaf, aktivasi anda belum berhasil.*❌

Aktivasi Userbot Premium belum berhasil. Anda dapat mencoba lagi dari menu 🛒 Shop 🛒.`
  );
}

// Kirim foto QR dengan fallback berlapis agar stabil di lingkungan Node
async function sendQr(ctx, text) {
  const opts = { caption: text, parse_mode: 'Markdown', reply_markup: shopDoneInline() };
  for (const p of QR_PATHS) {
    try {
      if (!p) continue;
      if (!fs.existsSync(p)) {
        console.error('[shop] QR path not found:', p);
        continue;
      }

      // 1) Coba kirim langsung via InputFile(path)
      try {
        await ctx.replyWithPhoto(new InputFile(p), opts);
        return;
      } catch (e1) {
        console.error('[shop] send photo via path failed:', e1.message);
      }

      // 2) Coba via stream
      try {
        const stream = fs.createReadStream(p);
        await ctx.replyWithPhoto(new InputFile(stream, path.basename(p) || 'qris.png'), opts);
        return;
      } catch (e2) {
        console.error('[shop] send photo via stream failed:', e2.message);
      }

      // 3) Coba via buffer
      try {
        const buf = fs.readFileSync(p);
        await ctx.replyWithPhoto(new InputFile(buf, path.basename(p) || 'qris.png'), opts);
        return;
      } catch (e3) {
        console.error('[shop] send photo via buffer failed:', e3.message);
      }
    } catch (e) {
      console.error('[shop] sendQr unexpected error:', e.message);
    }
  }
  // Fallback: kirim teks saja jika semua cara gagal
  await ctx.reply(text, { parse_mode: 'Markdown', reply_markup: shopDoneInline() });
}

async function backToGateOrMain(ctx) {
  const allowed = ent.isAllowed(ctx.from.id);
  if (allowed) {
    const menu = mainMenu(ctx);
    await ctx.reply(menu.text, { reply_markup: menu.reply_markup, parse_mode: menu.parse_mode });
  } else {
    await ctx.reply('Pilih salah satu:', { reply_markup: gateKeyboard() });
  }
}

module.exports = (bot) => {
  // Trial (sekali seumur hidup, walau restart)
  bot.hears('🎁 Uji coba 🎁', async (ctx) => {
    ent.ensureUserFromCtx(ctx);
    if (!ent.canStartTrial(ctx.from.id)) {
      await ctx.reply('❌ Uji coba sudah pernah digunakan. Silakan berlangganan via 🛒 Shop 🛒.');
      return;
    }
    const res = ent.startTrialHours(ctx.from.id, 2);
    const until = new Date(res.expires_at).toLocaleString('id-ID', { hour12: false });
    await ctx.reply(
      `🎊 *TRIAL BERHASIL!* 🎊\n*nikmati semua layanan selama 2 jam*\n_berlaku sampai_: ${until}`,
      { parse_mode: 'Markdown' }
    );
    await backToGateOrMain(ctx);
  });

  // Shop start
  bot.hears('🛒 Shop 🛒', async (ctx) => {
    const s = getS(ctx);
    s.state = STATES.WAITING_SELECTION;
    s.expectingProof = false;
    await ctx.reply('Pilih paket langganan:', { reply_markup: shopSelectKb() });
  });

  // Reply keyboard in Shop state
  bot.hears(['Userbot Premium bulanan 💎', 'Kembali'], async (ctx) => {
    const s = getS(ctx);
    if (ctx.message.text === 'Kembali') {
      resetS(ctx);
      await backToGateOrMain(ctx);
      return;
    }
    if (s.state !== STATES.WAITING_SELECTION) {
      return ctx.reply('Tidak dalam sesi Shop. Tekan 🛒 Shop 🛒.');
    }
    s.state = STATES.WAITING_PROOF;
    s.expectingProof = false;
    await sendQr(ctx, paymentCaption(s.days, ctx.from.id));
  });

  // Inline callbacks
  bot.callbackQuery('action:shop:cancel', async (ctx) => {
    resetS(ctx);
    try { await ctx.answerCallbackQuery(); } catch {}
    await backToGateOrMain(ctx);
  });

  bot.callbackQuery('action:shop:done', async (ctx) => {
    try { await ctx.answerCallbackQuery(); } catch {}
    const s = getS(ctx);
    if (s.state !== STATES.WAITING_PROOF) return;
    s.expectingProof = true;
    await ctx.reply(donePromptText(), { parse_mode: 'Markdown' });
  });

  // Admin verification
  bot.callbackQuery(/^action:shop:(approve|reject):(\d+):?(\d+)?$/, async (ctx) => {
    const [, kind, targetIdStr, daysStr] = ctx.match;
    const fromId = ctx.from.id;
    if (!ent.isAdmin(fromId)) {
      return ctx.answerCallbackQuery({ text: 'Hanya admin.', show_alert: true });
    }
    const targetId = Number(targetIdStr);
    if (kind === 'approve') {
      const days = Number(daysStr) || 31;
      try {
        const store = require('../accessStore');
        store.setStatus(targetId, 'active');
      } catch {}
      ent.grantPro(targetId, days);
      try {
        await ctx.api.sendMessage(
          targetId,
          approvedUserText(days),
          { parse_mode: 'Markdown', message_effect_id: '5046509860389126442' }
        );
      } catch {}
      try {
        const { mainMenu } = require('../utils/menu');
        const menu = mainMenu({ from: { id: targetId, first_name: 'User' } });
        await ctx.api.sendMessage(targetId, menu.text, { parse_mode: menu.parse_mode, reply_markup: menu.reply_markup });
      } catch {}
      try { await ctx.answerCallbackQuery({ text: `✅ Berhasil verifikasi ${targetId}` }); } catch {}
    } else {
      try { await ctx.api.sendMessage(targetId, rejectedUserText(), { parse_mode: 'Markdown' }); } catch {}
      try { await ctx.answerCallbackQuery({ text: `❌ Ditolak untuk ${targetId}` }); } catch {}
    }
  });

  // Consume proofs (1 photo only)
  bot.on('message', async (ctx, next) => {
    try {
      const s = sessions.get(ctx.from?.id);
      if (!s || s.state !== STATES.WAITING_PROOF) return next();

      const hasPhoto = Array.isArray(ctx.message.photo) && ctx.message.photo.length > 0;
      const isImageDoc = ctx.message.document && /^image\//i.test(ctx.message.document.mime_type || '');
      if (!hasPhoto && !isImageDoc) return;

      if (!s.expectingProof) {
        await ctx.reply('Tekan tombol Selesai✅ pada pesan QR terlebih dahulu, lalu kirim 1 foto bukti.');
        return;
      }

      if (ctx.message.media_group_id) {
        await ctx.reply('Kirim ulang: hanya 1 foto (bukan album).');
        return;
      }

      let fileId = null;
      if (hasPhoto) fileId = ctx.message.photo[ctx.message.photo.length - 1].file_id;
      else if (isImageDoc) fileId = ctx.message.document.file_id;
      if (!fileId) {
        await ctx.reply('Kirim ulang: pastikan mengirim 1 foto, bukan jenis lain.');
        return;
      }

      s.expectingProof = false;

      const username = ctx.from?.username ? `@${ctx.from.username}` : '-';
      const when = new Date().toLocaleString('id-ID', { hour12: false, timeZone: 'Asia/Jakarta' });
      const caption =
`Pembayaran baru:
UserID: ${ctx.from.id}
Username: ${username}
Paket: Bulanan (31 hari)
Waktu: ${when}

Klik untuk verifikasi:`;

      for (const adminId of ADMIN_IDS) {
        try {
          await ctx.api.sendPhoto(adminId, fileId, {
            caption,
            parse_mode: 'Markdown',
            reply_markup: new InlineKeyboard()
              .text('Setuju ✅', `action:shop:approve:${ctx.from.id}:31`).row()
              .text('Gagal ⛔', `action:shop:reject:${ctx.from.id}`)
          });
        } catch {
          await ctx.api.sendMessage(adminId, caption, {
            parse_mode: 'Markdown',
            reply_markup: new InlineKeyboard()
              .text('Setuju ✅', `action:shop:approve:${ctx.from.id}:31`).row()
              .text('Gagal ⛔', `action:shop:reject:${ctx.from.id}`)
          }).catch(()=>{});
        }
      }

      await ctx.reply('Mohon tunggu 1-10 menit untuk diverifikasi.');
    } catch (e) {
      console.error('[shop] proof error:', e);
    }
  });
};
