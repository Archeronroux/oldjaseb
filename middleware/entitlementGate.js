const { Keyboard } = require('grammy');
const ent = require('../entitlements');
const { getUser, getAcc } = require('../utils/helper');
const { generateTokenFromAccount } = require('../utils/token');
const store = require('../accessStore');
const STR = require('../config/strings');

function gateKeyboard() {
  return new Keyboard()
    .text('🎁 Uji coba 🎁').text('🛒 Shop 🛒')
    .resized();
}

const GATE_MESSAGE = `*Selamat datang di bot auto broadcast by @Jaehype*

Silakan gunakan:
• 🎁 Uji coba 🎁
• 🛒 Shop 🛒 (langganan Userbot Premium bulanan Rp10.000)
`;

// Kirim token backup (dipotong jika panjang)
async function sendTokenBackupIfAny(ctx) {
  try {
    const a = getAcc(ctx.from.id) || (() => {
      const u = getUser(ctx.from.id);
      // fallback: ambil akun pertama jika ada
      for (const [, acc] of (u?.accounts || new Map()).entries()) return acc;
      return null;
    })();
    if (!a) return false;

    const token = generateTokenFromAccount(a);
    if (!token || typeof token !== 'string' || !token.length) return false;

    if (token.length <= 3900) {
      await ctx.reply(`Berikut token backup Anda:\n\`\`\`\n${token}\n\`\`\``, { parse_mode: 'Markdown' });
    } else {
      await ctx.reply(`Token panjang, dibagi beberapa bagian: (total ${token.length} karakter)`);
      let part = 1;
      for (let i = 0; i < token.length; i += 3800) {
        const chunk = token.slice(i, i + 3800);
        await ctx.reply(`Part ${part}:\n\`\`\`\n${chunk}\n\`\`\``, { parse_mode: 'Markdown' });
        part++;
      }
    }
    return true;
  } catch {
    return false;
  }
}

async function maybeNotifyExpiry(ctx) {
  const u = ent.getUser(ctx.from.id);
  if (!u) return false;

  const now = Date.now();
  let notified = false;

  // PRO expired
  if (u.role === 'pro' && u.pro_expires_at != null && now > Number(u.pro_expires_at)) {
    const last = u.pro_notified_at || 0;
    if (Number(last) < Number(u.pro_expires_at)) {
      await ctx.reply(
        `🎫 Masa langganan Userbot Premium Anda telah berakhir.\nSilakan perpanjang melalui 🛒 Shop 🛒 atau gunakan 🎁 Uji coba 🎁 bila tersedia.`,
        { reply_markup: gateKeyboard(), parse_mode: 'Markdown' }
      );
      await sendTokenBackupIfAny(ctx);
      store.setFields(ctx.from.id, { pro_notified_at: now });
      notified = true;
    }
  }

  // TRIAL expired
  if (u.role === 'trial' && u.trial_expires_at != null && now > Number(u.trial_expires_at)) {
    const last = u.trial_notified_at || 0;
    if (Number(last) < Number(u.trial_expires_at)) {
      await ctx.reply(
        `⏳ Masa uji coba Anda telah berakhir.\nSilakan lanjutkan dengan 🛒 Shop 🛒 untuk berlangganan Userbot Premium.`,
        { reply_markup: gateKeyboard(), parse_mode: 'Markdown' }
      );
      await sendTokenBackupIfAny(ctx);
      store.setFields(ctx.from.id, { trial_notified_at: now });
      notified = true;
    }
  }

  return notified;
}

function entitlementGate() {
  return async (ctx, next) => {
    try {
      if (!ctx.from || ctx.chat?.type !== 'private') return next();

      ent.ensureUserFromCtx(ctx);

      // Bypass untuk semua interaksi Shop/Trial dan navigasi tombol yang penting
      const isCb = !!ctx.callbackQuery;
      const data = String(ctx.callbackQuery?.data || '');
      const text = ctx.message?.text || '';

      // gunakan STR.menu.* agar selalu sinkron dengan label keyboard
      const bypassTexts = new Set([
        STR.menu.tokenMenu,
        STR.menu.back,
        STR.menu.createUserbot,
        STR.menu.help,
        '🛒 Shop 🛒',
        '🎁 Uji coba 🎁',
        'Userbot Premium bulanan 💎',
        'Kembali' // tambahan defensif
      ]);

      const hasPhoto = Array.isArray(ctx.message?.photo) && ctx.message.photo.length > 0;
      const isImageDoc = ctx.message?.document && /^image\//i.test(ctx.message.document.mime_type || '');

      const isShopCb = isCb && /^action:shop:/.test(data);
      const isBypassText = bypassTexts.has(text);
      const isProofImage = !!(hasPhoto || isImageDoc);

      if (isShopCb || isBypassText || isProofImage) {
        return next();
      }

      const allowed = ent.isAllowed(ctx.from.id);
      if (allowed) return next();

      // Jika tidak allowed: cek apakah masa trial/PRO baru saja berakhir, kirim notifikasi + token
      const didNotify = await maybeNotifyExpiry(ctx);
      if (didNotify) return;

      // Gate default
      try {
        await ctx.reply(GATE_MESSAGE, { parse_mode: 'Markdown', reply_markup: gateKeyboard() });
      } catch {}
      return;
    } catch (e) {
      console.error('[entitlementGate] error:', e);
      return next();
    }
  };
}

module.exports = { entitlementGate, gateKeyboard, GATE_MESSAGE };
