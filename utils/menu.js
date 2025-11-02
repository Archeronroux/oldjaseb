const { Keyboard } = require('grammy');
const { getUser, getAcc } = require('./helper');
const STR = require('../config/strings');
const ent = require('../entitlements');

const allCommandNames = new Set();
const k = (t) => { allCommandNames.add(t); return t; };

function buildMain(u, a, firstName, userId) {
  const isAdmin = ent.isAdmin(userId);
  if (!a?.authed) {
    const keyboard = new Keyboard()
      .text(k(STR.menu.createUserbot)).row()
      .text(k(STR.menu.tokenMenu)).text(k(STR.menu.help))
      .resized();
    if (isAdmin) keyboard.row().text(k(STR.menu.admin));
    return {
      text: STR.messages.welcomeNotAuthed(firstName),
      reply_markup: keyboard,
      parse_mode: 'Markdown'
    };
  }
  const status = a.running ? 'Aktif' : 'Mati';
  const keyboard = new Keyboard()
    .text(k(STR.menu.run)).text(k(STR.menu.stop)).row()
    .text(k(STR.menu.pesanMenu)).text(k(STR.menu.targetMenu)).row()
    .text(k(STR.menu.settings)).text(k(STR.menu.stats)).row()
    .text(k(STR.menu.tokenMenu)).text(k(STR.menu.help))
    .resized();
  if (isAdmin) keyboard.row().text(k(STR.menu.admin));
  return {
    text: STR.messages.welcomeAuthed(a.name, status),
    reply_markup: keyboard,
    parse_mode: 'Markdown'
  };
}

const mainMenu = (ctx) => {
  const u = getUser(ctx.from.id);
  const a = getAcc(ctx.from.id);
  return buildMain(u, a, (ctx.from.first_name || 'Pengguna'), ctx.from.id);
};

function gateKeyboard() {
  return new Keyboard()
    .text('🎁 Uji coba 🎁').text('🛒 Shop 🛒')
    .resized();
}

const startCommand = async (ctx) => {
  // Jika user sedang pada flow login (pending code/password), batalkan dan hapus akun sementara
  try {
    const u = getUser(ctx.from.id);
    for (const [id, acc] of u.accounts) {
      if (acc && (acc.pendingCode || acc.pendingPass || acc.pendingMsgId)) {
        try { acc.cancel(ctx); } catch {}
        // Hapus akun sementara yang dibuat untuk proses login agar tidak menumpuk
        try { u.accounts.delete(id); } catch {}
      }
    }
  } catch (e) {
    // jangan ganggu flow utama kalau ada error kecil di cleanup
    console.error('[startCommand] cleanup pending acc error:', e && e.stack ? e.stack : e);
  }

  // Bersihkan session state di bot (agar tombol Kembali benar-benar keluar dari mode apapun)
  ctx.session = null;

  const allowed = ent.isAllowed(ctx.from.id);
  if (!allowed) {
    await ctx.reply(
      `🔐 *Akses Dibatasi*\n\nSilakan gunakan:\n• 🎁 Uji coba 🎁\n• 🛒 Shop 🛒 (Userbot Premium bulanan Rp10.000)`,
      { parse_mode: 'Markdown', reply_markup: gateKeyboard() }
    );
    return;
  }
  const m = mainMenu(ctx);
  await ctx.reply(m.text, { reply_markup: m.reply_markup, parse_mode: m.parse_mode });
};

const helpCommand = async (ctx) => {
  const text =
`*✨ Ubot Panorama ✨*
Gunakan untuk mengirim pesan terjadwal ke banyak grup.

Langkah cepat:
1. Buat sesi: 🤖 Buat Userbot & login
2. Tambah pesan: ✉️ Kelola Pesan 
3. Tambah target: 📚 Kelola Target/ Ambil Semua
4. Jalankan: 🚀 Jalankan Ubot

*⚠️ Gunakan sebaik-baiknya. Masih ada kekurangan.*
Terima kasih atas pengertiannya!

Kontak: @JaeHype
Channel Update: @PanoramaaStore`;
  await ctx.reply(text, {
    parse_mode: 'Markdown',
    reply_markup: new Keyboard().text(k(STR.menu.back)).resized()
  });
};

module.exports = {
  allCommandNames,
  mainMenu,
  // menus below unchanged
  pesanMenu: () =>
    new Keyboard()
      .text(k(STR.menu.addMessage)).row()
      .text(k(STR.menu.delMessage)).text(k(STR.menu.listMessage)).row()
      .text(k(STR.menu.back))
      .resized(),
  targetMenu: () =>
    new Keyboard()
      .text(k(STR.menu.addTarget)).text(k(STR.menu.grabAll)).row()
      .text(k(STR.menu.listTarget)).text(k(STR.menu.delTarget)).row()
      .text(k(STR.menu.verifyTarget)).row()
      .text(k(STR.menu.back))
      .resized(),
  tokenMenu: () =>
    new Keyboard()
      .text(k(STR.menu.tokenInput)).row()
      .text(k(STR.menu.tokenMine)).row()
      .text(k(STR.menu.back))
      .resized(),
  settingMenu: (a) => {
    const delayLabel = a.delayMode === 'semua'
      ? `⛓️ Jeda Semua Grup: ${a.delayAllGroups}m`
      : `🔗 Jeda Antar Grup: ${a.delay}s`;
    const startLabel = `🕒 Waktu Mulai: ${a.startTime ? a.startTime : '-'}`;
    const stopLabel = `🕝 Waktu Stop: ${a.stopTime ? a.stopTime : '-'}`;
    return new Keyboard()
      .text(k(delayLabel)).row()
      .text(k(STR.menu.changeDelayMode)).row()
      .text(k(startLabel)).text(k(stopLabel)).row()
      .text(k(STR.menu.back))
      .resized();
  },
  jedaMenu: () =>
    new Keyboard()
      .text(k('🔗 Jeda Antar Grup')).row()
      .text(k('⛓️ Jeda Per Semua Grup')).row()
      .text(k(STR.menu.back))
      .resized(),
  startCommand,
  helpCommand
};
