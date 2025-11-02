module.exports = {
  menu: {
    createUserbot: '🤖 Buat Userbot 🤖',
    tokenMenu: '🔑 Token 🔑',
    help: '💡 Bantuan 💡',
    run: '🚀 Jalankan Ubot 🚀',
    stop: '⛔ Hentikan Ubot ⛔',
    pesanMenu: '📚 Kelola Pesan 📚',
    targetMenu: '⚡ Kelola Target ⚡',
    settings: '⚙️ Settings ⚙️',
    stats: '📈 Lihat Statistik 📈',
    back: '⬅️ Kembali',
    addMessage: '📩 Tambah Pesan 📩',
    listMessage: '📋 List Pesan 📋',
    delMessage: '🗑️ Hapus Pesan 🗑️',
    addTarget: '📥 Tambah Target 📥',
    listTarget: '📋 List Target 📋',
    delTarget: '🗑️ Hapus Target 🗑️',
    grabAll: '🖇️ Ambil Semua 🖇️',
    verifyTarget: '🪄 Verifikasi Target 🪄',
    tokenMine: '🪢 Token Saya 🪢',
    tokenInput: '⌨️ Input Token ⌨️',
    changeDelayMode: '💎 Ganti Mode Jeda 💎',
    // Admin
    admin: '👑 Admin',
    adminListPro: '📜 List Pro Aktif',
    adminCheckUser: '🔎 Cek User',
    adminGrantPro: '➕ Grant Pro',
    adminExtendPro: '♻️ Perpanjang Pro',
    adminRevokePro: '❌ Revoke Pro',
    adminBlockUser: '🚫 Block User',
    adminAllowUser: '✅ Allow User',
    adminBroadcast: '📩 Broadcast PM'
  },
  messages: {
    welcomeNotAuthed: (name) =>
      `*👋🏻 Hai!, ${name}*\n\nSelamat datang di Ubot by @JaeHype!\nBot ini bisa broadcast otomatis!\n\n*Owner : @JaeHype*\n*Channel: @PanoramaaStoree*`,
    welcomeAuthed: (name, status) =>
`*👋🏻 Hai!, ${name}*

Selamat datang kembali di Ubot by @JaeHype!

---
*Status Akun:*
👤 Akun Aktif: *${name}*
📚 Status Ubot: *${status}*

Ads : [Join Channel utama](https://t.me/PanoramaaStoree)`,
    needLogin: '❌ Login dulu',
    askPhone: '📱 Kirim Nomor Telepon Anda (format: +628xxx):',
    invalidPhone: '❌ Format salah. Contoh: +6281234567890',
    otpInfo: `*Silakan kirim kode OTP yang masuk.*\nPisahkan angka dengan spasi (contoh: 2 4 5 6 3)`,
    passwordAsk: 'Kirim Password 2FA Anda',
    loginSuccess: () => `✅ Login berhasil!`,
    loginCancelled: 'Login dibatalkan.',
    addMessagePrompt:
      `*Kirim pesan yang akan dibroadcast*.\n• Format (bold/italic/dll) & link disimpan\n• Bisa forward untuk ambil style\n• Media belum didukung`,
    messageSaved: '✅ Teks Disimpan.',
    messageForwardSaved: '✅ Pesan Forward Disimpan.',
    messageUnsupported: '⚠️ Media belum didukung, disimpan placeholder.',
    noMessages: '❌ Anda belum menambah pesan.',
    addTargetPrompt:
      `📥 *Kirim link / username / undangan t.me* (bisa banyak, pisah spasi atau baris).\nContoh:\nhttps://t.me/namachannel\n@username\n+InviteHash\n\nCatatan:\n• t.me/c/ (link posting) tidak didu[...]`,
    noTargets: '❌ Anda belum menambah target.',
    startScheduled: (hhmm, mins) => `⏳ Akan mulai pada ${hhmm} (dalam ${mins.toFixed(1)} m)`,
    startScheduledTomorrow: (hhmm) => `⏰ Jadwal mulai besok jam ${hhmm}`,
    autoStartInfo: (hhmm) => `⏰ Timer mulai disetel: ${hhmm} (otomatis).`,
    alreadyRunning: 'ℹ️ Sudah berjalan.',
    started: '✅ Ubot dijalankan.',
    stopped: '🛑 Ubot dihentikan.',
    stopAuto: (hhmm) => `🛑 Berhenti otomatis (Waktu Stop ${hhmm}).`,
    startTimeSet: (hhmm) => `✅ Waktu Mulai: ${hhmm}`,
    startTimeCleared: '✅ Waktu Mulai dihapus.',
    stopTimeSet: (hhmm) => `✅ Waktu Stop: ${hhmm}`,
    stopTimeCleared: '✅ Waktu Stop dihapus.',
    verifyRunning: '🔍 *Memverifikasi & auto-join...*',
    verifyResultHeader: '🪄 *Verifikasi Target*',
    importDone: '✅ Import token selesai.',
    tokenHeader: 'Berikut token backup Anda:',
    tokenTooLongIntro: 'Token panjang, dibagi beberapa bagian:',
    floodWaitNotice: (seconds) => `⚠️ Limit join, tunggu ± ${seconds}s lalu ulangi verifikasi.`,
    scheduleNextDay: (hhmm) => `🕒 Jadwal mulai besok pada ${hhmm}`,
    noChange: 'ℹ️ Tidak ada perubahan.',
    summaryFailHeader: 'Penyebab gagal :',
    summaryLimit: (n) => `⚠️ Limit join, harap tunggu (${n})`,
    summaryInvalid: (n) => `⚠️ Input tidak valid (${n})`,
    summaryDuplicate: (n) => `⚠️ Duplikat di ${n} target`,
    summaryJoinFail: (n) => `⚠️ Gagal join (${n})`
  },
  errors: {
    clientNotConnected: '❌ Sesi belum aktif/terhubung.',
    invalidTime: '❌ Format salah. Gunakan HH:MM (24 jam).',
    invalidDelay: '❌ Masukkan angka 1-3600.',
    invalidDelayAll: '❌ Masukkan angka 1-1440.',
    tokenInvalid: (e) => '❌ Token tidak valid: ' + e,
    addTargetFailed: (e) => `❌ Gagal menambah target: ${e}`,
    importFailed: (e) => `❌ Token tidak valid: ${e}`
  }
};
