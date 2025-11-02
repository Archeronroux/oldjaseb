require('dotenv').config();
const fs = require('fs');
const path = require('path');

// -------- Validasi Variabel Lingkungan Wajib --------
const required = ['BOT_TOKEN', 'API_ID', 'API_HASH'];
const miss = required.filter(k => !process.env[k] || process.env[k].trim() === '');
if (miss.length) {
  console.error('❌ Env tidak lengkap: ' + miss.join(', '));
  console.error('Isi file .env kamu, contoh:\nBOT_TOKEN=8262515261:ABCDEF...\nAPI_ID=12345678\nAPI_HASH=abcdef0123456789abcdef0123456789');
  process.exit(1);
}

// -------- Ekstrak BOT_ID dari BOT_TOKEN --------
let BOT_ID;
try {
  BOT_ID = parseInt(process.env.BOT_TOKEN.split(':')[0], 10);
  if (Number.isNaN(BOT_ID)) throw new Error('Format BOT_TOKEN tidak valid (tidak bisa ambil angka sebelum :).');
} catch (e) {
  console.error('❌ Gagal ambil BOT_ID:', e.message);
  process.exit(1);
}

// -------- Direktori Sessions (jika dipakai userbot) --------
const sessionsDir = path.join(__dirname, '../sessions');
if (!fs.existsSync(sessionsDir)) {
  try {
    fs.mkdirSync(sessionsDir, { recursive: true });
  } catch (e) {
    console.error('❌ Tidak bisa buat folder sessions:', e.message);
    process.exit(1);
  }
}

// -------- Parsing API_ID --------
const API_ID = parseInt(process.env.API_ID, 10);
if (Number.isNaN(API_ID)) {
  console.error('❌ API_ID harus angka. Nilai sekarang:', process.env.API_ID);
  process.exit(1);
}

// -------- Export --------
module.exports = {
  BOT_TOKEN: process.env.BOT_TOKEN,
  API_ID,
  API_HASH: process.env.API_HASH,
  BOT_ID,
  sessionsDir
};

// Debug opsional
if (process.env.DEBUG_CONFIG === '1') {
  console.log('[CONFIG] BOT_ID =', BOT_ID);
  console.log('[CONFIG] sessionsDir =', sessionsDir);
}
