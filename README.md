
- Node.js >= 18
- NPM atau Yarn
- Akun Telegram
- API ID dan API Hash dari [my.telegram.org](https://my.telegram.org/apps)
- Bot Token dari [BotFather](https://t.me/BotFather)


```bash
# Update paket
sudo apt update && sudo apt upgrade -y

# install git
sudo apt install git -y

# Install Node.js (gunakan versi LTS terbaru)
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs git

# Clone repository
git clone https://github.com/QillerHo/jaseb.git
cd jaseb

# Install dependencies
npm install
```

### Windows

```powershell
# Pastikan sudah install Node.js LTS dari https://nodejs.org/
# Clone repository
git clone https://github.com/QillerHo/jaseb.git
cd jaseb

# Install dependencies
npm install
```

## Konfigurasi

Buat file `.env` di root project dengan isi seperti berikut:

```env
BOT_TOKEN=isi_dengan_token_bot
API_ID=isi_dengan_api_id
API_HASH=isi_dengan_api_hash
```

## Menjalankan

### Ubuntu/Debian

```bash
node index.js
```

### Windows (PowerShell / CMD)

```powershell
node index.js
```

Jika berhasil, terminal akan menampilkan:

```
JASEB started
```

## PM2 (Biar Bisa Ditinggal)
```bash
# Install PM2
sudo npm install -g pm2

# jalankan PM2
pm2 start index.js

# Stop PM2
pm2 stop index.js
```

## Cara Penggunaan

1. Jalankan bot dengan perintah `/start` di Telegram.
2. Login akun Telegram:
   - Masukkan nomor dengan format `+628xxx`.
   - Masukkan kode OTP dan password 2FA (jika ada).
3. Atur pesan jaseb.
4. Pilih target:
   - Mode otomatis (semua group/channel).
   - Mode manual (tambahkan target satu per satu).
5. Start untuk memulai jaseb.
6. Gunakan menu Stop untuk menghentikan.

## Catatan

- Delay pesan bisa diatur (default 5 detik).
- Bisa set timer untuk auto start atau auto stop.
- Bisa Mendukung multi akun Telegram.
