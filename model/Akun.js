const { TelegramClient, Api } = require('telegram');
const { StringSession } = require('telegram/sessions');
const { API_ID, API_HASH, sessionsDir } = require('../config/setting');
const fs = require('fs');
const path = require('path');
const {
  mapBotEntitiesToGramjsSafe,
  summarizeEntities,
  entitiesToHTML,
  htmlToTextAndEntities,
  sanitizeBotEntities
} = require('../utils/entities');
const STR = require('../config/strings');

const DEBUG = process.env.DEBUG_BROADCAST === '1';
const DEBUG_LOGIN = process.env.DEBUG_LOGIN === '1' || DEBUG;
const PREFER_PREMIUM = process.env.PREFER_PREMIUM !== '0';
const FORCE_HTML = process.env.FORCE_HTML !== '0';

const debugFile = path.join(sessionsDir, 'debug.log');
function log(line) {
  if (!DEBUG) return;
  try { fs.appendFileSync(debugFile, new Date().toISOString() + ' ' + line + '\n'); } catch {}
}
function ldbg(...a){ if (DEBUG_LOGIN) console.log('[LOGINDBG]', ...a); }

function withTimeout(promise, ms, label='op') {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`${label}_TIMEOUT_${ms}ms`)), ms))
  ]);
}

function parseMigrateDc(errMsg='') {
  const m = String(errMsg).match(/(PHONE|NETWORK|USER)_MIGRATE_(\d+)/i);
  return m ? Number(m[2]) : null;
}

class Akun {
  constructor(uid) {
    this.uid = uid;
    this.client = null;
    this.sess = '';
    this.name = '';
    this.isPremium = null;
    this.authed = false;

    this.msgs = [];
    this.targets = new Map();

    this.all = false;
    this.delayMode = 'antar';
    this.delay = 5;
    this.delayAllGroups = 20;

    this.startTime = null;
    this.stopTime = null;
    this.stopTimestamp = null;
    this._startTimer = null;
    this._stopTimer = null;
    this._autoStartTimer = null;

    this.running = false;
    this.timer = null;
    this.idx = 0;
    this.msgIdx = 0;

    this.stats = { sent: 0, failed: 0, skip: 0, start: 0 };

    // Login flow controls
    this.pendingCode = null;
    this.pendingPass = null;
    this.pendingMsgId = null;
    this.loadingMsgId = null;

    // queue OTP/Pass bila dikirim sebelum prompt siap
    this._queuedOtp = null;
    this._queuedOtpAt = 0;
    this._queuedPass = null;

    // resend controls (dimatikan)
    this._resendTimer = null;
    this._resendAttempts = 0;
    this._lastCodeHash = null;
    this._codeIssuedAt = 0;

    // flag sesi login sedang berlangsung (untuk router OTP global)
    this._loginInFlight = false;
    this._loginStartedAt = 0;

    this._sourceCache = new Map();
    this._profileFetched = false;

    this.lastBetweenTick = 0;
    this.lastAllTick = 0;

    this._lastPremiumCheck = 0;
    this._lastPersist = 0;
  }

  _log(...a) { if (DEBUG) console.log('[AKUN]', this.uid, ...a); }

  _lazyPersist() {
    try {
      if (this._lastPersist && Date.now() - this._lastPersist < 5000) return;
      this._lastPersist = Date.now();
      const { saveState } = require('../utils/persist');
      const { users } = require('../utils/helper');
      saveState(users);
    } catch {}
  }

  async init() {
    this.client = new TelegramClient(
      new StringSession(this.sess),
      API_ID,
      API_HASH,
      { deviceModel: 'Android 15 Pro', systemVersion: 'Android 15', appVersion: '10.0.0', useWSS: true, connectionRetries: 5 }
    );
  }

  _invalidateSession(hard=false) {
    try { this.client?.disconnect?.(); } catch {}
    this.client = null;
    if (hard) {
      this.sess = '';
      this.authed = false;
      this._profileFetched = false;
    }
    this._sourceCache = new Map();
    log(`[SESSION_${hard?'HARD':''}INVALIDATED] uid=${this.uid}`);
  }

  _isHardAuthError(e) {
    const m = String(e?.message || '').toUpperCase();
    return (
      m.includes('AUTH_KEY_UNREGISTERED') ||
      m.includes('SESSION_REVOKED') ||
      m.includes('SESSION_EXPIRED') ||
      m.includes('USER_DEACTIVATED')
    );
  }

  async ensureClient(opts = {}) {
    const refreshPremium = !!opts.refreshPremium;
    try {
      if (!this.sess) {
        this._invalidateSession(true);
        return false;
      }
      if (!this.client) await this.init();

      try {
        if (!this.client.connected) {
          await withTimeout(this.client.connect(), 8000, 'CONNECT');
        }
      } catch (e) {
        log(`[CONNECT_FAIL] ${e.message}`);
        this.client = null;
        return false;
      }

      const needProfile =
        !this._profileFetched ||
        refreshPremium ||
        (Date.now() - (this._lastPremiumCheck || 0) > 10 * 60 * 1000);

      if (needProfile) {
        try {
          const me = await withTimeout(this.client.getMe(), 6000, 'GET_ME');
          if (!me || !me.id) throw new Error('GET_ME_EMPTY');
          this.isPremium = !!me.premium;
          this.name = this.name || me.firstName || me.username || 'User';
          this._profileFetched = true;
          this._lastPremiumCheck = Date.now();
          this.authed = true;
          log(`[PROFILE] uid=${this.uid} premium=${this.isPremium}`);
        } catch (e) {
          log(`[PROFILE_FAIL] ${e.message}`);
          if (this._isHardAuthError(e)) {
            this._invalidateSession(true);
          } else {
            this._invalidateSession(false);
          }
          return false;
        }
      }
      return true;
    } catch (e) {
      console.error('[Akun.ensureClient] fatal:', e?.message || e);
      this._invalidateSession(false);
      return false;
    }
  }

  async _safeDeleteLoading(ctx) {
    if (this.loadingMsgId) {
      try { await ctx.api.deleteMessage(this.uid, this.loadingMsgId); } catch {}
      this.loadingMsgId = null;
    }
  }

  cleanup(ctx) {
    if (this.pendingMsgId && ctx) {
      ctx.api.deleteMessage(this.uid, this.pendingMsgId).catch(() => {});
      this.pendingMsgId = null;
    }
  }

  // TERPENTING: kalau OTP datang saat belum ada prompt, auto-queue agar tidak hilang.
  handleText(text, ctx) {
    const t = String(text || '').trim();

    if (this.pendingCode) {
      try { this.pendingCode(String(t).replace(/\s+/g, '')); } catch {}
      this.pendingCode = null;
      this.cleanup(ctx);
      return true;
    }
    if (this.pendingPass) {
      try { this.pendingPass(String(t).trim()); } catch {}
      this.pendingPass = null;
      this.cleanup(ctx);
      return true;
    }

    // Jika kelihatan OTP (3–8 digit, boleh spasi) dan prompt belum siap, simpan ke queue
    if (/^(\d\s*){3,8}$/.test(t) || /^\d{3,8}$/.test(t)) {
      this._queuedOtp = t.replace(/\D+/g, '');
      this._queuedOtpAt = Date.now();
      log('[LOGIN] QUEUE_OTP(handleText)');
      ldbg('handleText queued OTP=', this._queuedOtp);
      return true;
    }
    return false;
  }

  // Auto-resend dimatikan
  _startAutoResend() { /* disabled */ }
  _stopAutoResend() {
    if (this._resendTimer) { try { clearInterval(this._resendTimer); } catch {} }
    this._resendTimer = null;
    this._resendAttempts = 0;
  }

  cancel(ctx) {
    this.pendingCode = null;
    this.pendingPass = null;
    this._queuedOtp = null;
    this._queuedOtpAt = 0;
    this._queuedPass = null;
    this._lastCodeHash = null;
    this._codeIssuedAt = 0;
    this._stopAutoResend();
    this.cleanup(ctx);
    this._safeDeleteLoading(ctx);
  }

  // LOGIN FLOW: coba client.start() dulu; jika gagal → fallback manual (SendCode + SignIn)
  async login(ctx, phone) {
    const show = async (text) => {
      try { const m = await ctx.reply(text); this.loadingMsgId = m.message_id; } catch {}
      ldbg('UI:', text);
    };
    const clearLoading = async () => { await this._safeDeleteLoading(ctx); };
    const cancelKb = { inline_keyboard: [[{ text: 'Batal', callback_data: `cancel_${this.uid}` }]] };

    const manualFlow = async () => {
      const settings = new Api.CodeSettings({
        allowFlashcall: false,
        currentNumber: true,
        allowAppHash: true,
        allowMissedCall: false
      });

      // 1) SendCode (+ migrate DC bila perlu)
      try {
        const res = await withTimeout(
          this.client.invoke(new Api.auth.SendCode({
            phoneNumber: phone, apiId: API_ID, apiHash: API_HASH, settings
          })), 15_000, 'SEND_CODE'
        );
        this._lastCodeHash = res.phoneCodeHash;
        this._codeIssuedAt = Date.now();
        log('[LOGIN] SEND_CODE_OK');
        ldbg('SEND_CODE_OK hash set, issuedAt=', this._codeIssuedAt);
      } catch (e) {
        const dc = parseMigrateDc(e?.message || '');
        if (dc && typeof this.client._switchDC === 'function') {
          try { await this.client._switchDC(dc); log(`[LOGIN] switched DC → ${dc}`); ldbg('switch DC →', dc); } catch {}
          const res2 = await this.client.invoke(new Api.auth.SendCode({
            phoneNumber: phone, apiId: API_ID, apiHash: API_HASH, settings
          }));
          this._lastCodeHash = res2.phoneCodeHash;
          this._codeIssuedAt = Date.now();
          log('[LOGIN] SEND_CODE_OK(after migrate)');
          ldbg('SEND_CODE_OK(after migrate), issuedAt=', this._codeIssuedAt);
        } else {
          throw new Error('SEND_CODE_FAIL: ' + (e?.message || e));
        }
      }

      // 2) Tampilkan prompt OTP
      await clearLoading();
      this.cleanup(ctx);

      // Buang OTP antri yang lebih tua dari hash
      if (this._queuedOtp && this._queuedOtpAt && this._queuedOtpAt < this._codeIssuedAt) {
        ldbg('queued OTP is older than issuedAt — discard');
        this._queuedOtp = null;
        this._queuedOtpAt = 0;
      }

      if (!this._queuedOtp) {
        try {
          const msg = await ctx.reply(STR.messages.otpInfo, { parse_mode: 'Markdown', reply_markup: cancelKb });
          this.pendingMsgId = msg.message_id;
        } catch {}
        ldbg('ASK_OTP(manual)');
      } else {
        try {
          const m = await ctx.reply('⏳ Memverifikasi kode...');
          this.loadingMsgId = m.message_id;
        } catch {}
        ldbg('USE_QUEUED_OTP(manual) queuedAt=', this._queuedOtpAt, 'issuedAt=', this._codeIssuedAt);
      }

      // 3) Ambil OTP
      let otp = null;
      if (this._queuedOtp) {
        otp = this._queuedOtp;
        this._queuedOtp = null;
      } else {
        otp = await new Promise(resolve => {
          this.pendingCode = (code) => {
            log('[LOGIN] GOT_OTP(manual)');
            ldbg('GOT_OTP(manual) code=', code);
            (async () => { try { const m = await ctx.reply('⏳ Memverifikasi kode...'); this.loadingMsgId = m.message_id; } catch {} })();
            resolve(String(code).replace(/\D+/g, ''));
          };
        });
      }

      // 4) SignIn; bila 2FA → checkPassword
      try {
        await this.client.invoke(new Api.auth.SignIn({
          phoneNumber: phone, phoneCodeHash: this._lastCodeHash, phoneCode: otp
        }));
        log('[LOGIN] SIGN_IN_OK');
        ldbg('SIGN_IN_OK');
      } catch (e) {
        const msg = String(e?.message || '').toUpperCase();
        ldbg('SIGN_IN_FAIL', msg);
        if (msg.includes('SESSION_PASSWORD_NEEDED')) {
          await clearLoading();
          this.cleanup(ctx);
          let pwd = this._queuedPass;
          if (!pwd) {
            try {
              const m = await ctx.reply(STR.messages.passwordAsk, { reply_markup: cancelKb });
              this.pendingMsgId = m.message_id;
            } catch {}
            ldbg('ASK_PASS(manual)');
            pwd = await new Promise(resolve => { this.pendingPass = (p) => resolve(String(p).trim()); });
          }
          await this.client.checkPassword(pwd);
          log('[LOGIN] CHECK_PASSWORD_OK');
          ldbg('CHECK_PASSWORD_OK');
        } else if (msg.includes('PHONE_CODE_INVALID')) {
          await clearLoading();
          this.cleanup(ctx);
          await ctx.reply('❌ Kode OTP salah atau sudah tidak berlaku. Kirim ulang kode terbaru.');
          ldbg('PHONE_CODE_INVALID — prompt again');
          try {
            const msg2 = await ctx.reply(STR.messages.otpInfo, { parse_mode: 'Markdown', reply_markup: cancelKb });
            this.pendingMsgId = msg2.message_id;
          } catch {}
          const otp2 = await new Promise(resolve => { this.pendingCode = (code) => resolve(String(code).replace(/\D+/g, '')); });
          await this.client.invoke(new Api.auth.SignIn({
            phoneNumber: phone, phoneCodeHash: this._lastCodeHash, phoneCode: otp2
          }));
          log('[LOGIN] SIGN_IN_OK(retry)');
          ldbg('SIGN_IN_OK(retry)');
        } else {
          throw new Error('SIGN_IN_FAIL: ' + (e?.message || e));
        }
      }
    };

    try {
      // tandai sesi login in-flight
      this._loginInFlight = true;
      this._loginStartedAt = Date.now();

      // Siapkan client
      this.client = new TelegramClient(
        new StringSession(this.sess || ''),
        API_ID,
        API_HASH,
        { deviceModel: 'Android 15 Pro', systemVersion: 'Android 15', appVersion: '10.0.0', useWSS: true, connectionRetries: 5 }
      );
      await this.client.connect();

      await show('⏳ Mengirim OTP... Mohon tunggu sebentar.');

      // 1) Coba start(); jika gagal → manual
      const askOtp = async () => {
        await clearLoading();
        this.cleanup(ctx);

        // Abaikan OTP yang diqueue sebelum start()
        if (this._queuedOtp) ldbg('ignore queued OTP on start() to avoid stale code');
        this._queuedOtp = null;
        this._queuedOtpAt = 0;

        try {
          const msg = await ctx.reply(STR.messages.otpInfo, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: [[{ text: 'Batal', callback_data: `cancel_${this.uid}` }]] } });
          this.pendingMsgId = msg.message_id;
        } catch {}
        ldbg('ASK_OTP(start)');

        return await new Promise(resolve => {
          this.pendingCode = (code) => {
            log('[LOGIN] GOT_OTP(start)');
            ldbg('GOT_OTP(start) code=', code);
            (async () => {
              try {
                const m = await ctx.reply('⏳ Memverifikasi kode...');
                this.loadingMsgId = m.message_id;
              } catch {}
            })();
            resolve(String(code).replace(/\D+/g, ''));
          };
        });
      };
      const askPass = async () => {
        await clearLoading();
        this.cleanup(ctx);
        if (this._queuedPass) {
          ldbg('USE_QUEUED_PASS(start)');
          const p = this._queuedPass; this._queuedPass = null;
          return p;
        }
        try {
          const m = await ctx.reply(STR.messages.passwordAsk, { reply_markup: { inline_keyboard: [[{ text: 'Batal', callback_data: `cancel_${this.uid}` }]] } });
          this.pendingMsgId = m.message_id;
        } catch {}
        ldbg('ASK_PASS(start)');
        return await new Promise(resolve => {
          this.pendingPass = (pwd) => {
            ldbg('GOT_PASS(start)');
            resolve(String(pwd).trim());
          };
        });
      };

      try {
        await withTimeout(this.client.start({
          phoneNumber: async () => phone,
          phoneCode: askOtp,
          password: askPass,
          onError: (err) => { throw err; }
        }), 35_000, 'START');
      } catch (e) {
        const dc = parseMigrateDc(e?.message || '');
        if (dc && typeof this.client._switchDC === 'function') {
          try { await this.client._switchDC(dc); log(`[LOGIN] switched DC (start) → ${dc}`); ldbg('switch DC (start) →', dc); } catch {}
        }
        log(`[LOGIN] START_FAIL → manual: ${e?.message || e}`);
        ldbg('START_FAIL → manual', e?.message || e);
        await manualFlow();
      }

      // 2) Sukses login
      const session = this.client.session.save();
      this.sess = session;
      this.authed = true;

      try {
        const me = await this.client.getMe();
        this.name = me?.firstName || me?.username || 'User';
        this.isPremium = !!me?.premium;
        this._profileFetched = true;
      } catch {}

      // Bersih-bersih + persist
      this.cancel(ctx);
      try {
        const { saveState } = require('../utils/persist');
        const { users } = require('../utils/helper');
        saveState(users);
      } catch {}

      await ctx.reply(STR.messages.loginSuccess());
      log(`[LOGIN_OK] uid=${this.uid} phone=${phone}`);
      ldbg('LOGIN_OK');
    } catch (e) {
      log(`[LOGIN_FAIL] uid=${this.uid} err=${e?.message || e}`);
      ldbg('LOGIN_FAIL', e?.message || e);
      this._stopAutoResend();
      this.cancel(ctx);
      try { await ctx.reply('❌ Login gagal: ' + (e?.message || String(e))); } catch {}
      throw e;
    } finally {
      this._loginInFlight = false;
    }
  }

  botToInternal(botId) {
    try {
      const n = BigInt(botId);
      if (n >= 0n) return n;
      const abs = -n;
      if (String(abs).startsWith('100')) return abs - 1000000000000n;
      return abs;
    } catch { return null; }
  }

  async getSourceEntity(botApiChatId) {
    if (!(await this.ensureClient())) return null;
    if (this._sourceCache.has(botApiChatId)) return this._sourceCache.get(botApiChatId);
    const internal = this.botToInternal(botApiChatId);
    if (!internal) return null;
    try {
      const ent = await this.client.getEntity(internal);
      this._sourceCache.set(botApiChatId, ent);
      return ent;
    } catch { return null; }
  }

  stop() {
    try {
      this.running = false;
      this.stopTimestamp = null;
      if (this.timer) { try { clearInterval(this.timer); } catch {} this.timer = null; }
      if (this._startTimer) { try { clearTimeout(this._startTimer); } catch {} this._startTimer = null; }
      if (this._stopTimer) { try { clearTimeout(this._stopTimer); } catch {} this._stopTimer = null; }
      if (this._autoStartTimer) { try { clearTimeout(this._autoStartTimer); } catch {} this._autoStartTimer = null; }
    } catch {}
  }

  async _sendEntities(targetPeer, text, rawEntities, tag) {
    let baseEntities = sanitizeBotEntities(text, rawEntities || []);
    const { gram: gramFull } = mapBotEntitiesToGramjsSafe(text, baseEntities);
    const hasCustom = baseEntities.some(e => e.type === 'custom_emoji');
    const baseNoCustom = baseEntities.filter(e => e.type !== 'custom_emoji');
    const { gram: gramNoCustom } = mapBotEntitiesToGramjsSafe(text, baseNoCustom);

    log(`[DISPATCH] tag=${tag} len=${text?.length||0} ents=${baseEntities.length} custom=${hasCustom?1:0} premium=${this.isPremium} summary=${JSON.stringify(summarizeEntities(baseEntities))}`);

    const trySend = async (opts, label) => {
      try {
        await this.client.sendMessage(targetPeer, opts);
        log(`[SEND_OK] ${label} tag=${tag}`);
        return label;
      } catch (e) {
        log(`[SEND_FAIL] ${label} tag=${tag} err=${e.message}`);
        return { error: e };
      }
    };

    const prefetchCustomEmojiDocs = async () => {
      if (!hasCustom) return;
      try {
        const ids = [];
        for (const e of baseEntities) {
          if (e.type === 'custom_emoji' && e.custom_emoji_id) {
            try { ids.push(BigInt(e.custom_emoji_id)); } catch {}
          }
        }
        if (!ids.length) return;
        await this.client.invoke(new Api.messages.GetCustomEmojiDocuments({ id: ids }));
        log(`[PREFETCH_OK] docs=${ids.length}`);
      } catch (e) { log(`[PREFETCH_FAIL] ${e.message}`); }
    };

    const sendHtmlFallback = async (entitiesForHtml) => {
      if (!FORCE_HTML) return null;
      const html = entitiesToHTML(text, entitiesForHtml || baseNoCustom);
      return await trySend({ message: html, parseMode: 'html' }, 'HTML_FALLBACK');
    };

    if (this.isPremium && PREFER_PREMIUM) {
      await prefetchCustomEmojiDocs();
      if (Array.isArray(gramFull) && gramFull.length) {
        const res = await trySend({ message: text, entities: gramFull }, 'FULL_ENTITIES');
        if (res && !res.error) return 'FULL_ENTITIES';
        const em = String(res?.error?.message || '').toUpperCase();
        if (em.includes('CUSTOM_EMOJI_INVALID') || em.includes('EMOJI_INVALID')) {
          const res2 = await trySend({ message: text, entities: gramNoCustom }, 'NO_CUSTOM_RETRY');
          if (res2 && !res2.error) return 'NO_CUSTOM_RETRY';
          const res3 = await sendHtmlFallback(baseNoCustom);
          if (res3 && !res3.error) return 'HTML_FALLBACK';
        }
      }
      if (Array.isArray(gramNoCustom) && gramNoCustom.length) {
        const res = await trySend({ message: text, entities: gramNoCustom }, 'NO_CUSTOM_ENTITIES');
        if (res && !res.error) return 'NO_CUSTOM_ENTITIES';
      }
      const resH = await sendHtmlFallback(baseNoCustom);
      if (resH && !res.error) return 'HTML_FALLBACK';
    } else {
      if (Array.isArray(gramNoCustom) && gramNoCustom.length) {
        const res = await trySend({ message: text, entities: gramNoCustom }, 'NO_CUSTOM_ENTITIES');
        if (res && !res.error) return 'NO_CUSTOM_ENTITIES';
      }
      const resH = await sendHtmlFallback(baseNoCustom);
      if (resH && !res.error) return 'HTML_FALLBACK';
    }

    await this.client.sendMessage(targetPeer, { message: text });
    log(`[SEND_OK] PLAIN tag=${tag}`);
    return 'PLAIN';
  }

  async forwardOrCopy(msg, targetPeer, botApi, tag) {
    if (msg && typeof msg === 'object' && msg.src !== undefined && msg.mid !== undefined) {
      try {
        const srcKey = String(msg.src);
        const midNum = Number(msg.mid);
        if (!Number.isFinite(midNum) || midNum <= 0) throw new Error('MID_INVALID');
        const srcEnt = await this.getSourceEntity(srcKey);
        if (!srcEnt) throw new Error('SOURCE_NOT_RESOLVED');
        await this.client.forwardMessages(targetPeer, { fromPeer: srcEnt, messages: [midNum] });
        this.stats.sent++;
      } catch (e) {
        this.stats.failed++;
        log(`[FORWARD_FAIL][STRICT] ${e.message}`);
      }
      return;
    }

    if (msg && typeof msg === 'object') {
      try {
        if (msg.html === true && typeof msg.text === 'string') {
          const parsed = htmlToTextAndEntities(msg.text);
          msg = { text: parsed.text, entities: parsed.entities };
        }

        if (typeof msg.text === 'string') {
          await this._sendEntities(targetPeer, msg.text, Array.isArray(msg.entities) ? msg.entities : [], tag);
          this.stats.sent++;
          return;
        }
      } catch (e) {
        this.stats.failed++;
        log(`[FATAL_SEND] tag=${tag} e=${e.message}`);
        return;
      }
    }

    if (typeof msg === 'string') {
      try { await this.client.sendMessage(targetPeer, { message: msg }); this.stats.sent++; }
      catch (e) { this.stats.failed++; log(`[PLAIN_FAIL] ${e.message}`); }
      return;
    }

    try {
      await this.client.sendMessage(targetPeer, { message: msg?.preview || '[Pesan]' });
      this.stats.sent++;
    } catch (e) {
      this.stats.failed++;
      log(`[LEGACY_FAIL] ${e.message}`);
    }
  }

  async _tickStopCheck(botApi){
    if (this.stopTimestamp && Date.now() >= this.stopTimestamp) {
      this.stop();
      botApi && botApi.sendMessage(this.uid, STR.messages.stopAuto(this.stopTime)).catch(()=>{});
      return true;
    }
    return false;
  }

  async start(botApi, options = {}) {
    const manual = !!options.manual;

    if (this.running) {
      this._log('start(): already running');
      return { ok: false, reason: 'already_running' };
    }

    if (manual && this._startTimer) {
      clearTimeout(this._startTimer);
      this._startTimer = null;
      this._log('start(): manual override cleared _startTimer');
    }

    if (!manual && this._startTimer) {
      this._log('start(): scheduled pending (not manual)');
      return { ok: false, reason: 'scheduled_pending' };
    }

    if (!this.msgs.length) return { ok:false, reason:'no_messages' };
    if (!this.targets.size && !this.all) return { ok:false, reason:'no_targets' };

    const okEnsure = await this.ensureClient({ refreshPremium: true });
    if (!okEnsure) return { ok:false, reason:'client_not_connected' };

    if (!manual && this.startTime) {
      const ts = this._timeToTimestamp(this.startTime);
      if (ts && ts > Date.now() + 1500) {
        const waitMs = ts - Date.now();
        botApi && botApi.sendMessage(this.uid, STR.messages.startScheduled(this.startTime, waitMs / 60000));
        this._startTimer = setTimeout(() => {
          this._startTimer = null;
          this._doStart(botApi, { resume:false, manual:false });
        }, waitMs);
        return { ok: true, reason: 'scheduled_future' };
      }
    }

    this._doStart(botApi, { resume:false, manual });
    return { ok:true };
  }

  _timeToTimestamp(hhmm) {
    if (!/^([01]?\d|2[0-3]):([0-5]\d)$/.test(hhmm)) return null;
    const [h, m] = hhmm.split(':').map(n => parseInt(n, 10));
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate(), h, m, 0, 0).getTime();
  }

  _clearTimers() {
    if (this._startTimer) { clearTimeout(this._startTimer); this._startTimer = null; }
    if (this._stopTimer) { clearTimeout(this._stopTimer); this._stopTimer = null; }
    if (this._autoStartTimer) { clearTimeout(this._autoStartTimer); this._autoStartTimer = null; }
  }

  _doStart(botApi, { resume=false, manual=false } = {}) {
    if (this.running) return;
    this.running = true;
    this.stats = { sent: 0, failed: 0, skip: 0, start: Date.now() };
    this.idx = 0;
    this.msgIdx = 0;
    this.stopTimestamp = null;

    if (this.stopTime) {
      const st = this._timeToTimestamp(this.stopTime);
      if (st && st > Date.now()) {
        this.stopTimestamp = st;
        const diff = st - Date.now();
        this._stopTimer = setTimeout(() => {
          this.stop();
          botApi && botApi.sendMessage(this.uid, `🛑 Berhenti otomatis (Waktu Stop ${this.stopTime}).`);
        }, diff);
      } else {
        botApi && botApi.sendMessage(this.uid, `⚠️ Waktu Stop (${this.stopTime}) sudah lewat, diabaikan.`);
      }
    }

    if (this.delayMode === 'semua') {
      this._broadcastAllGroups(botApi);
      this._log('_doStart: mode=semua manual=', manual);
    } else {
      this._broadcastBetweenGroups(botApi);
      this._log('_doStart: mode=antar manual=', manual);
    }
  }

  resume(botApi) {
    if (this.running) return { ok:false, reason:'already_running' };
    if (!this.msgs.length || (!this.targets.size && !this.all))
      return { ok:false, reason:'insufficient_data' };
    this.running = true;
    if (!this.stats || !this.stats.start) this.stats = { sent:0, failed:0, skip:0, start: Date.now() };

    if (this.delayMode === 'semua') {
      this._broadcastAllGroups(botApi);
      this._log('resume(): loop semua');
    } else {
      this._broadcastBetweenGroups(botApi);
      this._log('resume(): loop antar');
    }
    return { ok:true };
  }

  _broadcastAllGroups(botApi){
    const tick=async ()=>{
      if(!this.running) return;
      if(await this._tickStopCheck(botApi)) return;
      if(!this.msgs.length || !this.targets.size){ this.stats.skip++; return; }
      if(this.msgIdx>=this.msgs.length) this.msgIdx=0;
      const msg=this.msgs[this.msgIdx++];
      const targets=Array.from(this.targets.values());
      for(const t of targets){
        let peer=this._getTargetPeer(t);
        if(!peer){
          try{
            const ent=await this.client.getEntity(t.id);
            t.entity=ent;
            if(ent.className==='Channel' && ent.accessHash){ t.type='channel'; t.access_hash=String(ent.accessHash); peer=this._getTargetPeer(t); }
            else if(ent.className==='Chat'){ t.type='chat'; peer=this._getTargetPeer(t); }
          }catch(e){
            this.stats.failed++; log(`[TARGET_RESOLVE_FAIL][ALL] id=${t.id} err=${e.message}`);
            continue;
          }
        }
        if(!peer){ this.stats.skip++; continue; }
        await this.forwardOrCopy(msg, peer, botApi, 'ALL');
      }
      this.lastAllTick = Date.now(); this._lazyPersist();
    };
    this.timer=setInterval(tick,this.delayAllGroups*60000);
    tick();
  }

  _broadcastBetweenGroups(botApi){
    const tick=async ()=>{
      if(!this.running) return;
      if(await this._tickStopCheck(botApi)) return;
      const targets=Array.from(this.targets.values());
      if(!targets.length || !this.msgs.length){ this.stats.skip++; return; }
      if(this.idx>=targets.length){ this.idx=0; this.msgIdx++; }
      if(this.msgIdx>=this.msgs.length) this.msgIdx=0;

      const t=targets[this.idx++];
      const msg=this.msgs[this.msgIdx];
      let peer=this._getTargetPeer(t);
      if(!peer){
        try{
          const ent=await this.client.getEntity(t.id);
          t.entity=ent;
          if(ent.className==='Channel' && ent.accessHash){ t.type='channel'; t.access_hash=String(ent.accessHash); peer=this._getTargetPeer(t); }
          else if(ent.className==='Chat'){ t.type='chat'; peer=this._getTargetPeer(t); }
          else { this.stats.skip++; return; }
        }catch(e){
          this.stats.failed++; log(`[TARGET_RESOLVE_FAIL][BETWEEN] id=${t.id} err=${e.message}`);
          return;
        }
      }
      await this.forwardOrCopy(msg, peer, botApi, 'BETWEEN');
      this.lastBetweenTick = Date.now(); this._lazyPersist();
    };
    this.timer=setInterval(tick,this.delay*1000);
    tick();
  }

  _getTargetPeer(t) {
    try {
      if (!t) return null;
      if (t.type === 'channel' && t.access_hash) {
        return new Api.InputPeerChannel({ channelId: BigInt(t.id), accessHash: BigInt(t.access_hash) });
      }
      if (t.type === 'chat') {
        return new Api.InputPeerChat({ chatId: BigInt(t.id) });
      }
      return null;
    } catch { return null; }
  }

  async _resolveLinkToEntity(link){
    if(!(await this.ensureClient())) throw new Error('CLIENT_NOT_CONNECTED');
    let t=link.trim();
    if(!/^https?:\/\//i.test(t)) t='https://'+t;
    const url=new URL(t);
    if(url.hostname!=='t.me') throw new Error('BUKAN_TME');
    if(url.pathname.startsWith('/c/')) throw new Error('LINK_POST');
    if(url.pathname.startsWith('/joinchat/') || url.pathname.startsWith('/+')){
      const hash = url.pathname.startsWith('/+') ? url.pathname.slice(2) : url.pathname.split('/joinchat/')[1];
      const cleanHash=(hash||'').split('?')[0];
      const info=await this.client.invoke(new Api.messages.CheckChatInvite({hash:cleanHash}));
      if(info.className==='ChatInviteAlready') return info.chat;
      if(info.className==='ChatInvite'){
        const upd=await this.client.invoke(new Api.messages.ImportChatInvite({hash:cleanHash}));
        return upd.chats?.[0];
      }
      throw new Error('INVITE_GAGAL');
    }
    const username=url.pathname.replace('/','').split('?')[0];
    if(!username) throw new Error('USERNAME_KOSONG');
    return await this.client.getEntity(username);
  }

  async _attemptJoin(entity){
    if(!entity) return {ok:false,error:'ENTITY_NULL'};
    if(entity.className==='Chat') return {ok:true,already:true};
    if(entity.className==='Channel'){
      try{
        await this.client.invoke(new Api.channels.JoinChannel({channel:entity}));
        return {ok:true,joined:true};
      }catch(e){
        const msg=(e.message||'').toUpperCase();
        if(msg.includes('USER_ALREADY_PARTICIPANT')) return {ok:true,already:true};
        if(msg.includes('FLOOD_WAIT')){
          const secs=parseInt(msg.split('_').pop(),10)||60;
          return {ok:false,floodWait:secs,error:'FLOOD_WAIT'};
        }
        return {ok:false,error:msg};
      }
    }
    return {ok:false,error:'TIPE_TIDAK_DIDUKUNG'};
  }

  _extractLinks(text){
    if(!text) return [];
    const re=/(?:https?:\/\/)?t\.me\/[^\s]+/gi;
    const out=[]; let m;
    while((m=re.exec(text))!==null) out.push(m[0]);
    return out;
  }

  async addTargets(text){
    if(!(await this.ensureClient({ refreshPremium: true }))){
      return { added:0, duplicates:[], invalid:[], errors:['CLIENT_NOT_CONNECTED'], joined_new:[], join_failed:[], flood_wait:[] };
    }
    const linksFound=this._extractLinks(text);
    const tokens=linksFound.length?linksFound:(text||'').split(/\s+/).filter(Boolean);

    let added=0;
    const duplicates=[], invalid=[], errors=[], join_failed=[], flood_wait=[], joined_new=[];
    const seen=new Set();

    for(const raw of tokens){
      if(seen.has(raw)) continue;
      seen.add(raw);
      try{
        let ent=null;
        if(linksFound.length){
          try{ ent=await this._resolveLinkToEntity(raw); }catch{ invalid.push(raw); continue; }
        } else {
          let t=raw.trim();
          if(/^https?:\/\/t\.me\//i.test(t)) { try{ ent=await this._resolveLinkToEntity(t);}catch{invalid.push(raw);continue;} }
          else if(t.startsWith('@')) { t=t.slice(1); try{ ent=await this.client.getEntity(t);}catch{invalid.push(raw);continue;} }
          else if(t.startsWith('+')||t.startsWith('joinchat/')){
            const hash=t.startsWith('+')?t.slice(1):t.split('joinchat/')[1];
            try{
              const info=await this.client.invoke(new Api.messages.CheckChatInvite({hash}));
              if(info.className==='ChatInviteAlready') ent=info.chat;
              else if(info.className==='ChatInvite'){ const upd=await this.client.invoke(new Api.messages.ImportChatInvite({hash})); ent=upd.chats?.[0]; }
              else { invalid.push(raw); continue; }
            }catch{ invalid.push(raw); continue; }
          } else if(/^[A-Za-z0-9_]{5,}$/.test(t)){
            try{ ent=await this.client.getEntity(t);}catch{invalid.push(raw);continue;}
          } else if(/^-?\d+$/.test(t)){
            try{ ent=await this.client.getEntity(BigInt(t)); }catch{ invalid.push(raw); continue; }
          } else if(/^t\.me\//i.test(t)){
            try{ ent=await this._resolveLinkToEntity('https://'+t);}catch{ invalid.push(raw); continue; }
          } else { invalid.push(raw); continue; }
        }

        if(!ent){ invalid.push(raw); continue; }
        if(!/Channel|Chat/i.test(ent.className)){ invalid.push(raw); continue; }

        const idStr=String(ent.id);
        if(this.targets.has(idStr)){
          duplicates.push(ent.title||ent.firstName||ent.username||idStr);
          continue;
        }

        const joinRes=await this._attemptJoin(ent);
        if(!joinRes.ok){
          if(joinRes.floodWait) { flood_wait.push({input:raw,seconds:joinRes.floodWait}); continue; }
          else { join_failed.push({input:raw,reason:joinRes.error}); continue; }
        } else if(joinRes.joined){
          joined_new.push(ent.title||ent.firstName||ent.username||idStr);
        }

        let type=null, access_hash=null;
        if(ent.className==='Channel' && ent.accessHash){ type='channel'; access_hash=String(ent.accessHash); }
        else if(ent.className==='Chat'){ type='chat'; }

        this.targets.set(idStr,{ id:ent.id, title:ent.title||ent.firstName||ent.username||idStr, type, access_hash, entity:ent });
        added++;
      }catch(e){
        errors.push(`${raw} (${e.message})`);
      }
    }

    return { added, duplicates, invalid, errors, joined_new, join_failed, flood_wait };
  }

  async verifyTargets({limit=Infinity, stopOnFlood=true} = {}) {
    const summary={ total:this.targets.size, already:0, joined_new:0, failed:[], flood_wait:null };
    if(!(await this.ensureClient({ refreshPremium: true }))){ summary.failed.push({reason:'CLIENT_NOT_CONNECTED'}); return summary; }
    let dialogs=[];
    try{ dialogs=await this.client.getDialogs(); }catch{}
    const have=new Set();
    for(const d of dialogs){
      try{
        const ent=d.entity;
        if(ent && (ent.className==='Channel' || ent.className==='Chat'))
          have.add(String(ent.id));
      }catch{}
    }
    let processed=0;
    for(const [idStr,tgt] of this.targets){
      if(processed>=limit) break;
      processed++;
      if(have.has(idStr)){ summary.already++; continue; }
      let entity=tgt.entity;
      let resolved=false;
      if(!entity){
        try{ entity=await this.client.getEntity(tgt.id); resolved=true; }catch{}
      }
      if(!resolved && !entity && tgt.type==='channel' && tgt.access_hash){
        try{
          entity=new Api.InputPeerChannel({channelId:BigInt(tgt.id),accessHash:BigInt(tgt.access_hash)});
          try{
            await this.client.invoke(new Api.channels.JoinChannel({channel:entity}));
            summary.joined_new++;
            try{ const fullEnt=await this.client.getEntity(tgt.id); tgt.entity=fullEnt; }catch{}
            continue;
          }catch(e){
            const msg=(e.message||'').toUpperCase();
            if(msg.includes('USER_ALREADY_PARTICIPANT')) { summary.already++; continue; }
            if(msg.includes('FLOOD_WAIT')){
              const secs=parseInt(msg.split('_').pop(),10)||60;
              summary.flood_wait=secs; if(stopOnFlood) break; continue;
            }
            summary.failed.push({id:tgt.id,title:tgt.title,reason:msg}); continue;
          }
        }catch(e2){
          summary.failed.push({id:tgt.id,title:tgt.title,reason:'PEER_BUILD_FAIL:'+e2.message});
          continue;
        }
      }
      if(entity){
        if(entity.className==='Chat' || entity.className==='InputPeerChat'){ summary.already++; tgt.entity=entity; continue; }
        try{
          await this.client.invoke(new Api.channels.JoinChannel({channel:entity}));
          summary.joined_new++; tgt.entity=entity;
        }catch(e){
          const msg=(e.message||'').toUpperCase();
          if(msg.includes('USER_ALREADY_PARTICIPANT')) summary.already++;
          else if(msg.includes('FLOOD_WAIT')){
            const secs=parseInt(msg.split('_').pop(),10)||60;
            summary.flood_wait=secs; if(stopOnFlood) break;
          } else summary.failed.push({id:tgt.id,title:tgt.title,reason:msg});
        }
      } else summary.failed.push({id:tgt.id,title:tgt.title,reason:'NO_ENTITY'});
    }
    return summary;
  }

  async addAll(){
    try{
      if(!(await this.ensureClient({ refreshPremium: true }))) throw new Error('CLIENT_NOT_CONNECTED');
      const dialogs=await this.client.getDialogs();
      dialogs.filter(d=>d.isGroup||d.isChannel).forEach(d=>{
        const ent=d.entity;
        const id=ent?.id ?? d.id;
        if(!id) return;
        let type=null, access_hash=null;
        if(ent?.className==='Channel' && ent?.accessHash){ type='channel'; access_hash=String(ent.accessHash); }
        else if(ent?.className==='Chat' || d.isGroup){ type='chat'; }
        this.targets.set(String(id), { id, title:d.title, type, access_hash, entity:ent||null });
      });
      return this.targets.size;
    }catch{ return 0; }
  }
}

module.exports = Akun;
