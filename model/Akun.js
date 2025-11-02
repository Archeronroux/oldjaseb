const { TelegramClient, Api } = require('telegram');
const { StringSession } = require('telegram/sessions');
const { API_ID, API_HASH, sessionsDir } = require('../config/setting');
const fs = require('fs');
const path = require('path');
const {
  mapBotEntitiesToGramjsSafe,
  summarizeEntities,
  splitCustomEmoji,
  entitiesToHTML
} = require('../utils/entities');
const STR = require('../config/strings');

const DEBUG = process.env.DEBUG_BROADCAST === '1';
const FORCE_HTML = process.env.FORCE_HTML === '1';

const debugFile = path.join(sessionsDir, 'debug.log');
function log(line) {
  if (!DEBUG) return;
  try { fs.appendFileSync(debugFile, new Date().toISOString() + ' ' + line + '\n'); } catch {}
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

    this.pendingCode = null;
    this.pendingPass = null;
    this.pendingMsgId = null;

    this._sourceCache = new Map();
    this.loadingMsgId = null;
    this._profileFetched = false;

    // Resume helpers
    this.lastBetweenTick = 0;
    this.lastAllTick = 0;
  }

  // ---- Helper logging internal ----
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
      { deviceModel: 'Android 15 Pro', systemVersion: 'Android 15', appVersion: '10.0.0' }
    );
  }

  async ensureClient() {
    try {
      if (!this.sess) return false;
      if (!this.client) await this.init();
      if (!this.client.connected) await this.client.connect();
      if (!this._profileFetched) {
        try {
          const me = await this.client.getMe();
            this.isPremium = !!me?.premium;
            this.name = this.name || me?.firstName || me?.username || 'User';
            this._profileFetched = true;
            log(`[PROFILE] uid=${this.uid} premium=${this.isPremium}`);
        } catch {}
      }
      return true;
    } catch (e) {
      console.error('[Akun.ensureClient] gagal connect:', e.message);
      return false;
    }
  }

  async _safeDeleteLoading(ctx) {
    if (this.loadingMsgId) {
      try { await ctx.api.deleteMessage(this.uid, this.loadingMsgId); } catch {}
      this.loadingMsgId = null;
    }
  }

  _resolveEffectIds() {
    const single = (process.env.WELCOME_EFFECT_ID || '').trim();
    const multi = (process.env.WELCOME_EFFECT_IDS || '').trim();
    if (multi) return multi.split(',').map(s => s.trim()).filter(Boolean);
    if (single) return [single];
    return [
      '5104841245755180586',
      '5046509860389126442',
      '5044134455711629726',
      '5064383411453188150'
    ];
  }

  async _sendWelcomeWithEffects(api, text) {
    const ids = this._resolveEffectIds();
    for (const id of ids) {
      try {
        await api.sendMessage(this.uid, text, { parse_mode: 'Markdown', message_effect_id: id });
        return true;
      } catch (e) { log(`[WELCOME_EFFECT_FAIL id=${id}] ${e.message}`); }
    }
    try {
      await api.sendMessage(this.uid, text, { parse_mode: 'Markdown' });
      return true;
    } catch (e) {
      console.error('[WELCOME_SEND_FAIL]', e.message);
      return false;
    }
  }

  async login(ctx, phone) {
    try {
      const loading = await ctx.reply('⏳ *Tunggu sebentar...*', { parse_mode: 'Markdown' });
      this.loadingMsgId = loading.message_id;
    } catch {}
    await this.init();
    if (!this.client) {
      await this._safeDeleteLoading(ctx);
      return ctx.reply('❌ Gagal init client.');
    }

    this.client.start({
      phoneNumber: () => phone,
      phoneCode: () => new Promise(r => {
        this.pendingCode = r;
        this._safeDeleteLoading(ctx);
        const { InlineKeyboard } = require('grammy');
        ctx.api.sendMessage(this.uid, STR.messages.otpInfo, {
          parse_mode: 'Markdown',
          reply_markup: new InlineKeyboard().text('❌ Batal', `cancel_${this.uid}`)
        }).then(msg => this.pendingMsgId = msg.message_id).catch(()=>{});
      }),
      password: () => new Promise(r => {
        this.pendingPass = r;
        this._safeDeleteLoading(ctx);
        const { InlineKeyboard } = require('grammy');
        ctx.api.sendMessage(this.uid, STR.messages.passwordAsk, {
          reply_markup: new InlineKeyboard().text('❌ Batal', `cancel_${this.uid}`)
        }).then(msg => this.pendingMsgId = msg.message_id).catch(()=>{});
      }),
      onError: e => {
        try { ctx.api.sendMessage(this.uid, `Error: ${e.message}`); } catch {}
      }
    }).then(async () => {
      try {
        this.sess = this.client.session.save();
        this.authed = true;
        const me = await this.client.getMe();
        this.name = me?.firstName || me?.username || 'User';
        this.isPremium = !!me?.premium;
        this._profileFetched = true;
        this.cleanup(ctx);
        await this._safeDeleteLoading(ctx);

        log(`[LOGIN] uid=${this.uid} premium=${this.isPremium}`);

        try {
          const { saveState } = require('../utils/persist');
          const { users } = require('../utils/helper');
          saveState(users);
        } catch (e) {
          console.error('[Akun.login] saveState error:', e.message);
        }

        const welcome = STR.messages.welcomeAuthed(this.name, 'Mati');
        await this._sendWelcomeWithEffects(ctx.api, welcome);

        const { mainMenu } = require('../utils/menu');
        const menu = mainMenu({ from: { id: this.uid, first_name: this.name } });
        await ctx.api.sendMessage(this.uid, menu.text, {
          reply_markup: menu.reply_markup,
          parse_mode: menu.parse_mode
        });

      } catch (e) {
        console.error('[Akun.login] success flow error:', e);
        try { await ctx.api.sendMessage(this.uid, '⚠️ Masalah setelah login: ' + (e.message || e)); } catch {}
      }
    }).catch(async (e) => {
      this.cleanup(ctx);
      await this._safeDeleteLoading(ctx);
      try { await ctx.api.sendMessage(this.uid, `❌ Login gagal: ${e.message}`); } catch {}
    });
  }

  cleanup(ctx) {
    if (this.pendingMsgId && ctx) {
      ctx.api.deleteMessage(this.uid, this.pendingMsgId).catch(() => {});
      this.pendingMsgId = null;
    }
  }

  handleText(text, ctx) {
    if (this.pendingCode) {
      try { this.pendingCode(text.replace(/\s+/g, '')); } catch {}
      this.pendingCode = null;
      this.cleanup(ctx);
      return true;
    }
    if (this.pendingPass) {
      try { this.pendingPass(text.trim()); } catch {}
      this.pendingPass = null;
      this.cleanup(ctx);
      return true;
    }
    return false;
  }

  cancel(ctx) {
    this.pendingCode = null;
    this.pendingPass = null;
    this.cleanup(ctx);
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

  scheduleStartStop() {
    if (this._autoStartTimer) {
      clearTimeout(this._autoStartTimer);
      this._autoStartTimer = null;
    }
    if (!this.startTime) return;
    const now = Date.now();
    const todayTs = this._timeToTimestamp(this.startTime);
    let targetTs = todayTs;
    if (!todayTs) return;
    if (todayTs <= now + 1500) targetTs = todayTs + 86400000;
    const waitMs = targetTs - now;
    this._autoStartTimer = setTimeout(() => {
      this._autoStartTimer = null;
      if (!this.running) {
        const { getBot } = require('../utils/helper');
        const botApi = getBot()?.api;
        this._doStart(botApi, { resume:false, manual:false });
      }
      this.scheduleStartStop();
    }, waitMs);
  }

  stop(manual=false) {
    this._clearTimers();
    if (manual) {
      this.stopTimestamp = null;
    }
    this.running = false;
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this._log('stop() dipanggil manual=', manual);
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

  async _sendEntities(targetPeer, text, rawEntities, tag) {
    if (FORCE_HTML) {
      const html = entitiesToHTML(text, rawEntities);
      log(`[FORCE_HTML] tag=${tag} htmlLen=${html.length}`);
      await this.client.sendMessage(targetPeer, { message: html, parseMode: 'html' });
      return 'HTML_FORCE';
    }
    const { clean, gram } = mapBotEntitiesToGramjsSafe(text, rawEntities);
    const { normal, custom } = splitCustomEmoji(clean);
    log(`[DISPATCH] tag=${tag} textLen=${text.length} ents=${clean.length} custom=${custom.length} premium=${this.isPremium} summary=${JSON.stringify(summarizeEntities(clean))}`);
    const attempts=[];
    if (this.isPremium===false && custom.length){
      const mappedNormal = mapBotEntitiesToGramjsSafe(text, normal).gram;
      attempts.push({mode:'NO_CUSTOM',ents:mappedNormal});
    } else {
      attempts.push({mode:'FULL',ents:gram});
      if(custom.length){
        const mappedNormal = mapBotEntitiesToGramjsSafe(text, normal).gram;
        attempts.push({mode:'NO_CUSTOM',ents:mappedNormal});
      }
    }
    attempts.push({mode:'HTML_FALLBACK', html: entitiesToHTML(text, clean)});
    attempts.push({mode:'PLAIN', ents:[]});
    for(const att of attempts){
      try{
        if(att.mode.startsWith('HTML'))
          await this.client.sendMessage(targetPeer,{message:att.html,parseMode:'html'});
        else
          await this.client.sendMessage(targetPeer,{message:text,entities:att.ents&&att.ents.length?att.ents:undefined});
        return att.mode;
      }catch(e){ log(`[FAIL] tag=${tag} mode=${att.mode} err=${e.message}`); }
    }
    throw new Error('ALL_MODES_FAILED');
  }

  async forwardOrCopy(msg, targetPeer, botApi, tag) {
    if (msg && typeof msg === 'object' && msg.html && typeof msg.text === 'string') {
      try {
        await this.client.sendMessage(targetPeer, { message: msg.text, parseMode: 'html' });
        this.stats.sent++;
      } catch (e) {
        this.stats.failed++; log(`[HTML_SEND_FAIL] ${e.message}`);
      }
      return;
    }
    if (msg && typeof msg === 'object' && typeof msg.text === 'string') {
      try { await this._sendEntities(targetPeer, msg.text, Array.isArray(msg.entities)?msg.entities:[], tag); this.stats.sent++; }
      catch(e){ this.stats.failed++; log(`[FATAL_SEND] tag=${tag} e=${e.message}`); }
      return;
    }
    if (typeof msg === 'string') {
      try { await this.client.sendMessage(targetPeer,{message:msg}); this.stats.sent++; }
      catch(e){ this.stats.failed++; log(`[PLAIN_FAIL] ${e.message}`); }
      return;
    }
    if (msg && typeof msg === 'object' && typeof msg.mid==='number' && msg.src!==undefined){
      try{
        const srcEnt=await this.getSourceEntity(msg.src);
        if(!srcEnt) throw new Error('SOURCE_NOT_JOINED');
        await this.client.forwardMessages(targetPeer,{fromPeer:srcEnt,messages:[msg.mid]});
        this.stats.sent++;
      }catch(e){
        log(`[FORWARD_FAIL] ${e.message} -> fallback copy`);
        try{
          await this._sendEntities(targetPeer, msg.text||'[Forward]', Array.isArray(msg.entities)?msg.entities:[], tag+'_FALLBACK');
          this.stats.sent++;
        }catch(e2){
          this.stats.failed++; log(`[FORWARD_FALLBACK_FAIL] ${e2.message}`);
        }
      }
      return;
    }
    try{
      await this.client.sendMessage(targetPeer,{message:msg?.preview||'[Pesan]'});
      this.stats.sent++;
    }catch(e){ this.stats.failed++; log(`[LEGACY_FAIL] ${e.message}`); }
  }

  async _tickStopCheck(botApi){
    if (this.stopTimestamp && Date.now() >= this.stopTimestamp) {
      this.stop();
      botApi && botApi.sendMessage(this.uid, STR.messages.stopAuto(this.stopTime)).catch(()=>{});
      return true;
    }
    return false;
  }

  /**
   * START BROADCAST (dengan dukungan manual override).
   * @param {*} botApi
   * @param {{manual?:boolean}} options
   * @returns {{ok:boolean,reason?:string}}
   */
  async start(botApi, options = {}) {
    const manual = !!options.manual;

    // Already running?
    if (this.running) {
      this._log('start(): already running');
      return { ok: false, reason: 'already_running' };
    }

    // Manual override: batalkan timer terjadwal jika ada.
    if (manual && this._startTimer) {
      clearTimeout(this._startTimer);
      this._startTimer = null;
      this._log('start(): manual override cleared _startTimer');
    }

    // Jika bukan manual dan masih ada _startTimer aktif -> tolak.
    if (!manual && this._startTimer) {
      this._log('start(): scheduled pending (not manual)');
      return { ok: false, reason: 'scheduled_pending' };
    }

    if (!this.msgs.length) return { ok:false, reason:'no_messages' };
    if (!this.targets.size && !this.all) return { ok:false, reason:'no_targets' };

    const okEnsure = await this.ensureClient();
    if (!okEnsure) return { ok:false, reason:'client_not_connected' };

    // Abaikan startTime bila manual
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

    // Langsung mulai
    this._doStart(botApi, { resume:false, manual });
    return { ok:true };
  }

  // INTERNAL DO START
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

  /**
   * Resume loop dari state (tanpa reset idx/msgIdx).
   */
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
    if(!(await this.ensureClient())){
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

  async verifyTargets({limit=Infinity, stopOnFlood=true} = {}){
    const summary={ total:this.targets.size, already:0, joined_new:0, failed:[], flood_wait:null };
    if(!(await this.ensureClient())){ summary.failed.push({reason:'CLIENT_NOT_CONNECTED'}); return summary; }
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
      if(!(await this.ensureClient())) throw new Error('CLIENT_NOT_CONNECTED');
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
