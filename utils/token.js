const zlib = require('zlib');

/**
 * SUPPORT: v5 (legacy JSON), v10 (binary+dictionary).
 * v10 + trimming:
 *  - Target index < TRIM_TAIL_AFTER  => selalu penuh.
 *  - Target index >= TRIM_TAIL_AFTER => field sesuai opsi env:
 *      TRIM_TAIL_ACCESS_HASH=1  -> access_hash diset 0 (dihilangkan)
 *      TRIM_TAIL_TITLE=1        -> judul tidak masuk (modeTitle=0) walau ada di dictionary
 *
 * ENV:
 *  TRIM_TAIL_AFTER        (default 15)
 *  TRIM_TAIL_ACCESS_HASH  (default 0)
 *  TRIM_TAIL_TITLE        (default 0)
 *  FULL_TOKEN=1           pakai v5 full JSON (tanpa trimming)
 */

 // ---------------- Varint (unsigned) ----------------
function encodeVarUint(n){
  n = BigInt(n);
  if (n < 0n) throw new Error('encodeVarUint: negative');
  const out=[];
  while(n >= 0x80n){
    out.push(Number((n & 0x7Fn) | 0x80n));
    n >>= 7n;
  }
  out.push(Number(n));
  return Buffer.from(out);
}
function decodeVarUint(buf, off){
  let res=0n, shift=0n, i=off;
  for(; i<buf.length; i++){
    const b=BigInt(buf[i]);
    res |= (b & 0x7Fn) << shift;
    if((b & 0x80n) === 0n){
      return { value: res, bytes: i-off+1 };
    }
    shift += 7n;
    if (shift > 70n) throw new Error('Varint too long');
  }
  throw new Error('EOF varint');
}
const encodeVarLen = encodeVarUint;
const decodeVarLen = decodeVarUint;

// --------------- Zigzag (signed) -------------------
function zigzagEncode(n){ n=BigInt(n); return n >= 0n ? (n<<1n) : ((~n<<1n)|1n); }
function zigzagDecode(z){ z=BigInt(z); return (z & 1n)===0n ? (z>>1n) : ~(z>>1n); }
function encodeVarInt(n){ return encodeVarUint(zigzagEncode(BigInt(n))); }
function decodeVarInt(buf, off){
  const { value, bytes } = decodeVarUint(buf, off);
  return { value: zigzagDecode(value), bytes };
}

// --------------- Base64url -------------------------
function toB64u(buf){
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function fromB64u(str){
  const pad = str.length%4===2?'==':str.length%4===3?'=':'';
  return Buffer.from(str.replace(/-/g,'+').replace(/_/g,'/')+pad,'base64');
}

// --------------- Entities --------------------------
const ENTITY_CODE = {
  bold:'b', italic:'i', underline:'u', strikethrough:'s', spoiler:'o',
  code:'c', pre:'p', text_link:'l', mention:'m', text_mention:'n',
  custom_emoji:'e', blockquote:'q', bot_command:'d', hashtag:'h',
  cashtag:'g', url:'r', email:'a', phone_number:'t'
};
const CODE_ENTITY = Object.fromEntries(Object.entries(ENTITY_CODE).map(([k,v])=>[v,k]));

// --------------- Helpers ---------------------------
function utf8Bytes(s){ return Buffer.from(s||'','utf8'); }
function utf8Decode(b){ return b.toString('utf8'); }
function normMsg(m){
  if(typeof m==='string') return {text:m, entities:[]};
  if(m && typeof m==='object' && typeof m.text==='string')
    return {text:m.text, entities:Array.isArray(m.entities)?m.entities:[]};
  return {text:'', entities:[]};
}
function normTarget(t){
  return { id:t.id, title:t.title, type:t.type, access_hash:t.access_hash };
}

// --------------- v5 Full JSON ----------------------
function generateFullV5(acc){
  const msgs = Array.isArray(acc.msgs)
    ? acc.msgs.map(m=>{
        if(typeof m==='string') return m;
        if(m && typeof m==='object'){
          if(m.src!==undefined && m.mid!==undefined){
            return {src:m.src,mid:m.mid,text:m.text,entities:Array.isArray(m.entities)?m.entities:[]};
          }
          if(typeof m.text==='string'){
            return {text:m.text,entities:Array.isArray(m.entities)?m.entities:[]};
          }
        }
        return m;
      })
    : [];
  const targets = acc.targets && typeof acc.targets.size==='number'
    ? Array.from(acc.targets.values()).map(t=>({
        id:t.id,
        title:t.title||String(t.id),
        type:t.type||null,
        access_hash:t.access_hash||null
      }))
    : [];
  return toB64u(Buffer.from(JSON.stringify({v:5,msgs,targets}),'utf8'));
}

// --------------- Generator v10 (dictionary + trimming) ---------------
function generateV10(acc){
  const TRIM_AFTER = parseInt(process.env.TRIM_TAIL_AFTER||'15',10);
  const TRIM_AH = process.env.TRIM_TAIL_ACCESS_HASH === '1';
  const TRIM_TITLE = process.env.TRIM_TAIL_TITLE === '1';

  const buffers=[];
  buffers.push(Buffer.from([0x0A])); // version

  // Messages
  const msgs = Array.isArray(acc.msgs)?acc.msgs:[];
  buffers.push(encodeVarLen(msgs.length));
  for(const raw of msgs){
    const m=normMsg(raw);
    const tb=utf8Bytes(m.text);
    buffers.push(encodeVarLen(tb.length), tb);
    const ents = Array.isArray(m.entities)?m.entities:[];
    buffers.push(encodeVarLen(ents.length));
    for(const e of ents){
      const code=ENTITY_CODE[e.type];
      if(!code) continue;
      buffers.push(Buffer.from(code));
      buffers.push(encodeVarLen(e.offset||0), encodeVarLen(e.length||0));
      let extra='';
      if(e.type==='text_link' && e.url) extra=e.url;
      else if(e.type==='text_mention' && e.user && e.user.id) extra=String(e.user.id);
      else if(e.type==='custom_emoji' && e.custom_emoji_id) extra=String(e.custom_emoji_id);
      else if(e.type==='pre' && e.language) extra=e.language;
      const eb=utf8Bytes(extra);
      buffers.push(encodeVarLen(eb.length));
      if(eb.length) buffers.push(eb);
    }
  }

  // Targets
  const targets = (acc.targets && typeof acc.targets.size==='number')
    ? Array.from(acc.targets.values()).map(normTarget)
    : [];
  buffers.push(encodeVarLen(targets.length));

  // Dictionary judul (untuk target >= TRIM_AFTER)
  const dict = [];
  const dictMap = new Map(); // title -> index
  let idx=0;

  for(const t of targets){
    // id
    try { buffers.push(encodeVarInt(BigInt(t.id))); } catch { buffers.push(encodeVarInt(0n)); }
    // type
    const typeCode = t.type==='channel'?'c':(t.type==='chat'?'g':'\x00');
    buffers.push(Buffer.from(typeCode));
    // access_hash
    let ahBI=0n;
    if(t.access_hash!==null && t.access_hash!==undefined && t.access_hash!==''){
      try { ahBI=BigInt(t.access_hash); } catch {}
    }
    if (idx >= TRIM_AFTER && TRIM_AH) {
      // pangkas access hash (set 0)
      buffers.push(encodeVarInt(0n));
    } else {
      buffers.push(encodeVarInt(ahBI));
    }

    // Title handling:
    // modeTitle:
    // 0 = no title (use id as title)
    // 1 = inline
    // 2 = dictionary ref
    const idStr = String(t.id);
    const realTitle = t.title && String(t.title)!==idStr ? String(t.title) : '';
    if (!realTitle) {
      buffers.push(encodeVarLen(0)); // mode 0
    } else {
      if (idx < TRIM_AFTER) {
        // simpan inline penuh
        buffers.push(encodeVarLen(1)); // mode 1
        const tb=utf8Bytes(realTitle);
        buffers.push(encodeVarLen(tb.length), tb);
      } else {
        if (TRIM_TITLE) {
          // Paksa hilang total (mode 0) – paling hemat
          buffers.push(encodeVarLen(0));
        } else {
          // dictionary
            if(!dictMap.has(realTitle)){
            dictMap.set(realTitle, dict.length);
            dict.push(realTitle);
          }
          const dIndex = dictMap.get(realTitle);
          buffers.push(encodeVarLen(2)); // mode 2
          buffers.push(encodeVarLen(dIndex));
        }
      }
    }
    idx++;
  }

  // Dump dictionary
  buffers.push(encodeVarLen(dict.length));
  for(const title of dict){
    const b=utf8Bytes(title);
    buffers.push(encodeVarLen(b.length), b);
  }

  const binary=Buffer.concat(buffers);
  let comp;
  try{
    comp = zlib.brotliCompressSync(binary, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } });
  }catch{
    comp = zlib.deflateSync(binary);
  }
  return toB64u(comp);
}

// --------------- Public Generator ------------------
function generateTokenFromAccount(acc){
  if (process.env.FULL_TOKEN === '1') return generateFullV5(acc);
  return generateV10(acc);
}

// --------------- Parser ----------------------------
function parseToken(str){
  const buf = fromB64u(str.trim());

  // Try v10 brotli
  let dec = tryBrotli(buf);
  if (dec && dec[0]===0x0A) return parseV10(dec);
  // Try v10 deflate
  dec = tryInflate(buf);
  if (dec && dec[0]===0x0A) return parseV10(dec);

  // Try legacy v5 direct JSON
  try{
    const txt = buf.toString('utf8');
    const d = JSON.parse(txt);
    if (d && Array.isArray(d.msgs) && Array.isArray(d.targets)) return d;
  }catch{}

  throw new Error('Token tidak valid / format tidak didukung');
}

function tryBrotli(b){
  try { return zlib.brotliDecompressSync(b); } catch { return null; }
}
function tryInflate(b){
  try { return zlib.inflateSync(b); } catch { return null; }
}

function parseV10(buf){
  let off=0;
  const ver = buf[off++]; if (ver!==0x0A) throw new Error('Bukan v10');
  function readVar(){ const {value,bytes}=decodeVarLen(buf,off); off+=bytes; return value; }
  function readVarInt(){ const {value,bytes}=decodeVarInt(buf,off); off+=bytes; return value; }
  function readBytes(n){
    if(off+Number(n)>buf.length) throw new Error('EOF');
    const sl=buf.slice(off, off+Number(n)); off+=Number(n); return sl;
  }

  const mCount = Number(readVar());
  const msgs=[];
  for(let i=0;i<mCount;i++){
    const lt = Number(readVar());
    const text = utf8Decode(readBytes(lt));
    const eCount = Number(readVar());
    const ents=[];
    for(let j=0;j<eCount;j++){
      const code = String.fromCharCode(buf[off++]);
      const type = CODE_ENTITY[code];
      const offset = Number(readVar());
      const length = Number(readVar());
      const extraLen = Number(readVar());
      let extra='';
      if(extraLen>0) extra=utf8Decode(readBytes(extraLen));
      const ent={type,offset,length};
      if(type==='text_link' && extra) ent.url=extra;
      else if(type==='text_mention' && extra) ent.user={id:extra};
      else if(type==='custom_emoji' && extra) ent.custom_emoji_id=extra;
      else if(type==='pre' && extra) ent.language=extra;
      ents.push(ent);
    }
    msgs.push({ text, entities:ents });
  }

  const tCount = Number(readVar());
  const rawTargets = [];
  for(let i=0;i<tCount;i++){
    const idBI = readVarInt();
    const id = idBI.toString();
    const typeByte = buf[off++];
    const type = typeByte===99?'channel':(typeByte===103?'chat':null);
    const ahBI = readVarInt();
    const access_hash = ahBI === 0n ? null : ahBI.toString();

    const modeTitle = Number(readVar());
    let title = id;
    if (modeTitle === 1) {
      const len = Number(readVar());
      title = utf8Decode(readBytes(len)) || id;
    } else if (modeTitle === 2) {
      const dictIndex = Number(readVar());
      // simpan placeholder; akan diisi setelah dictionary dibaca
      rawTargets.push({ id, type, access_hash, titleIndex: dictIndex, title: null });
      continue;
    }
    rawTargets.push({ id, type, access_hash, title, titleIndex: null });
  }

  // Dictionary
  const dictCount = Number(readVar());
  const dict=[];
  for(let i=0;i<dictCount;i++){
    const len=Number(readVar());
    dict.push(utf8Decode(readBytes(len)));
  }

  // Resolve dictionary titles
  for(const t of rawTargets){
    if (t.titleIndex!==null){
      const dTitle = dict[t.titleIndex];
      t.title = (dTitle && String(dTitle).length) ? dTitle : t.id;
      delete t.titleIndex;
    }
  }

  return { v:10, msgs, targets: rawTargets.map(t=>({
    id:t.id,
    title:t.title || t.id,
    type:t.type,
    access_hash:t.access_hash,
    entity:null
  })) };
}

module.exports = {
  generateTokenFromAccount,
  parseToken
};
