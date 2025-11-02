const { Api } = require('telegram');

/**
 * Sanitasi entities (clamp offset & length, urut stabil).
 */
function sanitizeBotEntities(text, entities) {
  if (!Array.isArray(entities)) return [];
  const max = typeof text === 'string' ? text.length : 0;
  return entities
    .map((e, i) => {
      const off = Math.max(0, Math.min(max, e.offset ?? 0));
      const len = Math.max(0, Math.min(max - off, e.length ?? 0));
      return len > 0 ? { ...e, offset: off, length: len, _i: i } : null;
    })
    .filter(Boolean)
    .sort((a, b) => a.offset - b.offset || a._i - b._i)
    .map(({ _i, ...e }) => e);
}

function summarizeEntities(entities) {
  return (entities || []).map(e => ({
    type: e.type,
    offset: e.offset,
    length: e.length,
    url: e.url,
    custom_emoji_id: e.custom_emoji_id,
    language: e.language
  }));
}

/**
 * Mapping Bot API → GramJS.
 */
function mapBotEntitiesToGramjs(cleanEntities) {
  const out = [];
  for (const e of cleanEntities) {
    const offset = e.offset ?? 0;
    const length = e.length ?? 0;
    switch (e.type) {
      case 'bold': out.push(new Api.MessageEntityBold({ offset, length })); break;
      case 'italic': out.push(new Api.MessageEntityItalic({ offset, length })); break;
      case 'underline': out.push(new Api.MessageEntityUnderline({ offset, length })); break;
      case 'strikethrough': out.push(new Api.MessageEntityStrike({ offset, length })); break;
      case 'spoiler': out.push(new Api.MessageEntitySpoiler({ offset, length })); break;
      case 'code': out.push(new Api.MessageEntityCode({ offset, length })); break;
      case 'pre': out.push(new Api.MessageEntityPre({ offset, length, language: e.language || '' })); break;
      case 'text_link':
        if (e.url) out.push(new Api.MessageEntityTextUrl({ offset, length, url: e.url }));
        break;
      case 'text_mention':
        if (e.user && e.user.id) {
          try { out.push(new Api.MessageEntityMentionName({ offset, length, userId: BigInt(e.user.id) })); } catch {}
        }
        break;
      case 'custom_emoji':
        if (e.custom_emoji_id) {
          try { out.push(new Api.MessageEntityCustomEmoji({ offset, length, documentId: BigInt(e.custom_emoji_id) })); } catch {}
        }
        break;
      case 'blockquote':
        try { out.push(new Api.MessageEntityBlockquote({ offset, length })); } catch {}
        break;
      case 'url': out.push(new Api.MessageEntityUrl({ offset, length })); break;
      case 'email': out.push(new Api.MessageEntityEmail({ offset, length })); break;
      case 'phone_number': out.push(new Api.MessageEntityPhone({ offset, length })); break;
      case 'mention': out.push(new Api.MessageEntityMention({ offset, length })); break;
      case 'hashtag': out.push(new Api.MessageEntityHashtag({ offset, length })); break;
      case 'cashtag': out.push(new Api.MessageEntityCashtag({ offset, length })); break;
      case 'bot_command': out.push(new Api.MessageEntityBotCommand({ offset, length })); break;
      default: break;
    }
  }
  return out;
}

function splitCustomEmoji(entities) {
  const normal = [];
  const custom = [];
  for (const e of entities) {
    if (e.type === 'custom_emoji') custom.push(e);
    else normal.push(e);
  }
  return { normal, custom };
}

/**
 * Build HTML fallback untuk parseMode: 'html'.
 * (Tidak bisa memunculkan custom_emoji.)
 */
function entitiesToHTML(text, entities) {
  if (!text) return '';
  const clean = sanitizeBotEntities(text, entities);
  const opens = {};
  const closes = {};
  const pushOpen = (i, tag) => { (opens[i] = opens[i] || []).push(tag); };
  const pushClose = (i, tag) => { (closes[i] = closes[i] || []).push(tag); };
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  for (const e of clean) {
    let openTag = null, closeTag = null;
    switch (e.type) {
      case 'bold': openTag='<b>'; closeTag='</b>'; break;
      case 'italic': openTag='<i>'; closeTag='</i>'; break;
      case 'underline': openTag='<u>'; closeTag='</u>'; break;
      case 'strikethrough': openTag='<s>'; closeTag='</s>'; break;
      case 'spoiler': openTag='<span class="tg-spoiler">'; closeTag='</span>'; break;
      case 'code': openTag='<code>'; closeTag='</code>'; break;
      case 'pre': openTag='<pre><code>'; closeTag='</code></pre>'; break;
      case 'text_link':
        if (e.url) { openTag = `<a href="${e.url.replace(/"/g,'&quot;')}">`; closeTag='</a>'; }
        break;
      case 'text_mention':
        if (e.user && e.user.id) {
          openTag=`<a href="tg://user?id=${e.user.id}">`; closeTag='</a>';
        }
        break;
      case 'blockquote':
        openTag='<blockquote>'; closeTag='</blockquote>'; break;
      default:
        break;
    }
    if (openTag) {
      pushOpen(e.offset, openTag);
      pushClose(e.offset + e.length, closeTag);
    }
  }

  let out = '';
  for (let i=0;i<text.length;i++){
    if (opens[i]) out += opens[i].join('');
    out += esc(text[i]);
    if (closes[i+1]) out += closes[i+1].reverse().join('');
  }
  if (closes[text.length]) out += closes[text.length].reverse().join('');
  return out;
}

function mapBotEntitiesToGramjsSafe(text, entities) {
  const clean = sanitizeBotEntities(text, entities);
  const gram = mapBotEntitiesToGramjs(clean);
  return { clean, gram };
}

module.exports = {
  sanitizeBotEntities,
  summarizeEntities,
  mapBotEntitiesToGramjsSafe,
  splitCustomEmoji,
  entitiesToHTML
};
