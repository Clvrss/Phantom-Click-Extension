/*
 * Phantom Click - content.js
 * Finds external HTML links, shows a Safe / Warning / Risky badge beside each one and a
 * hover/focus card with the score, indicators and recommendation.
 *
 * Workflow (SRS section 3.3): validate scheme -> local rules (preliminary badge) -> resolve redirect
 * in background.js -> re-check final URL -> optional AI follow-up -> cache.
 *
 * Privacy: reads only <a href> values. Never reads message text or other page content (NFR-15).
 */
(() => {
  'use strict';

  const R = self.PhantomRules;
  if (!R || window.__phantomClickLoaded) return;
  window.__phantomClickLoaded = true;

  const LABEL = { safe: 'Safe', warning: 'Warning', risky: 'Risky' };
  const CHECK_FAILED = "Couldn't check this link. Be careful.";
  const CACHE_TTL = 24 * 60 * 60 * 1000;   // OI-3: proposed lifetime 24 h
  const CACHE_FAIL_TTL = 5 * 60 * 1000;    // failed checks are retried sooner
  const CACHE_MAX = 1000;

  const ICONS = {
    safe: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/><path d="M8.5 12l2.5 2.5L15.5 9.5"/></svg>',
    warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.5L2.8 19.5h18.4z"/><path d="M12 10v4.5M12 17.4v.1"/></svg>',
    risky: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.6-3 8.4-7 10-4-1.6-7-5.4-7-10V6z"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/></svg>',
    logo: '<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#4f46e5"/><path d="M12 4.5l6 2.3v4.7c0 3.6-2.5 6.3-6 7.6-3.5-1.3-6-4-6-7.6V6.8z" fill="#fff"/><path d="M10.2 9.2v6l1.6-1.4 1.1 2.3 1.2-.5-1.1-2.3h2.1z" fill="#1e1b4b"/></svg>'
  };

  // ------------------------------------------------------------------ state
  let running = false;
  let excluded = [];
  let blocked = new Set();
  let cache = {};
  let cacheTimer = 0;

  const entries = new Map();        // <a> -> entry
  const byUrl = new Map();          // url -> Set(entry), to avoid duplicate badges for one result
  const dirty = new Set();          // anchors waiting to be (re)processed
  const inflightChecks = new Map(); // url -> shared job
  let mo = null, io = null, ui = null, scanTimer = 0, raf = 0, posTimer = 0;
  let current = null, pinned = false, hideTimer = 0;
  let cardPage = 'basic';          // 'basic' (page 1) or 'detail' (page 2)
  const detail = new Map();         // link -> detailed analysis state { state, summary, error, server }
  let dark = false;                 // toolbar switch: dark colours for the hover card
  let transparency = 0;             // toolbar slider: 0 (solid) to 80 (very see-through), in percent
  let urlvetOn = true;              // toolbar switch: use URLvet for the detailed analysis
  let iconOnly = false;             // toolbar setting: badges show only the status logo, no text
  let urlvetDownUntil = 0;          // after a failure, do not retry on its own for a minute

  // ---------------------------------------------------------------- helpers
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };
  const svg = (name) => {
    const t = document.createElement('template');
    t.innerHTML = ICONS[name];
    return t.content.firstChild;
  };
  const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return u; } };
  const isExcluded = (host) => excluded.some((d) => host === d || host.endsWith('.' + d));

  function send(msg, waitMs) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), waitMs || 12000);
      try {
        chrome.runtime.sendMessage(msg).then(
          (r) => { clearTimeout(timer); resolve(r || null); },
          () => { clearTimeout(timer); resolve(null); }
        );
      } catch (e) { clearTimeout(timer); resolve(null); }
    });
  }

  // ------------------------------------------------------------------ cache
  let lastLists = { safe: '', phishing: '' };
  // the list bundled with the extension plus the newest list from the feed backend
  const mergeFeed = (l, key) => ((l.snapshot && l.snapshot[key]) || []).concat((l.feed && l.feed[key]) || []);
  let listSig = '0';   // changes whenever the .txt lists change, so old results are never reused
  const cacheSig = () => chrome.runtime.getManifest().version + '|' + listSig;
  const hashText = (t) => { let h = 5381; for (let i = 0; i < t.length; i++) h = ((h << 5) + h + t.charCodeAt(i)) | 0; return (h >>> 0).toString(36) + t.length; };
  function resetCache() {
    cache = {};
    clearTimeout(cacheTimer);
    try { chrome.storage.local.set({ cache: {}, cacheSig: cacheSig() }); } catch (e) { /* ignore */ }
  }

  function cacheGet(url) {
    const e = cache[url];
    if (!e) return null;
    if (Date.now() - e.ts > (e.phase === 'failed' ? CACHE_FAIL_TTL : CACHE_TTL)) { delete cache[url]; return null; }
    return e;
  }
  function cachePut(url, res) {
    cache[url] = { rules: res.rules, phase: res.phase, finalUrl: res.finalUrl, failMsg: res.failMsg, note: res.note, ts: Date.now() };
    clearTimeout(cacheTimer);
    cacheTimer = setTimeout(() => {
      const keys = Object.keys(cache);
      if (keys.length > CACHE_MAX) {
        keys.sort((a, b) => cache[a].ts - cache[b].ts).slice(0, keys.length - CACHE_MAX).forEach((k) => delete cache[k]);
      }
      try { chrome.storage.local.set({ cache, cacheSig: cacheSig() }); } catch (e) { /* extension reloaded */ }
    }, 1000);
  }

  // ------------------------------------------------------------ result view
  // Turns a result into what the badge and card display (FR-15..FR-19, FR-30).
  function view(res) {
    const s = R.scoreFrom(res.rules.map((r) => r.id));
    const failed = res.phase === 'failed' || res.phase === 'unsupported';
    // A link that could not be checked is never Safe: it carries at least the "unfamiliar" score.
    const score = failed ? Math.max(s.score, R.CONFIG.failedCheckScore) : s.score;
    let status = R.statusFromScore(score);
    let score2 = score;
    const showScore = true;
    let tag = '';
    if (res.phase === 'preliminary') tag = 'preliminary';
    let rec;
    if (status === 'risky') rec = 'Avoid opening this link.';
    else if (failed) rec = CHECK_FAILED;
    else if (status === 'safe') rec = 'No obvious risk found. Open it only if you expect it.';
    else if (res.rules.some((r) => r.id === 'R-02')) rec = 'Unfamiliar website. Only open it if you trust where the link came from.';
    else rec = 'Be careful before opening.';
    return { status, score: score2, showScore, tag, rec, failed };
  }

  // ------------------------------------------------------------- UI (shadow)
  function makeHost(extraStyle) {
    const host = document.createElement('phantom-click-root');
    host.style.cssText = 'all:initial;width:0;height:0;overflow:visible;pointer-events:none;visibility:hidden;' + extraStyle;
    const shadow = host.attachShadow({ mode: 'closed' });
    const css = document.createElement('link');
    css.rel = 'stylesheet';
    css.href = chrome.runtime.getURL('content.css');
    const reveal = () => { host.style.visibility = 'visible'; };
    css.addEventListener('load', reveal);
    setTimeout(reveal, 1500);
    return { host, shadow, css };
  }

  // Two layers:
  //  - docLayer: absolute, scrolls WITH the page (no lag while scrolling) and has a low z-index,
  //    so page headers and overlays naturally cover the badges.
  //  - fixedLayer + card: fixed on top. Used for links inside fixed/sticky bars and inner scroll areas.
  function ensureUI() {
    if (ui) return ui;
    const d = makeHost('position:absolute;top:0;left:0;z-index:1;');
    const t = makeHost('position:fixed;top:0;left:0;z-index:2147483647;');
    const docLayer = el('div', 'pc-layer');
    const fixedLayer = el('div', 'pc-layer');
    const card = el('div'); card.id = 'card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-label', 'Phantom Click link details');
    card.tabIndex = -1;
    card.addEventListener('mouseenter', () => clearTimeout(hideTimer));
    card.addEventListener('mouseleave', scheduleHide);
    card.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideCard(true, true); });
    d.shadow.append(d.css, docLayer);
    t.shadow.append(t.css, fixedLayer, card);
    document.documentElement.append(d.host, t.host);
    ui = { hosts: [d.host, t.host], docLayer, fixedLayer, card };
    applyCompact();
    return ui;
  }

  function applyCompact() {
    if (!ui) return;
    ui.card.classList.toggle('pc-dark', dark);
    [ui.docLayer, ui.fixedLayer].forEach((layer) => {
      layer.classList.toggle('pc-compact', iconOnly);
      layer.style.setProperty('--pc-opacity', String(1 - transparency / 100));
    });
  }

  function createBadge(ent) {
    const b = el('button', 'pc-badge');
    b.type = 'button';
    b.addEventListener('mouseenter', () => showCard(ent, false));
    b.addEventListener('mouseleave', scheduleHide);
    b.addEventListener('focus', () => showCard(ent, false));
    b.addEventListener('blur', scheduleHide);
    b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); toggleDetail(ent); });
    b.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideCard(true, true); });
    (ent.mode === 'doc' ? ensureUI().docLayer : ensureUI().fixedLayer).appendChild(b);
    ent.badge = b;
  }

  function updateBadge(ent) {
    const b = ent.badge;
    if (!b || !ent.result) return;
    const v = view(ent.result);
    const isBlocked = blocked.has(ent.url);
    if (ent.shown !== v.status) {
      b.textContent = '';
      const sizer = el('span', 'pc-sizer');
      sizer.setAttribute('aria-hidden', 'true');
      sizer.append(el('i'), el('span', 'pc-sizer-label'));
      const pill = el('span', 'pc-pill');
      pill.append(svg(v.status), el('span', 'pc-label'));
      b.append(sizer, pill);
      ent.shown = v.status;
    }
    const text = LABEL[v.status] + (isBlocked ? ' \u00b7 Blocked' : '');
    b.querySelector('.pc-label').textContent = text;
    b.querySelector('.pc-sizer-label').textContent = text;
    b.className = 'pc-badge pc-on pc-' + v.status + (ent.result.phase === 'preliminary' ? ' pc-pending' : '') + (current === ent ? ' pc-open' : '') + (isBlocked ? ' pc-isblocked' : '');
    b.setAttribute('aria-label', 'Phantom Click: ' + LABEL[v.status] + (isBlocked ? ', blocked' : '') +
      '. Press Enter for details about this link.');
    schedulePosition();
  }

  // ----------------------------------------------------------- hover/focus card (two pages)
  // Page 1 (hover or focus): fast result from the local rules. Page 2 (click the badge or "More Detail
  // analysis"): explanation of every rule, plus the detailed URLvet analysis, which is only requested then.
  const ERROR_TEXT = {
    disabled: 'Detailed analysis is turned off. Turn it on in the Phantom Click toolbar menu.',
    not_configured: 'The analysis server address is not valid.',
    unreachable: 'The analysis server could not be reached.',
    timeout: 'The analysis server did not answer in time.',
    rate_limited: 'The analysis server is busy. Try again in a minute.',
    bad_response: 'The analysis server sent an answer Phantom Click could not read.'
  };
  const VERDICT_CLASS = { Safe: 'safe', Suspicious: 'warning', Risky: 'risky' };

  function finalDomain(ent) {
    const d = detail.get(ent.url);
    if (d && d.state === 'done' && d.summary.finalUrl) return hostOf(d.summary.finalUrl);
    const res = ent.result;
    if (res.phase === 'preliminary') return 'Checking\u2026';
    if (res.phase === 'failed' || res.phase === 'unsupported') return 'Not available';
    return res.finalUrl ? hostOf(res.finalUrl) : hostOf(ent.url);
  }

  function cardHead(ent, v) {
    const head = el('div', 'pc-head');
    const logo = svg('logo'); logo.setAttribute('class', 'pc-logo');
    head.append(logo, el('div', 'pc-title', 'Phantom Click'));
    if (v.status !== 'safe' && ent.kind === 'check') {        // FR-33: Block URL for Warning and Risky
      const isBlocked = blocked.has(ent.url);
      const bb = el('button', 'pc-block' + (isBlocked ? ' pc-blocked' : ''), isBlocked ? 'Unblock URL' : 'Block URL');
      bb.type = 'button';
      bb.addEventListener('click', () => toggleBlock(ent));
      head.append(bb);
    }
    return head;
  }

  const TYPE_TEXT = { link: 'HTML link', image: 'Image link', button: 'Button' };
  function cardMeta(ent, showFinal) {
    const dl = el('dl', 'pc-meta');
    dl.append(el('dt', null, 'Checked type'), el('dd', null, TYPE_TEXT[ent.src] || 'HTML link'));
    dl.append(el('dt', null, 'Checked domain'), el('dd', null, ent.kind === 'check' ? hostOf(ent.url) : ent.url || 'Unknown'));
    if (showFinal) dl.append(el('dt', null, 'Final domain'), el('dd', null, finalDomain(ent)));
    return dl;
  }

  function button(cls, label, onClick) {
    const b = el('button', cls, label);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  function renderBasic(card, ent, v) {
    const res = ent.result;
    const st = el('div', 'pc-status pc-' + v.status);
    st.append(svg(v.status), el('div', 'pc-status-name', LABEL[v.status]));
    const sc = el('div', 'pc-score');
    sc.append(el('span', 'pc-score-label', 'Risk score'));
    sc.append(el('span', 'pc-score-value', v.showScore ? v.score + '%' : '\u2014'));
    if (v.showScore && v.tag) sc.append(el('span', 'pc-score-tag', v.tag));
    st.append(sc);
    card.append(st, cardMeta(ent, false), el('div', 'pc-suggest', v.rec));

    card.append(el('h3', 'pc-section', 'Analysis detection'));
    if (res.rules.length) {
      const ul = el('ul', 'pc-chips');
      byRisk(res.rules).forEach((r) => {
        const high = r.severity === 'high';
        const li = el('li', 'pc-det ' + (high ? 'pc-det-high' : 'pc-det-med'));
        const ico = el('span', 'pc-det-ico', '!');
        const tip = high ? 'High' : 'Medium';
        ico.dataset.tip = tip; ico.tabIndex = 0; ico.setAttribute('role', 'img'); ico.setAttribute('aria-label', tip);
        li.append(el('span', 'pc-det-title', r.title), ico);
        ul.append(li);
      });
      card.append(ul);
    } else if (res.phase === 'unsupported') {
      card.append(el('p', 'pc-note', res.msg));
    } else if (res.phase === 'failed') {
      card.append(el('p', 'pc-note', 'No risk indicator was found in the link itself.'));
    } else {
      card.append(el('p', 'pc-note', 'No obvious risk indicator was found.'));
    }
    if (res.phase === 'preliminary') card.append(el('p', 'pc-note pc-loading', 'Checking where this link leads\u2026 this result is preliminary.'));
    if (res.phase === 'failed') card.append(el('p', 'pc-note', CHECK_FAILED + ' ' + (res.failMsg || '')));
    if (res.note) card.append(el('p', 'pc-note', res.note));
    if (blocked.has(ent.url)) card.append(el('p', 'pc-note', 'This link is blocked on this page and will not open.'));
    card.append(button('pc-more', 'More Detail analysis', () => goDetail(ent)));
  }

  function listBlock(items, cls) {
    const ul = el('ul', 'pc-bullets ' + cls);
    items.forEach((t) => ul.append(el('li', null, t)));
    return ul;
  }

  // Top of page 2: the URLvet state (loading, unavailable, or the verdict), so it is visible without scrolling.
  function renderUrlvetStatus(box, ent) {
    box.append(el('h4', 'pc-sub', 'Detailed analysis (URLvet)'));
    const d = detail.get(ent.url);
    if (ent.kind !== 'check') {
      box.append(el('p', 'pc-note', 'Detailed analysis is not available for this type of link.'));
      return;
    }
    if (!d || d.state === 'loading') {
      const row = el('p', 'pc-note pc-loading');
      row.append(el('span', 'pc-spin'), document.createTextNode('Analysing\u2026 this can take up to 15 seconds.'));
      box.append(row);
      return;
    }
    if (d.state === 'error' && d.error === 'disabled') {
      box.append(el('p', 'pc-note', ERROR_TEXT.disabled));
      return;
    }
    if (d.state === 'error') {
      box.append(el('p', 'pc-note pc-bad-text', 'Detailed analysis unavailable.'));
      box.append(el('p', 'pc-note', ERROR_TEXT[d.error] || (/^http_/.test(d.error) ? 'The analysis server returned an error (' + d.error.slice(5) + ').' : ERROR_TEXT.bad_response)));
      box.append(button('pc-retry', 'Try again', () => { requestDetail(ent, true); renderCard(ent); }));
      return;
    }
    const u = d.summary;
    const verdict = el('div', 'pc-verdict pc-' + (VERDICT_CLASS[u.verdict] || 'warning'));
    verdict.append(el('strong', null, 'URLvet verdict: ' + u.verdict));
    if (u.score != null) verdict.append(el('span', null, 'Risk score ' + Math.max(0, Math.min(100, 100 - u.score)) + '/100 (lower is safer)'));
    box.append(verdict);
    if (u.incomplete) {
      box.append(el('p', 'pc-note', 'Some checks did not finish' + (u.incompleteChecks.length ? ' (' + u.incompleteChecks.join(', ') + ')' : '') + '. Treat this verdict with care.'));
    }
  }

  // After the Phantom Click checks: what URLvet found (only when the analysis succeeded).
  function renderUrlvetBody(box, ent) {
    const d = detail.get(ent.url);
    if (!d || d.state !== 'done') return;
    const u = d.summary;
    box.append(el('h4', 'pc-sub', 'Redirect chain'));
    if (u.chain.length > 1) {
      const ol = el('ol', 'pc-chain');
      u.chain.forEach((hop, i) => ol.append(el('li', i === u.chain.length - 1 ? 'pc-final' : null, hop)));
      box.append(ol);
      if (u.domainJump) box.append(el('p', 'pc-note', 'The link ends on a different site than it started on.'));
    } else {
      box.append(el('p', 'pc-note', 'No redirects were followed.'));
    }
    if (u.bad.length || u.neutral.length || u.good.length) {
      box.append(el('h4', 'pc-sub', 'What was found'));
      if (u.bad.length) box.append(listBlock(u.bad, 'pc-lv-bad'));
      if (u.neutral.length) box.append(listBlock(u.neutral, 'pc-lv-neutral'));
      if (u.good.length) box.append(listBlock(u.good, 'pc-lv-good'));
    }
    if (u.flags.length) {
      box.append(el('h4', 'pc-sub', 'Page and site checks'));
      const ul = el('ul', 'pc-bullets');
      u.flags.forEach((f) => ul.append(el('li', 'pc-lv-' + f.level, f.text)));
      box.append(ul);
    }
    if (u.facts.length) {
      const dl = el('dl', 'pc-facts');
      u.facts.forEach(([k, val]) => dl.append(el('dt', null, k), el('dd', null, val)));
      box.append(dl);
    }
    if (u.googleAttribution) box.append(el('p', 'pc-fine', 'Advisory provided by Google'));
    box.append(el('p', 'pc-fine', 'Analysed by URLvet at ' + (d.server || 'the analysis server') + '. Only this link\u2019s address was sent.'));
  }

  // the most serious finding first (a known phishing domain before "not encrypted")
  const byRisk = (rules) => rules.slice().sort((a, b) => (b.severity === 'high') - (a.severity === 'high') || b.weight - a.weight);

  function renderDetail(card, ent, v) {
    card.append(cardMeta(ent, true));
    card.append(el('h3', 'pc-section', 'Analysis explanation'));
    const box = el('div', 'pc-explain');
    box.tabIndex = 0;

    renderUrlvetStatus(box, ent);

    // Phantom Click rules
    box.append(el('h4', 'pc-sub', 'Phantom Click checks'));
    const sum = el('div', 'pc-verdict pc-' + v.status);
    sum.append(el('strong', null, LABEL[v.status] + (v.showScore ? ' \u00b7 ' + v.score + '%' : '')),
      el('span', null, v.failed && v.status !== 'risky' ? 'Not verified: the destination could not be checked.' : v.rec));
    box.append(sum);
    const res = ent.result;
    if (res.rules.length) {
      const ul = el('ul', 'pc-list');
      byRisk(res.rules).forEach((r) => {
        const li = el('li');
        li.append(el('strong', null, r.title), el('span', null, r.explanation));
        ul.append(li);
      });
      box.append(ul);
    } else {
      box.append(el('p', 'pc-note', res.phase === 'unsupported' ? res.msg : 'No risk indicator was found in the link itself.'));
    }
    if (res.phase === 'failed') box.append(el('p', 'pc-note', CHECK_FAILED + ' ' + (res.failMsg || '')));
    if (res.note) box.append(el('p', 'pc-note', res.note));

    renderUrlvetBody(box, ent);
    card.append(box);
    card.append(button('pc-prev', 'Previous Page', () => goBasic(ent)));
  }

  function renderCard(ent) {
    const card = ensureUI().card;
    const old = card.querySelector('.pc-explain');
    const keepScroll = old ? old.scrollTop : 0;
    const v = view(ent.result);
    card.textContent = '';
    card.dataset.page = cardPage;
    card.append(cardHead(ent, v));
    if (cardPage === 'detail') renderDetail(card, ent, v); else renderBasic(card, ent, v);
    const box = card.querySelector('.pc-explain');
    if (box && keepScroll) box.scrollTop = keepScroll;
  }

  // Asks the URLvet server for the detailed report. Only ever called from page 2, so the badge and
  // page 1 never wait for it.
  function requestDetail(ent, force) {
    if (ent.kind !== 'check') return;
    const d = detail.get(ent.url);
    if (d && (d.state === 'loading' || d.state === 'done')) return;
    if (!urlvetOn) { detail.set(ent.url, { state: 'error', error: 'disabled' }); return; }
    if (d && d.state === 'error' && d.error !== 'disabled' && !force && Date.now() < urlvetDownUntil) return;
    detail.set(ent.url, { state: 'loading' });
    send({ type: 'urlvet', url: ent.url }, 25000).then((r) => {
      if (r && r.ok) {
        detail.set(ent.url, { state: 'done', summary: r.summary, server: r.server });
      } else {
        detail.set(ent.url, { state: 'error', error: (r && r.error) || 'unreachable' });
        urlvetDownUntil = Date.now() + 60000;
      }
      updateBadge(ent);
      if (current && current.url === ent.url && ui && ui.card.classList.contains('pc-open')) {
        renderCard(current);
        placeCard(current);
      }
    });
  }

  function goDetail(ent) {
    cardPage = 'detail';
    pinned = true;                 // stays open while you read
    renderCard(ent);
    placeCard(ent);
    requestDetail(ent, false);
    renderCard(ent);               // show the loading state straight away
    placeCard(ent);
    ensureUI().card.focus({ preventScroll: true });
  }
  function goBasic(ent) {
    cardPage = 'basic';
    renderCard(ent);
    placeCard(ent);
    ensureUI().card.focus({ preventScroll: true });
  }
  // Clicking the badge flips between the two pages (the first click opens page 2).
  function toggleDetail(ent) {
    const open = current === ent && ui && ui.card.classList.contains('pc-open');
    if (!open) showCard(ent, false);
    if (open && cardPage === 'detail') goBasic(ent); else goDetail(ent);
  }

  const ICON_W = 25, ICON_H = 20;   // size of the badge once the text tag has collapsed
  function iconBox(ent) {
    const r = (ent.badge && ent.on ? ent.badge : ent.a).getBoundingClientRect();
    return { l: r.left, t: r.top, r: r.left + ICON_W, b: r.top + ICON_H };
  }

  // The card sits beside the status logo (right side by default), logo at its top-left corner;
  // near the screen edges it flips so the logo is at the bottom-left, top-right or bottom-right.
  function placeCard(ent) {
    const card = ensureUI().card;
    const box = iconBox(ent);
    const cw = document.documentElement.clientWidth, ch = document.documentElement.clientHeight;
    const w = card.offsetWidth, h = card.offsetHeight, gap = 6, m = 8;
    let left = box.r + gap, side = 'l';
    if (left + w > cw - m) { left = box.l - gap - w; side = 'r'; }
    if (left < m) left = m;
    let top = box.t - 6, vert = 't';
    if (top + h > ch - m) { top = box.b + 6 - h; vert = 'b'; }
    if (top < m) top = m;
    card.dataset.corner = vert + side;
    card.style.left = Math.round(left) + 'px';
    card.style.top = Math.round(top) + 'px';
  }

  function showCard(ent, pin) {
    if (!ent.result) return;
    clearTimeout(hideTimer);
    const card = ensureUI().card;
    const wasOpen = card.classList.contains('pc-open');
    if (current && current !== ent && current.badge) current.badge.classList.remove('pc-open');
    if (!wasOpen || current !== ent) { cardPage = 'basic'; pinned = false; }
    current = ent;
    renderCard(ent);
    if (ent.badge) ent.badge.classList.add('pc-open');   // collapses the Safe/Warning/Risky text tag
    card.classList.add('pc-open');
    placeCard(ent);
    if (pin) { pinned = true; card.focus(); }
  }
  function hideCard(force, refocus) {
    if (pinned && !force) return;
    const was = current;
    if (ui) ui.card.classList.remove('pc-open');
    if (was && was.badge) was.badge.classList.remove('pc-open');
    current = null; pinned = false; cardPage = 'basic';
    if (refocus && was && was.badge) was.badge.focus({ preventScroll: true });
  }
  function scheduleHide() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(() => hideCard(false), 250);
  }

  // A blocked link cannot be opened from this page. Two layers of protection:
  //  1) the <a> gets pointer-events:none, so mouse clicks (left, middle) never reach it or the page's own handlers
  //  2) a capture-phase click guard stops keyboard activation and anything that slips through
  const blockedAnchors = new WeakSet();
  const lockedEls = new Set();
  function lockAnchor(a) {
    blockedAnchors.add(a);
    lockedEls.add(a);
    a.setAttribute('data-phantom-click-blocked', '');
    a.style.setProperty('pointer-events', 'none', 'important');
  }
  function unlockAnchor(a) {
    blockedAnchors.delete(a);
    lockedEls.delete(a);
    a.removeAttribute('data-phantom-click-blocked');
    a.style.removeProperty('pointer-events');
  }
  function syncBlocked() {
    entries.forEach((e) => { if (blocked.has(e.url)) lockAnchor(e.a); else if (blockedAnchors.has(e.a)) unlockAnchor(e.a); });
  }

  function toggleBlock(ent) {
    if (blocked.has(ent.url)) blocked.delete(ent.url); else blocked.add(ent.url);
    try { chrome.storage.local.set({ blocked: [...blocked] }); } catch (e) { /* ignore */ }
    syncBlocked();
    entries.forEach((e) => { if (e.url === ent.url) updateBadge(e); });
    renderCard(ent);
    placeCard(ent);
  }

  // Blocked links do not open from this page.
  function guardClick(e) {
    const a = elementFromEvent(e);
    if (!a) return;
    const ent = entries.get(a);
    if (blockedAnchors.has(a) || (ent && blocked.has(ent.url))) {
      e.preventDefault();
      e.stopImmediatePropagation();
      if (ent && ent.badge) { ent.badge.classList.remove('pc-flash'); void ent.badge.offsetWidth; ent.badge.classList.add('pc-flash'); }
    }
  }
  function outsidePointer(e) {
    if (pinned && ui && !ui.hosts.includes(e.target)) hideCard(true);
  }
  // Keyboard users only: a mouse click focuses a link too, but must not open the card (FR-26).
  function linkFocusIn(e) {
    const a = elementFromEvent(e);
    const ent = a && entries.get(a);
    if (!ent) return;
    let kb = false;
    try { kb = a.matches(':focus-visible'); } catch (err) { kb = false; }
    if (kb) showCard(ent, false);
  }
  function linkFocusOut() { scheduleHide(); }
  function onKey(e) { if (e.key === 'Escape' && current) hideCard(true); }

  // ---------------------------------------------------------- positioning
  let needFull = true;
  function schedulePosition(full) {
    if (full !== false) needFull = true;
    if (raf) return;
    raf = requestAnimationFrame(() => { raf = 0; const f = needFull; needFull = false; positionAll(f); });
  }
  // While the page scrolls only fixed-layer badges are moved by script; page-layer badges move natively.
  function onScroll() {
    if (current && !pinned) hideCard(true);
    schedulePosition(false);
  }

  let posMemo = new WeakMap();
  const positionOf = (n) => {
    let p = posMemo.get(n);
    if (!p) { p = getComputedStyle(n).position; posMemo.set(n, p); }
    return p;
  };
  // True when a fixed/sticky element (header, toolbar, modal) that does not contain the link is on top at x,y.
  function coveredAt(ent, x, y) {
    if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) return false;
    for (const e of document.elementsFromPoint(x, y)) {
      if (ui && ui.hosts.includes(e)) continue;
      if (e === ent.a || ent.a.contains(e) || e.contains(ent.a)) return false;
      for (let n = e; n && n !== document.documentElement; n = n.parentElement) {
        if (n.contains(ent.a)) break;
        const p = positionOf(n);
        if (p === 'fixed' || p === 'sticky') return true;
      }
      return false;
    }
    return false;
  }

  // 'fixed' when the link sits in a fixed/sticky bar or inside an inner scroll area, otherwise 'doc'.
  function modeOf(a) {
    for (let n = a; n && n !== document.documentElement; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.position === 'fixed' || cs.position === 'sticky') return 'fixed';
      if (n !== a && /auto|scroll|overlay/.test(cs.overflowY + cs.overflowX) &&
          (n.scrollHeight > n.clientHeight + 1 || n.scrollWidth > n.clientWidth + 1)) return 'fixed';
    }
    return 'doc';
  }
  function attach(ent) {
    const layer = ent.mode === 'doc' ? ensureUI().docLayer : ensureUI().fixedLayer;
    if (ent.badge.parentNode !== layer) layer.appendChild(ent.badge);
  }

  function placeBadge(ent, ctx) {
    const b = ent.badge;
    if (!b || !ent.result) return;
    const hide = () => { b.style.visibility = 'hidden'; ent.on = false; };
    if (!ent.visible) return hide();
    const r = textRect(ent);
    if (!r) return hide();
    if (ent.dups.some((d) => d.on)) return hide(); // a twin badge for the same destination is already showing
    const w = b.offsetWidth || 70;
    let left, top;
    if ((ent.src === 'image' || ent.src === 'area') && r.width >= 60 && r.height >= 40) {
      // pictures: top-right corner, inside the image
      left = Math.max(Math.min(r.right - w - 6, ctx.vw - w - 2), r.left + 4);
      top = r.top + 6;
    } else {
      // text links and small icons: beside the end of the text; buttons: just outside their right edge
      let right = r.right;
      if (ent.src === 'link') {
        const ar = ent.a.getClientRects();
        if (ar.length === 1 && ar[0].height < r.height * 2.6 && ar[0].right > right && ar[0].right - right <= 60) right = ar[0].right;
      }
      left = Math.min(right + 3, ctx.vw - w - 2);
      top = r.top + r.height / 2 - ICON_H / 2;           // vertically centred on the line / button
    }
    if (ent.mode === 'fixed') {
      const cx = left + ICON_W / 2;
      if (coveredAt(ent, cx, top + 2) || coveredAt(ent, cx, top + ICON_H - 2) || coveredAt(ent, r.right - 2, r.top + r.height / 2)) return hide();
    }
    const x = Math.round(left + (ent.mode === 'doc' ? ctx.sx : 0));
    const y = Math.round(top + (ent.mode === 'doc' ? ctx.sy : 0));
    b.style.transform = 'translate(' + x + 'px,' + y + 'px)';
    b.style.visibility = 'visible';
    ent.on = true;
  }

  function positionAll(full) {
    posMemo = new WeakMap();
    const now = Date.now();
    const ctx = { vw: document.documentElement.clientWidth, sx: scrollX, sy: scrollY };
    entries.forEach((ent, a) => {
      if (!a.isConnected) { removeEntry(a); return; }
      if (!ent.badge) return;
      if (!full && ent.mode === 'doc') return;
      if (full && now - ent.modeAt > 1500) {
        ent.modeAt = now;
        const m = modeOf(a);
        if (m !== ent.mode) { ent.mode = m; attach(ent); }
      }
      placeBadge(ent, ctx);
    });
    if (current && ui && ui.card.classList.contains('pc-open')) placeCard(current);
  }

  // --------------------------------------------------------- link detection
  // What can carry a web address: text links, image links, and buttons that go somewhere.
  const CANDIDATES = 'a[href], area[href], [data-href], button, input[type="submit"], input[type="button"], input[type="image"], [role="button"]';

  // The address a button leads to, read from the page's markup only (nothing is run):
  // its own formaction, the action of the form it submits, or a web address written in its onclick.
  function buttonTarget(el) {
    const fa = el.getAttribute('formaction');
    if (fa) return fa;
    const dh = el.getAttribute('data-href');
    if (dh && /^(https?:)?\/\//i.test(dh.trim())) return dh.trim();
    const type = (el.getAttribute('type') || (el.tagName === 'BUTTON' ? 'submit' : '')).toLowerCase();
    if (type === 'submit' || type === 'image') {
      const form = el.form;
      const act = form && form.getAttribute('action');
      if (act) return act;
    }
    const oc = el.getAttribute('onclick');
    if (oc) {
      const m = /(?:location(?:\.href)?\s*=|location\.(?:assign|replace)\s*\(|window\.open\s*\()\s*['"]([^'"]+)['"]/.exec(oc);
      if (m) return m[1];
    }
    return null;
  }

  // 'link' (has text), 'image' (a link with no text: pictures and icons) or 'button'; null when there is no address.
  function describe(el) {
    if (el.tagName === 'A') {
      if (!el.hasAttribute('href')) return null;
      return { raw: el.getAttribute('href'), src: lastTextNode(el) ? 'link' : 'image' };
    }
    if (el.tagName === 'AREA') return el.hasAttribute('href') ? { raw: el.getAttribute('href'), src: 'area' } : null;
    const raw = buttonTarget(el);
    return raw == null ? null : { raw, src: 'button' };
  }

  // Rectangle of a clickable zone of an image map: the zone's coordinates placed over the picture that uses the map.
  function areaRect(area) {
    const map = area.closest('map');
    const name = map && (map.getAttribute('name') || map.id);
    if (!name) return null;
    let img = null;
    document.querySelectorAll('img[usemap]').forEach((i) => { if (!img && i.getAttribute('usemap').replace(/^#/, '') === name) img = i; });
    if (!img) return null;
    const ir = img.getBoundingClientRect();
    const nums = (area.getAttribute('coords') || '').split(',').map((x) => parseFloat(x)).filter((x) => isFinite(x));
    const sx = img.naturalWidth ? ir.width / img.naturalWidth : 1, sy = img.naturalHeight ? ir.height / img.naturalHeight : 1;
    let x1, y1, x2, y2;
    const shape = (area.getAttribute('shape') || 'rect').toLowerCase();
    if (shape === 'circle' && nums.length >= 3) { x1 = nums[0] - nums[2]; x2 = nums[0] + nums[2]; y1 = nums[1] - nums[2]; y2 = nums[1] + nums[2]; }
    else if (nums.length >= 4 && shape !== 'default') {
      const xs = [], ys = [];
      nums.forEach((v, i) => (i % 2 ? ys : xs).push(v));
      x1 = Math.min(...xs); x2 = Math.max(...xs); y1 = Math.min(...ys); y2 = Math.max(...ys);
    } else return ir.width > 2 && ir.height > 2 ? ir : null;
    const l = ir.left + x1 * sx, t = ir.top + y1 * sy, w = (x2 - x1) * sx, h = (y2 - y1) * sy;
    return w > 2 && h > 2 ? { left: l, top: t, right: l + w, bottom: t + h, width: w, height: h, x: l, y: t } : null;
  }

  // Rectangle of the biggest picture inside an image link (or of the link itself).
  function mediaRect(el) {
    let best = null, area = 0;
    el.querySelectorAll('img, svg, picture, video, canvas').forEach((m) => {
      const r = m.getBoundingClientRect();
      if (r.width * r.height > area) { area = r.width * r.height; best = r; }
    });
    const r = best || el.getBoundingClientRect();
    return r.width > 2 && r.height > 2 ? r : null;
  }

  // The tracked element (link, image link or button) an event or node belongs to.
  function elementFromEvent(e) {
    const path = e.composedPath ? e.composedPath() : [];
    for (const n of path) if (n && n.nodeType === 1 && (entries.has(n) || blockedAnchors.has(n))) return n;
    for (let n = e.target; n && n.nodeType === 1; n = n.parentElement) if (entries.has(n) || blockedAnchors.has(n)) return n;
    return null;
  }

  function lastTextNode(a) {
    const w = document.createTreeWalker(a, NodeFilter.SHOW_TEXT);
    let last = null, n;
    while ((n = w.nextNode())) if (n.nodeValue.trim()) last = n;
    return last;
  }
  // Rectangle of the last visible line of the link's own text (not of icons, images or wrappers).
  function textRect(ent) {
    if (ent.src === 'button') { const br = ent.a.getBoundingClientRect(); return br.width > 2 && br.height > 2 ? br : null; }
    if (ent.src === 'area') return areaRect(ent.a);
    if (ent.src === 'image') return mediaRect(ent.a);
    let n = ent.textNode;
    if (!n || !n.isConnected || !ent.a.contains(n)) { n = lastTextNode(ent.a); ent.textNode = n; }
    if (!n) return null;
    const range = document.createRange();
    range.selectNodeContents(n);
    const rs = range.getClientRects();
    for (let i = rs.length - 1; i >= 0; i--) if (rs[i].width > 2 && rs[i].height > 2) return rs[i];
    return null;
  }
  function nearby(a, b) {
    let n = a;
    for (let i = 0; i < 6 && n; i++, n = n.parentElement) if (n.contains(b)) return true;
    return false;
  }

  function classify(raw) {
    const t = (raw || '').trim();
    if (!t || t[0] === '#') return null;
    const m = /^([a-z][a-z0-9+.\-]*):/i.exec(t);
    if (m) {
      const scheme = m[1].toLowerCase();
      if (scheme === 'mailto' || scheme === 'tel') return null;                          // FR-07
      if (scheme !== 'http' && scheme !== 'https') {                                      // FR-06
        return { kind: 'unsupported', url: scheme + ':', msg: 'Links that start with "' + scheme + ':" cannot be checked, so Phantom Click does not open or fetch them.' };
      }
    }
    let u;
    try { u = new URL(t, location.href); } catch (e) {                                    // NFR-12
      return { kind: 'unsupported', url: '', msg: 'This link is not a valid web address, so it cannot be checked.' };
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') {
      return { kind: 'unsupported', url: u.protocol, msg: 'This type of link cannot be checked, so Phantom Click does not open or fetch it.' };
    }
    u.hash = '';
    if (R.sameOrganization(u.hostname, location.hostname)) return null; // not external (same site or same owner)
    return { kind: 'check', url: u.href };
  }

  function markDirty(a) {
    dirty.add(a);
    if (!scanTimer) scanTimer = setTimeout(flush, 40);
  }
  function flush() {
    scanTimer = 0;
    if (!running) return;
    const batch = [...dirty].slice(0, 40);        // small slices keep the page responsive (NFR-03)
    batch.forEach((a) => dirty.delete(a));
    batch.forEach(handleAnchor);
    schedulePosition();
    if (dirty.size) scanTimer = setTimeout(flush, 30);
  }

  function handleAnchor(a) {
    try {
      if (!a.isConnected) { removeEntry(a); return; }
      const d = describe(a);
      const old = entries.get(a);
      if (!d) { if (old) removeEntry(a); return; }
      const raw = d.raw;
      if (old && old.raw === raw && old.src === d.src) return;
      if (old) removeEntry(a);
      const c = classify(raw);
      if (!c) return;
      const ent = { a, raw, src: d.src, kind: c.kind, url: c.url, visible: false, badge: null, result: null, shown: null, textNode: null, dups: [], on: false, mode: 'doc', modeAt: 0 };
      entries.set(a, ent);
      if (c.kind === 'check') {
        let set = byUrl.get(c.url);
        if (!set) { set = new Set(); byUrl.set(c.url, set); }
        ent.dups = [...set].filter((o) => o.src === ent.src && nearby(o.a, a)); // e.g. title + "Read more" of one search result
        set.add(ent);
      }
      ent.mode = modeOf(a);
      ent.modeAt = Date.now();
      if (c.kind === 'check') {
        if (blocked.has(ent.url)) lockAnchor(a);
        else if (blockedAnchors.has(a)) unlockAnchor(a);   // the link now points somewhere else
      }
      createBadge(ent);
      io.observe(a);
      if (c.kind === 'unsupported') {
        ent.result = { rules: [], phase: 'unsupported', msg: c.msg };
        updateBadge(ent);
        return;
      }
      // 1) initial local result straight away (FR-13)
      ent.result = { rules: R.analyze(ent.url).matches, phase: 'preliminary' };
      updateBadge(ent);
      // 2) cached result replaces it immediately if we have one (FR-03, FR-31)
      const cached = cacheGet(ent.url);
      if (cached) {
        ent.result = { rules: cached.rules, phase: cached.phase, finalUrl: cached.finalUrl, failMsg: cached.failMsg, note: cached.note };
        updateBadge(ent);
        return;
      }
      // 3) otherwise resolve + re-check (shared by identical URLs)
      joinJob(ent);
    } catch (e) {
      console.debug('[Phantom Click] could not process a link:', e && e.name);
    }
  }

  function removeEntry(a) {
    const ent = entries.get(a);
    if (!ent) return;
    if (ent.badge) ent.badge.remove();
    if (io) io.unobserve(a);
    ent.on = false;
    if (current === ent) hideCard(true);
    const job = inflightChecks.get(ent.url);
    if (job) job.subs.delete(ent);
    const set = byUrl.get(ent.url);
    if (set) { set.delete(ent); if (!set.size) byUrl.delete(ent.url); }
    entries.delete(a);
  }

  // ------------------------------------------------------------ check job
  function joinJob(ent) {
    let job = inflightChecks.get(ent.url);
    if (!job) {
      job = { subs: new Set(), result: null };
      inflightChecks.set(ent.url, job);
      runJob(ent.url, job);
    }
    job.subs.add(ent);
    if (job.result) applyResult(ent, job.result);
  }

  function applyResult(ent, res) {
    ent.result = res;
    updateBadge(ent);
    if (current === ent) renderCard(ent);
  }

  async function runJob(url, job) {
    const publish = (res) => { job.result = res; job.subs.forEach((e) => applyResult(e, res)); };
    try {
      const local = R.analyze(url).matches;
      const resp = await send({ type: 'resolve', url });
      let res;
      let finalOk = resp && resp.ok && /^https?:\/\//i.test(resp.finalUrl || '');
      if (!finalOk) {
        // FR-11: failed check is Warning, never Safe
        res = { rules: local, phase: 'failed', failMsg: (resp && resp.error) || 'The check could not be completed.' };
      } else {
        let rules = local;
        if (resp.finalUrl !== url) {
          // FR-14: re-check the final URL; keep High-severity findings from the original link
          const fin = R.runRules(resp.finalUrl);
          // keep High-severity findings and R-01 (the first request was still unencrypted) from the original
          const keep = R.softenForTrustedDestination(local, url, resp.finalUrl);
          rules = fin.concat(keep.filter((m) => (m.severity === 'high' || m.id === 'R-01') && !fin.some((f) => f.id === m.id)));
          // a redirect to a look-alike of the starting domain (e.g. vikingfile.com -> vik1ngfile.site)
          const lk = R.compareDomains(hostOf(url), hostOf(resp.finalUrl));
          if (lk && !rules.some((m) => m.id === 'R-04')) rules = rules.concat(R.describe('R-04', [lk]));
        }
        if (rules.some((m) => m.id === 'R-07')) rules = rules.filter((m) => m.id !== 'R-02');   // listed: not just "unfamiliar"
        res = { rules, phase: 'final', finalUrl: resp.finalUrl, note: resp.note };
      }
      publish(res);
      cachePut(url, job.result);
    } catch (e) {
      publish({ rules: R.analyze(url).matches, phase: 'failed', failMsg: 'The check could not be completed.' });
    } finally {
      inflightChecks.delete(url);
    }
  }

  // ------------------------------------------------------------ lifecycle
  function start() {
    if (running) return;
    running = true;
    ensureUI();
    io = new IntersectionObserver((list) => {
      const ctx = { vw: document.documentElement.clientWidth, sx: scrollX, sy: scrollY };
      posMemo = new WeakMap();
      list.forEach((i) => {
        const ent = entries.get(i.target);
        if (!ent) return;
        ent.visible = i.isIntersecting;
        placeBadge(ent, ctx);
      });
    }, { rootMargin: '600px 0px' }); // badges are placed before their link scrolls into view
    mo = new MutationObserver((muts) => {
      for (const m of muts) {
        if (m.type === 'attributes') {
          const t = m.target;
          if (t.matches && t.matches(CANDIDATES)) markDirty(t);
          else if (t.tagName === 'FORM') t.querySelectorAll(CANDIDATES).forEach(markDirty); // a form's action changed
          continue;
        }
        m.addedNodes.forEach((n) => {
          if (n.nodeType === 3) { const p = n.parentElement && n.parentElement.closest('a[href]'); if (p) markDirty(p); return; }
          if (n.nodeType !== 1) return;
          if (n.matches && n.matches(CANDIDATES)) markDirty(n);
          if (n.querySelectorAll) n.querySelectorAll(CANDIDATES).forEach(markDirty);
        });
      }
      schedulePosition();
    });
    mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['href', 'formaction', 'action', 'onclick', 'data-href'] });
    document.querySelectorAll(CANDIDATES).forEach(markDirty);
    addEventListener('scroll', onScroll, { capture: true, passive: true });
    addEventListener('resize', schedulePosition, { passive: true });
    document.addEventListener('click', guardClick, true);
    document.addEventListener('auxclick', guardClick, true);
    document.addEventListener('pointerdown', outsidePointer, true);
    document.addEventListener('focusin', linkFocusIn);
    document.addEventListener('focusout', linkFocusOut);
    document.addEventListener('keydown', onKey, true);
    posTimer = setInterval(() => { if (!document.hidden) schedulePosition(); }, 800); // layout shifts (images loading etc.)
  }

  function stop() {
    if (!running) return;
    running = false;
    if (mo) mo.disconnect();
    if (io) io.disconnect();
    clearInterval(posTimer); clearTimeout(scanTimer); scanTimer = 0;
    removeEventListener('scroll', onScroll, { capture: true });
    removeEventListener('resize', schedulePosition);
    document.removeEventListener('click', guardClick, true);
    document.removeEventListener('auxclick', guardClick, true);
    document.removeEventListener('pointerdown', outsidePointer, true);
    document.removeEventListener('focusin', linkFocusIn);
    document.removeEventListener('focusout', linkFocusOut);
    document.removeEventListener('keydown', onKey, true);
    lockedEls.forEach((a) => { try { unlockAnchor(a); } catch (e) { /* gone */ } });
    entries.clear(); byUrl.clear(); dirty.clear(); current = null; pinned = false;
    if (ui) { ui.hosts.forEach((h) => h.remove()); ui = null; }
  }

  function applySettings() {
    if (isExcluded(location.hostname)) stop(); else start();
  }

  async function init() {
    try {
      // domain lists from lists/known-safe.txt and lists/known-phishing.txt (via the background worker)
      const lists = await send({ type: 'lists' });
      if (lists) {
        lastLists = lists;
        R.setLists({
          known: R.parseList(lists.safe, 'safe').domains,
          phishing: R.parseList(lists.phishing, 'phishing').domains,
          feedHosts: mergeFeed(lists, 'hosts'),
          feedUrls: mergeFeed(lists, 'urls')
        });
        listSig = hashText((lists.safe || '') + '\n--\n' + (lists.phishing || '') + '\n--\n' + (lists.feed ? lists.feed.updated : ''));
      }
    } catch (e) { console.debug('[Phantom Click] could not load domain lists:', e && e.name); }
    try {
      const data = await chrome.storage.local.get(['excluded', 'blocked', 'cache', 'cacheSig', 'badgeIconOnly', 'badgeTransparency', 'urlvetEnabled', 'darkMode']);
      iconOnly = !!data.badgeIconOnly;
      dark = !!data.darkMode;
      transparency = Math.min(80, Math.max(0, Number(data.badgeTransparency) || 0));
      urlvetOn = data.urlvetEnabled !== false;
      excluded = Array.isArray(data.excluded) ? data.excluded : [];
      blocked = new Set(Array.isArray(data.blocked) ? data.blocked : []);
      cache = data.cache && typeof data.cache === 'object' ? data.cache : {};
      if (data.cacheSig !== cacheSig()) resetCache(); // new version: old results are stale
    } catch (e) { /* defaults */ }
    applySettings();
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      if (changes.blocked) { blocked = new Set(changes.blocked.newValue || []); syncBlocked(); entries.forEach(updateBadge); }
      if (changes.darkMode) { dark = !!changes.darkMode.newValue; applyCompact(); }
      if (changes.badgeTransparency) {
        transparency = Math.min(80, Math.max(0, Number(changes.badgeTransparency.newValue) || 0));
        applyCompact();
      }
      if (changes.urlvetEnabled) {
        urlvetOn = changes.urlvetEnabled.newValue !== false;
        if (urlvetOn) {
          detail.forEach((d, k) => { if (d.state === 'error' && d.error === 'disabled') detail.delete(k); });
          if (current && cardPage === 'detail') { requestDetail(current, true); renderCard(current); placeCard(current); }
        } else if (current && cardPage === 'detail') {
          renderCard(current); placeCard(current);
        }
      }
      if (changes.badgeIconOnly) { iconOnly = !!changes.badgeIconOnly.newValue; applyCompact(); schedulePosition(); }
      if (changes.excluded) { excluded = changes.excluded.newValue || []; applySettings(); }
      if (changes.feed) { // a new OpenPhish list arrived: load it, forget old results and check again
        const f = changes.feed.newValue;
        R.setLists({
          known: R.parseList(lastLists.safe, 'safe').domains,
          phishing: R.parseList(lastLists.phishing, 'phishing').domains,
          feedHosts: mergeFeed({ snapshot: lastLists.snapshot, feed: f }, 'hosts'),
          feedUrls: mergeFeed({ snapshot: lastLists.snapshot, feed: f }, 'urls')
        });
        listSig = hashText((lastLists.safe || '') + '\n--\n' + (lastLists.phishing || '') + '\n--\n' + (f ? f.updated : ''));
        resetCache();
        stop();
        applySettings();
      }
    });
  }

  init();
})();
