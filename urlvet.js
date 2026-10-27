/*
 * Phantom Click - urlvet.js
 * Talks to a separately running URLvet server (https://github.com/urlvet/urlvet, AGPL-3.0) over its HTTP API.
 * No URLvet source code or data lists are included in Phantom Click: this file only builds the request
 * address and turns the JSON report that comes back into a small summary the popup can show.
 *
 * Loaded by background.js (importScripts) and by the tests.
 */
(function (root) {
  'use strict';

  // URLvet's public server. Change this one line (or store a `urlvetEndpoint`) to use your own copy, for example http://localhost:8080.
  const DEFAULT_ENDPOINT = 'https://api.url.vet';
  const MAX_TEXT = 300;
  const MAX_ITEMS = 30;

  const isLocalHost = (h) => h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h.endsWith('.localhost');

  // Returns the clean server address, or null when it cannot be used.
  // Plain http is only accepted for a server on this computer; anything else must use https.
  function normalizeEndpoint(input) {
    let v = String(input == null ? '' : input).trim();
    if (!v) return DEFAULT_ENDPOINT;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = (/^(localhost|127\.0\.0\.1|\[::1\])(:|\/|$)/i.test(v) ? 'http://' : 'https://') + v;
    let u;
    try { u = new URL(v); } catch (e) { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    if (u.protocol === 'http:' && !isLocalHost(u.hostname)) return null;
    return u.origin + u.pathname.replace(/\/+$/, '');
  }

  const analyzeUrl = (base, target) => base + '/api/v1/analyze?url=' + encodeURIComponent(target);
  const healthUrl = (base) => base + '/api/v1/health';

  // ------------------------------------------------------------ summary helpers
  const text = (x) => (typeof x === 'string' ? x.slice(0, MAX_TEXT) : '');
  const num = (x) => (typeof x === 'number' && isFinite(x) ? x : null);
  const list = (x) => (Array.isArray(x) ? x.filter((s) => typeof s === 'string').slice(0, MAX_ITEMS).map(text) : []);
  const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : {});

  // Turns the full URLvet report into the few things the detail view shows.
  // Everything coming from the server is treated as data: strings are cut to a safe length and are only
  // ever shown as plain text. Returns null when the answer is not a URLvet report.
  function summarize(report) {
    const r = obj(report);
    const res = obj(r.result);
    if (typeof res.verdict !== 'string') return null;
    const reasons = obj(res.reasons);

    // redirect chain: submitted link -> short-link hops -> HTTP redirects
    const chain = [];
    const addChain = (c) => list(c).forEach((u) => { if (!chain.includes(u)) chain.push(u); });
    addChain(obj(r.short_link).chain);
    addChain(obj(r.redirected_from).chain);
    const redir = obj(obj(r.analysis).redirection_result);
    addChain(redir.chain);
    const finalUrl = text(redir.final_url) || text(obj(r.redirected_from).target) || text(obj(r.short_link).target) || text(r.url);

    // plain facts about the site
    const facts = [];
    const di = obj(r.domain_info);
    if (r.domain_info) {
      if (di.age_known && text(di.age_human)) facts.push(['Domain age', text(di.age_human)]);
      else if (r.domain_info && di.age_known === false) facts.push(['Domain age', 'not published by the registry']);
      if (text(di.registrar)) facts.push(['Registrar', text(di.registrar)]);
    } else {
      facts.push(['Domain registration', 'not available']);
    }
    const rank = num(obj(r.features).rank);
    if (rank && rank > 0) facts.push(['Popularity rank', '#' + rank]);
    const ssl = obj(r.ssl_info);
    if (ssl.HasTLS === true) {
      facts.push(['Certificate', (text(ssl.Issuer) || 'issuer unknown') + (num(ssl.AgeDays) != null ? ', ' + ssl.AgeDays + ' days old' : '')]);
    } else if (ssl.HasTLS === false) {
      facts.push(['Certificate', 'none (no HTTPS)']);
    }
    const http = obj(obj(r.analysis).http_status);
    if (num(http.code)) facts.push(['Page answered with', http.code + (text(http.text) ? ' ' + text(http.text) : '')]);

    // signals found on the page itself or in threat lists, each with a level for colouring
    const flags = [];
    const add = (level, t) => flags.push({ level, text: t });
    const cd = obj(r.content_data);
    if (r.content_data) {
      if (cd.has_login_form) add('bad', 'The page has a login form.');
      if (cd.has_payment_form) add('bad', 'The page asks for payment details.');
      else if (cd.has_personal_form) add('neutral', 'The page asks for personal details.');
      if (cd.has_hidden_iframe) add('bad', 'The page contains a hidden frame.');
      const brand = obj(cd.brand_check);
      if (brand.is_mismatch) add('bad', 'The page presents itself as ' + (text(brand.brand_found) || 'a known brand') + ', which does not own this domain.');
      const sr = obj(cd.script_redirect);
      if (cd.script_redirect) add('bad', 'The page sends visitors elsewhere with a script' + (text(sr.target) ? ' (to ' + text(sr.target) + ')' : '') + '.');
      const pb = obj(cd.provider_block);
      if (cd.provider_block) add('bad', (text(pb.provider) || 'The hosting provider') + ' shows a ' + (text(pb.reason) || 'blocked') + ' warning for this site.');
      if (text(cd.content_type) && !/html/i.test(cd.content_type)) add('neutral', 'The link opens a file (' + text(cd.content_type) + '), not a web page.');
    } else {
      add('neutral', 'The page could not be opened for inspection.');
    }
    const ts = obj(r.typosquat_result);
    if (ts.is_suspicious) add('bad', 'The domain imitates ' + (text(ts.matched_domain) || 'a well-known site') + '.');
    if (obj(r.domain_randomness).IsSuspicious) add('neutral', 'The domain name looks machine-generated.');
    const feeds = obj(r.threat_feeds);
    if (feeds.listed) add('bad', 'Listed as a threat by ' + (list(feeds.sources).join(', ') || 'a threat list') + '.');
    let google = false;
    ['safe_browsing', 'web_risk'].forEach((k) => {
      const g = obj(r[k]);
      if (r[k]) google = true;
      if (g.listed) add('bad', 'Flagged by Google (' + (list(g.threat_types).join(', ') || 'threat') + ').');
    });

    return {
      verdict: text(res.verdict),
      score: num(res.final_score),
      risk: num(res.risk_score),
      trust: num(res.trust_score),
      bad: list(reasons.bad_reasons),
      good: list(reasons.good_reasons),
      neutral: list(reasons.neutral_reasons),
      domain: text(r.domain),
      finalUrl,
      chain: chain.slice(0, 12),
      domainJump: !!redir.has_domain_jump || !!r.redirected_from,
      facts,
      flags,
      googleAttribution: google,
      incomplete: !!r.incomplete,
      incompleteChecks: list(r.incomplete_checks)
    };
  }

  const api = { DEFAULT_ENDPOINT, normalizeEndpoint, analyzeUrl, healthUrl, summarize };
  root.PhantomUrlvet = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
