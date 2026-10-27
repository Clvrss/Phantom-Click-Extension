// Data credits: OpenPhish (https://openphish.com) and the phishunt.io free feed (CC0,
// https://phishunt.io). See NOTICE.md.
/*
 * Phantom Click - feed.js
 * Talks to the Phantom Click feed backend (backend/server.py), which downloads the OpenPhish community feed
 * and serves a cleaned copy. The extension downloads that whole list and matches links on this computer,
 * so the addresses you browse are never sent to the backend.
 *
 * Loaded by background.js (importScripts), the popup and the tests.
 */
(function (root) {
  'use strict';

  const DEFAULT_ENDPOINT = 'http://localhost:8787';
  const MAX_ENTRIES = 200000;
  const MAX_TEXT = 300;

  const isLocalHost = (h) => h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h.endsWith('.localhost');

  // Clean server address, or null when it cannot be used. Plain http is only accepted for this computer.
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

  const feedUrl = (base) => base + '/api/v1/feed';
  const healthUrl = (base) => base + '/api/v1/health';

  const clean = (arr) => {
    if (!Array.isArray(arr)) return [];
    const out = [];
    for (const s of arr) {
      if (typeof s !== 'string' || !s || s.length > MAX_TEXT) continue;
      out.push(s.toLowerCase());
      if (out.length >= MAX_ENTRIES) break;
    }
    return out;
  };

  // Checks what the server sent. Returns { updated, source, hosts, urls } or null if it is not a feed.
  function summarize(json) {
    if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
    if (!Array.isArray(json.hosts) && !Array.isArray(json.urls)) return null;
    return {
      updated: typeof json.updated === 'number' && isFinite(json.updated) ? json.updated : 0, // seconds since 1970
      source: typeof json.source === 'string' ? json.source.slice(0, MAX_TEXT) : '',
      hosts: clean(json.hosts),
      urls: clean(json.urls)
    };
  }

  const api = { DEFAULT_ENDPOINT, normalizeEndpoint, feedUrl, healthUrl, summarize };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.PhantomFeed = api;
})(typeof self !== 'undefined' ? self : this);
