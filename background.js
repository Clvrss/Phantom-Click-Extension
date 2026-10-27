/*
 * Phantom Click - background.js (MV3 service worker)
 *  - Redirect resolution: HEAD, redirect "follow", credentials omitted, 5 s timeout (FR-08..FR-11)
 *  - Reads the domain lists from lists/known-safe.txt and lists/known-phishing.txt
 *  - Limited concurrency queue, de-duplicated by URL (FR-09)
 * Only the URL is ever requested: no cookies, no page content, no message text (NFR-15, NFR-16).
 */
'use strict';

importScripts('urlvet.js', 'feed.js'); // URLvet helpers; OpenPhish backend feed helpers

const RESOLVE_TIMEOUT_MS = 5000;
const MAX_CONCURRENT = 4;

let running = 0;
const waiting = [];
const inflight = new Map(); // url -> Promise

function resolveRedirect(url) {
  if (inflight.has(url)) return inflight.get(url);
  const p = new Promise((done) => { waiting.push({ url, done }); pump(); });
  inflight.set(url, p);
  p.finally(() => inflight.delete(url));
  return p;
}

function pump() {
  while (running < MAX_CONCURRENT && waiting.length) {
    const job = waiting.shift();
    running++;
    headRequest(job.url).then(job.done).finally(() => { running--; pump(); });
  }
}

async function headRequest(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), RESOLVE_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: ctrl.signal
    });
    // Any HTTP answer means the redirect chain was followed and res.url is the real destination.
    // Servers that refuse HEAD (403/405...) still tell us where the link leads, so we keep going.
    const out = { ok: true, finalUrl: res.url || url };
    if (!res.ok) out.note = 'The site did not allow a full check (status ' + res.status + '), so only its address was checked.';
    return out;
  } catch (e) {
    return { ok: false, error: e && e.name === 'AbortError' ? 'The check took longer than 5 seconds.' : 'The server could not be reached.' };
  } finally {
    clearTimeout(timer);
  }
}

// ------------------------------------------------------------------ URLvet (detailed analysis)
// Only called when the user opens the detailed view of a link. The server is a separate program
// (default: a copy running on this computer). Only the link's address is sent.
const URLVET_TIMEOUT_MS = 20000;   // URLvet itself stops after 15 s
const urlvetJobs = new Map();      // url -> Promise, so one link is never sent twice at the same time

async function urlvetBase() {
  const { urlvetEndpoint } = await chrome.storage.local.get('urlvetEndpoint');
  return PhantomUrlvet.normalizeEndpoint(urlvetEndpoint);
}

async function urlvetRun(url) {
  const { urlvetEnabled } = await chrome.storage.local.get('urlvetEnabled');
  if (urlvetEnabled === false) return { ok: false, error: 'disabled' };   // the toolbar switch is off
  const base = await urlvetBase();
  if (!base) return { ok: false, error: 'not_configured' };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), URLVET_TIMEOUT_MS);
  try {
    const res = await fetch(PhantomUrlvet.analyzeUrl(base, url), { credentials: 'omit', cache: 'no-store', signal: ctrl.signal });
    if (res.status === 429) return { ok: false, error: 'rate_limited' };
    if (!res.ok) return { ok: false, error: 'http_' + res.status };
    const summary = PhantomUrlvet.summarize(await res.json());
    return summary ? { ok: true, summary, server: base } : { ok: false, error: 'bad_response' };
  } catch (e) {
    return { ok: false, error: e && e.name === 'AbortError' ? 'timeout' : 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

function urlvetAnalyze(url) {
  if (!urlvetJobs.has(url)) {
    const p = urlvetRun(url);
    urlvetJobs.set(url, p);
    p.finally(() => urlvetJobs.delete(url));
  }
  return urlvetJobs.get(url);
}

// Domain lists live in plain text files inside the extension (lists/*.txt). The worker reads them
// and hands the raw text to the content script, which parses them with rules.js. Page scripts cannot read them.
let listsPromise = null;
async function readText(path) {
  try {
    const res = await fetch(chrome.runtime.getURL(path));
    return res.ok ? await res.text() : '';
  } catch (e) { return ''; }
}
function loadLists() {
  if (!listsPromise) {
    listsPromise = Promise.all([readText('lists/known-safe.txt'), readText('lists/known-phishing.txt'), readText('lists/phishing-snapshot.json')])
      .then(([safe, phishing, snap]) => {
        if (!safe && !phishing) listsPromise = null; // could not be read: try again next time
        let snapshot = null;
        try { snapshot = PhantomFeed.summarize(JSON.parse(snap)); } catch (e) { /* no snapshot: the live feed still works */ }
        return { safe, phishing, snapshot };
      });
  }
  return listsPromise;
}

// ------------------------------------------------------------------ OpenPhish feed (via the backend)
// The backend (backend/server.py) downloads the OpenPhish list every 12 hours. We download its cleaned copy
// here and keep it in chrome.storage.local, so links are matched on this computer and never sent anywhere.
const FEED_TIMEOUT_MS = 15000;
const FEED_REFRESH_MIN = 60;   // ask the backend again every hour (it only has new data twice a day)
const FEED_RETRY_MIN = 2;      // after a failure (for example the backend was not running yet) try again soon
const FEED_CHECK_MIN = 5;      // how often we look whether a sync is due; the check itself costs nothing

// Runs by itself: when the browser starts, when a page loads and there is no list yet, and on a timer.
// Nobody has to press anything; if the backend is started later, the list arrives within a few minutes.
let syncing = null;
function syncFeed() {
  if (!syncing) syncing = doSync().finally(() => { syncing = null; });
  return syncing;
}
async function maybeSync() {
  try {
    const { feedSync, feed, feedEndpoint } = await chrome.storage.local.get(['feedSync', 'feed', 'feedEndpoint']);
    const age = feedSync ? Date.now() - feedSync.at : Infinity;
    if (!feedSync || (!feedSync.ok && age > FEED_RETRY_MIN * 60000) || age > FEED_REFRESH_MIN * 60000) { syncFeed(); return; }
    if (!feedSync.ok) return;
    // Cheap check every few minutes: has the backend downloaded a newer list than the one we hold? If so, fetch it now.
    const base = PhantomFeed.normalizeEndpoint(feedEndpoint);
    if (!base) return;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 4000);
    try {
      const res = await fetch(PhantomFeed.healthUrl(base), { credentials: 'omit', cache: 'no-store', signal: ctrl.signal });
      const h = res.ok ? await res.json() : null;
      if (h && typeof h.updated === 'number' && (!feed || h.updated !== feed.updated)) syncFeed();
    } finally { clearTimeout(timer); }
  } catch (e) { /* backend off or busy: try again at the next check */ }
}

async function doSync() {
  const { feedEndpoint, feedSync: prev, feed: oldFeed } = await chrome.storage.local.get(['feedEndpoint', 'feedSync', 'feed']);
  const base = PhantomFeed.normalizeEndpoint(feedEndpoint);
  const status = { at: Date.now(), ok: false, lastOk: prev && (prev.ok ? prev.at : prev.lastOk) || 0 };
  if (!base) { status.error = 'bad_address'; await chrome.storage.local.set({ feedSync: status }); return status; }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FEED_TIMEOUT_MS);
  try {
    const res = await fetch(PhantomFeed.feedUrl(base), { credentials: 'omit', cache: 'no-store', signal: ctrl.signal });
    if (!res.ok) throw new Error('http_' + res.status);
    const feed = PhantomFeed.summarize(await res.json());
    if (!feed) throw new Error('bad_response');
    Object.assign(status, { ok: true, updated: feed.updated, hosts: feed.hosts.length, urls: feed.urls.length, server: base });
    // Never replace a working list with an empty one.
    if (oldFeed && oldFeed.updated === feed.updated && (feed.hosts.length || feed.urls.length)) await chrome.storage.local.set({ feedSync: status }); // same list: do not disturb open pages
    else if (feed.hosts.length || feed.urls.length) await chrome.storage.local.set({ feed: { updated: feed.updated, hosts: feed.hosts, urls: feed.urls }, feedSync: status });
    else { status.ok = false; status.error = 'empty'; await chrome.storage.local.set({ feedSync: status }); }
  } catch (e) {
    status.error = e && e.name === 'AbortError' ? 'timeout' : (e && /^(http_|bad_)/.test(e.message) ? e.message : 'unreachable');
    try { await chrome.storage.local.set({ feedSync: status }); } catch (e2) { /* ignore */ }
  } finally { clearTimeout(timer); }
  return status;
}

function scheduleFeed() {
  try {
    chrome.alarms.create('feed-sync', { delayInMinutes: 1, periodInMinutes: FEED_CHECK_MIN });
  } catch (e) { /* alarms not available: the next browser start syncs again */ }
}
chrome.runtime.onInstalled.addListener(() => { scheduleFeed(); syncFeed(); });
chrome.runtime.onStartup.addListener(() => { scheduleFeed(); syncFeed(); });
chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'feed-sync') maybeSync(); });
scheduleFeed();   // also whenever the worker wakes up, so the timer can never be missing
maybeSync();

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'feed-sync') {
    syncFeed().then(sendResponse);
    return true;
  }
  if (msg && msg.type === 'lists') {
    maybeSync();
    Promise.all([loadLists(), chrome.storage.local.get('feed')]).then(([l, s]) => sendResponse(Object.assign({}, l, { feed: s.feed || null })));
    return true;
  }
  if (!msg || typeof msg.url !== 'string') return false;
  if (msg.type === 'urlvet' && /^https?:\/\//i.test(msg.url) && msg.url.length <= 2048) {
    urlvetAnalyze(msg.url).then(sendResponse);
    return true;
  }
  if (msg.type === 'resolve' && /^https?:\/\//i.test(msg.url)) {
    resolveRedirect(msg.url).then(sendResponse);
    return true;
  }
  return false;
});
