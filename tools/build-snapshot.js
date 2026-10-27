#!/usr/bin/env node
/*
 * Builds lists/phishing-snapshot.json from a big list of phishing links (one per line), for example the
 * Phishing.Database "phishing-links-ACTIVE.txt". Keeps only what is useful AND safe to ship:
 *   - sites that show up again and again (12+ links), with a name the rules do not already rate Risky
 *   - folders on compromised sites (3+ links), never the whole site
 *   - free-hosting sub-sites that show up 4+ times
 * Never included: trusted sites, shared services (storage, IPFS, CDN, mail, forms...), shorteners, raw IP addresses.
 *
 *   node tools/build-snapshot.js phishing-links-ACTIVE.txt lists/phishing-snapshot.json "Phishing.Database"
 */
'use strict';
const fs = require('fs');
const path = require('path');
const R = require('../rules.js');

const [input, output, sourceName] = process.argv.slice(2);
if (!input || !output) { console.error('usage: node tools/build-snapshot.js <links.txt> <out.json> [source name]'); process.exit(1); }

const known = R.parseList(fs.readFileSync(path.join(__dirname, '../lists/known-safe.txt'), 'utf8'), 'safe').domains;
R.setLists({ known, phishing: [] });

const SHARED = /ipfs|cdn|storage|googleapis|cloudflare|digitalocean|amazonaws|azure|firebase|blob|bucket|cloudfront|dweb|genial\.ly|canva|github|gitlab|sharepoint|dropbox|weebly|wix|mail|cloud|static|files|upload|docs|drive|forms|sites\.|hosting|plesk|mybluehost|myftpupload|pantheonsite|zohopublic|emailmeform|fleek|pinata|oraclecloud|yandexcloud|appdomain|\.page$|siasky|skynet|arweave|gateway|ingress|easywp|codeanyapp/;
const SHORT = new Set(R.CONFIG.shorteners.concat(['t.ly', 'linktr.ee', 'qrco.de', 'lnkd.in', 'tr.ee', 'v.gd', 'url.ie']));
const IP = /^\d+\.\d+\.\d+\.\d+$/;
const platforms = R.CONFIG.hostingPlatforms;
const onPlatform = (h) => platforms.some((p) => h === p || h.endsWith('.' + p));
// A plain, normal-looking name on its own ending is probably a real site that was hacked: we list its folders, not the site.
const looksThrowaway = (h) => {
  const reg = R.registrableDomain(h), label = reg.split('.')[0], tld = reg.split('.').pop();
  return h.split('.').length - reg.split('.').length >= 1 || label.includes('-') || (label.match(/\d/g) || []).length >= 2
    || R.CONFIG.riskyTlds.includes(tld) || label.length >= 20;
};
const notRisky = (u) => R.analyze(u).status !== 'risky';

const hostHits = new Map(), folderHits = new Map();
let lines = 0;
for (const raw of fs.readFileSync(input, 'utf8').split('\n')) {
  const m = raw.trim().match(/^https?:\/\/([^\/:?#@]+)(?::\d+)?(\/[^?#]*)?/i);
  if (!m) continue;
  lines++;
  const host = m[1].toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (!host.includes('.') || IP.test(host)) continue;
  hostHits.set(host, (hostHits.get(host) || 0) + 1);
  const segs = (m[2] || '').toLowerCase().split('/').filter(Boolean);
  if (segs.length >= 2) {   // need a real folder, not just a file in the root
    const key = host + '/' + segs.slice(0, 2).join('/');
    folderHits.set(key, (folderHits.get(key) || 0) + 1);
  }
}

const skipHost = (h) => R.isTrustedHost(h) || SHARED.test(h) || SHORT.has(h) || SHORT.has(R.registrableDomain(h));
const hosts = [], urls = [];
const byHits = (map) => [...map.entries()].sort((a, b) => b[1] - a[1]);

for (const [h, n] of byHits(hostHits)) {
  if (skipHost(h)) continue;
  if (onPlatform(h)) {
    if (n >= 4 && R.registrableDomain(h) !== h && notRisky('https://' + h + '/')) hosts.push(h);
  } else if (n >= 12 && looksThrowaway(h) && notRisky('https://' + h + '/')) {
    hosts.push(h);
  }
}
const hostSet = new Set(hosts);
for (const [key, n] of byHits(folderHits)) {
  if (n < 3) continue;
  const h = key.split('/')[0];
  if (hostSet.has(h) || skipHost(h) || onPlatform(h)) continue;
  if (notRisky('https://' + key + '/')) urls.push(key);
}
const out = { made: new Date().toISOString().slice(0, 10), source: sourceName || path.basename(input), from_links: lines,
  hosts: hosts.slice(0, 4000), urls: urls.slice(0, 2500) };
fs.writeFileSync(output, JSON.stringify(out));
console.log('links read: ' + lines + ' | sites: ' + out.hosts.length + ' | folders: ' + out.urls.length + ' | ' + fs.statSync(output).size + ' bytes');
