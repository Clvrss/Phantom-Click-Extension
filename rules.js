/*
 * Phantom Click - rules.js
 * Seven local checking rules (R-01 to R-07), scoring and classification.
 * Everything tunable (weights, bands, domain lists, keywords) lives in CONFIG
 * so a weight can be changed without touching any UI code (NFR-22, VT-23).
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------- CONFIG
  const CONFIG = {
    maxScore: 100,
    highSeverityFloor: 51, // FR-16
    bands: { safeMax: 20, warningMax: 50 }, // FR-17: 0-20 Safe, 21-50 Warning, 51+ Risky

    rules: {
      'R-01': { severity: 'medium', weight: 25, title: 'Not encrypted (HTTP)',
        explanation: 'This link uses plain HTTP instead of HTTPS, so data sent to it is not encrypted.' },
      'R-02': { severity: 'medium', weight: 25, title: 'Unfamiliar domain',
        explanation: 'We do not recognise this domain and it shows signs often seen on throwaway sites. That is a reason for caution, not proof of a problem.' },
      'R-03': { severity: 'medium', weight: 30, title: 'Unusual link structure',
        explanation: 'The link is built in an unusual way, which is common in links that try to hide where they lead.' },
      'R-04': { severity: 'high', weight: 50, title: 'Looks like another website',
        explanation: 'The domain looks misspelled or similar to a well-known site. Fake sites often copy real names.' },
      'R-05': { severity: 'high', weight: 55, title: 'Suspicious words in the link',
        explanation: 'The link path contains words often used to pressure people into logging in or verifying something.' },
      'R-06': { severity: 'high', weight: 60, title: 'Suspicious subdomain',
        explanation: 'The first part of the address imitates a trusted name, but the real site is a different domain.' },
      'R-07': { severity: 'high', weight: 60, title: 'Known phishing domain',
        explanation: 'This domain is on our list of known phishing sites.' },
      'R-08': { severity: 'high', weight: 55, title: "Another site's name in the link",
        explanation: 'The link puts the name of a well-known site inside the address of a different site, a common way to look trustworthy.' },
      'R-09': { severity: 'medium', weight: 30, title: 'Looks like a sign-in page kit',
        explanation: 'The link has features common to copied sign-in pages: a script page with sign-in words, a long random code, or a hidden folder.' },
      'R-10': { severity: 'medium', weight: 30, title: 'Passes you on to another address',
        explanation: 'The link carries a second web address inside it. Unfamiliar sites use this to send you somewhere else without you noticing.' },
      'R-13': { severity: 'high', weight: 55, title: 'File that hides its real type',
        explanation: 'The file name has two endings, such as invoice.pdf.exe. It looks like a document but is really a program that runs on your computer.' },
      'R-14': { severity: 'medium', weight: 30, title: 'Scam words in the domain name',
        explanation: 'The domain name itself is made of lure words such as claim, free, parcel or verify. Real companies rarely name a site like that.' },
      'R-12': { severity: 'medium', weight: 30, title: 'Default name on a free hosting site',
        explanation: 'The page uses the automatic name a free hosting service gives to a new site and nobody changed it. Throwaway and scam pages are often left like this.' },
      'R-11': { severity: 'medium', weight: 30, title: 'Downloads a program or disguised file',
        explanation: 'The link points straight at a file that can run on your computer, or at a file with two endings such as .pdf.exe that hides what it really is.' }
    },
    // R-12: automatic names that free hosting services hand out (Netlify: charming-madeleine-c3ccb3.netlify.app). Vercel preview names are left out: real developers share those all the time.
    defaultHostNames: [/^[a-z]{3,}-[a-z]{3,}-[0-9a-f]{6}\.netlify\.app$/, /^[a-z]{3,}-[a-z]{3,}-[0-9a-f]{4}\.[a-z0-9-]+\.workers\.dev$/],
    // R-14: lure words in the domain name (two or more together, outside the real brand's own domain)
    // Strong: rarely part of an honest company name. Weak: common words that only count next to a strong one.
    lureWords: ['claim', 'airdrop', 'gift', 'prize', 'parcel', 'tracking', 'delivery', 'refund', 'reward', 'bonus',
      'giveaway', 'voucher', 'hadiah', 'gratis', 'login', 'signin', 'verify', 'verification', 'billing', 'wallet', 'recover',
      'suspended', 'unlock', 'robux', 'vbucks', 'followers', 'cashback', 'klaim', 'undian'],
    weakLureWords: ['free', 'online', 'secure', 'account', 'update', 'confirm', 'support', 'promo'],
    // Short brand names: only counted when they stand alone between hyphens (dhl-parcel-tracking.top)
    shortBrands: ['dhl', 'bca', 'bni', 'bri', 'ovo', 'jne', 'jnt', 'ups', 'gopay', 'dana'],
    // R-10 / R-11
    redirectParams: ['url', 'u', 'link', 'redirect', 'redirect_uri', 'redirect_url', 'redir', 'next', 'goto', 'target', 'dest',
      'destination', 'return', 'returnurl', 'return_to', 'continue', 'out', 'to', 'r', 'ref_url'],
    programExtensions: ['exe', 'scr', 'msi', 'bat', 'cmd', 'apk', 'jar', 'vbs', 'vbe', 'ps1', 'lnk', 'hta', 'pif',
      'dmg', 'pkg', 'iso', 'img', 'wsf', 'cpl', 'msix', 'appx', 'crx'],
    documentExtensions: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'mp3', 'mp4', 'zip', 'rar'],

    // R-02 / R-04 / R-06 compare against this list (data-source decision: OI-1).
    knownDomains: [], // filled from lists/known-safe.txt (see setLists)

    // Brand names to protect even when the real domain has a longer name (used by R-04).
    brandAliases: { steam: 'steampowered.com', telkomsel: 'telkomsel.com' },

    feedHosts: [], feedUrls: [], // filled from the backend feed (OpenPhish + phishunt.io) (see setLists)
    phishingDomains: [], // filled from lists/known-phishing.txt (see setLists)

    // R-02 method (OI-1). 'signals': an unlisted domain is flagged only if it also shows an unfamiliar
    // signal (below). 'strict': every domain not on knownDomains is flagged.
    unfamiliarMode: 'signals',
    riskyTlds: ['xyz', 'top', 'click', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'support', 'zip', 'mov', 'loan',
      'icu', 'cyou', 'rest', 'monster', 'buzz', 'country', 'stream', 'download', 'men', 'review', 'party',
      'cam', 'sbs', 'bond', 'surf', 'site', 'fun', 'space', 'website', 'cfd', 'vip', 'bid'],
    // Free site and app platforms. Anyone can open a page here, so the name in front is chosen by the page owner.
    // Pages on them are judged by that name (random-looking, brand names, login words), not by the platform.
    hostingPlatforms: ['pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'github.io', 'gitlab.io', 'blogspot.com',
      'herokuapp.com', 'web.app', 'firebaseapp.com', 'onrender.com', 'azurewebsites.net', 'replit.app', 'repl.co',
      'glitch.me', 'weebly.com', 'wixsite.com', 'webflow.io', 'typedream.app', 'zapier.app', 'gitbook.io',
      'wasmer.app', 'duckdns.org', 'square.site', 'crabdance.com', 'surge.sh', '000webhostapp.com', 'webcindario.com', 'epizy.com', 'rf.gd',
      'infinityfreeapp.com', 'byethost.com', 'myddns.me', 'ddns.net', 'no-ip.org', 'hopto.org', 'zapto.org', 'sytes.net', 'ngrok.io', 'ngrok-free.app',
      'trycloudflare.com', 'loca.lt', 'serveo.net'],
    // Dynamic-DNS and tunnel hosts: a name here is free and instant, so scammers use them a lot.
    throwawayHosts: ['duckdns.org', 'myddns.me', 'ddns.net', 'no-ip.org', 'hopto.org', 'zapto.org', 'sytes.net', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'surge.sh', '000webhostapp.com', 'webcindario.com', 'epizy.com', 'rf.gd', 'infinityfreeapp.com', 'byethost.com'],

    // Brands that run their own country domains (google.co.id, amazon.co.uk). Other brands on a country
    // domain (roblox.ly) are not trusted automatically.
    // Country endings that are free or cheap and mostly used by scammers: a brand name on them is never "its own country site".
    abusedCountryEndings: ['tk', 'ml', 'ga', 'cf', 'gq', 'cc', 'ws', 'ly', 'to', 'su', 'pw', 'ru', 'by'],
    countryBrands: ['tripadvisor', 'booking', 'airbnb', 'ikea', 'samsung', 'sony', 'nike', 'adidas', 'nokia', 'canon', 'dell', 'lenovo',
      'asus', 'acer', 'huawei', 'xiaomi', 'toyota', 'honda', 'nissan', 'bmw', 'mercedes', 'nestle', 'unilever', 'kfc', 'mcdonalds',
      'starbucks', 'dominos', 'lazada', 'tokopedia', 'uber', 'grab', 'tiktok', 'twitter', 'zalando', 'ebay', 'aliexpress', 'oracle', 'cisco','google', 'amazon', 'ebay', 'yahoo', 'microsoft', 'apple', 'facebook', 'wikipedia', 'netflix',
      'spotify', 'paypal', 'linkedin', 'adobe', 'shopee', 'bing', 'youtube', 'instagram', 'whatsapp'],
    // Endings a brand may legitimately use besides its main domain; a brand name on any other ending is flagged (R-04).
    commonEndings: ['com', 'net', 'org', 'dev', 'app', 'io', 'co', 'info', 'biz', 'me', 'tv'],

    // Domain endings that can never be a real public site (reserved for examples and tests).
    reservedTlds: ['example', 'test', 'invalid'],
    failedCheckScore: 25, // shown when a link could not be checked (Warning band)
    minDigitsInLabel: 3,
    maxLabelLength: 24,

    // Institutions that are hard to register: treated as trusted for R-02 and R-05.
    trustedSuffixes: ['ac.id', 'go.id', 'sch.id', 'mil.id', 'edu', 'gov', 'mil', 'ac.uk', 'gov.uk',
      'edu.au', 'gov.au', 'ac.jp', 'go.jp', 'edu.sg', 'gov.sg', 'ac.in', 'gov.in', 'edu.my', 'gov.my'],

    // Domains owned by the same organisation count as the same site (no badge between them).
    orgGroups: [
      ['google.com', 'gstatic.com', 'googleusercontent.com', 'googleapis.com', 'youtube.com', 'youtu.be', 'gmail.com'],
      ['facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'wa.me', 'meta.com'],
      ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'bing.com', 'linkedin.com'],
      ['apple.com', 'icloud.com'], ['x.com', 'twitter.com'], ['amazon.com', 'amazon.co.uk']
    ],

    shorteners: ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
      'cutt.ly', 'shorturl.at', 's.id', 'bit.do', 'rb.gy', 'tiny.cc'],

    // R-05
    strongKeywords: ['verify', 'verification', 'suspended', 'unlock', 'wallet', 'recover', 'validate',
      'giftcard', 'airdrop', 'seedphrase'],
    strongPhrases: ['free-gift', 'security-alert', 'confirm-identity', 'reset-password', 'account-locked'],
    weakKeywords: ['claim', 'prize', 'login', 'signin', 'account', 'secure', 'update', 'password', 'billing', 'payment',
      'bank', 'support', 'confirm'],
    weakKeywordsNeeded: 2,

    // R-06
    subdomainBrandSkip: ['archive', 'archives', 'office', 'stripe', 'booking', 'target', 'oracle', 'outlook', 'messenger', 'twitch', 'ledger', 'harvard', 'blogger'],
    subdomainKeywords: ['login', 'signin', 'secure', 'verify', 'account', 'update', 'billing', 'wallet', 'support'],

    // R-02 refinement: weak signals (digits) only count when two of them appear together; strong ones count alone.
    weakSignalsNeeded: 2,

    // R-08: names and domains that scammers copy (path words next to a sign-in word on an unrelated site)
    sensitiveWords: ['login', 'signin', 'sign-in', 'verify', 'verification', 'secure', 'security', 'account', 'password',
      'confirm', 'update', 'billing', 'payment', 'wallet', 'recover', 'validate', 'suspended', 'unlock', 'auth', 'authenticate', 'authentificate', 'authentification', 'logon', 'otp', 'netbank'],
    // Brands scammers copy that are not in the safe list (used by R-08 to spot a name in the path).
    extraBrands: ['scotiabank', 'scotia', 'desjardins', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
      'barclays', 'santander', 'dhl', 'fedex', 'usps', 'docusign', 'coinbase', 'binance', 'metamask', 'office365',
      'onedrive', 'sharepoint', 'icloud', 'netflix', 'whatsapp', 'instagram', 'facebook', 'paypal', 'alibaba', 'dropbox',
      'adobe', 'linkedin', 'steam', 'roblox', 'telegram', 'bancolombia', 'itau', 'bradesco', 'sparkasse', 'postbank',
      'mandiri', 'klikbca', 'bukalapak', 'traveloka', 'indihome', 'gopay', 'shopeepay', 'lazada', 'trustwallet', 'ledger', 'pancakeswap',
      'uniswap', 'opensea', 'tiktok', 'telkomsel', 'jenius', 'permata',
      'commbank', 'netbank', 'westpac', 'suncorp', 'bendigobank', 'rabobank', 'abnamro', 'commerzbank', 'deutschebank', 'nordea', 'swedbank',
      'lloyds', 'natwest', 'halifax', 'tdbank', 'rbcroyalbank', 'capitalone', 'usbank', 'truist', 'navyfederal', 'americanexpress',
      'mastercard', 'visa', 'zelle', 'venmo', 'cashapp', 'revolut', 'monzo', 'kucoin', 'bybit', 'okx', 'ledgerlive', 'trezor',
      'robinhood', 'schwab', 'icbc', 'sberbank', 'tinkoff', 'mercadolibre',
      'mercadopago', 'nubank', 'caixa', 'bancodobrasil', 'correios', 'sicredi', 'sicoob', 'rakuten', 'mufg', 'smbc', 'paytm', 'phonepe',
      'airtel', 'flipkart', 'hdfcbank', 'icicibank', 'axisbank', 'kotak', 'sbi'],

    // R-09: sign-in kit look
    kitWords: ['login', 'signin', 'sign-in', 'auth', 'verify', 'verification', 'confirm', 'secure', 'account', 'token', 'password',
      'otp', 'validate', 'billing', 'payment', 'wallet', 'recover', 'suspended', 'unlock', 'step', 'submit', 'cmd', 'webmail', 'logon', 'authentificate'],
    htmlKitWords: ['otp', 'logon', 'signin', 'verification', 'authentificate', 'authentication'],   // .html pages: saved copies of sign-in pages
    longCodeLength: 24,   // a hex-like code this long in the path or query

    // R-03
    maxUrlLength: 150, // measured on origin + path only (no query string, no #fragment)
    maxHostLabels: 5,
    maxHostHyphens: 3,
    maxEncodedChars: 5,

    // Lookalike matching (R-04)
    minBrandLength: 5,
    // Brands that scammers copy most. A one-slip misspelling of one of these inside a longer name is flagged (faiceboikonlineshoip.cc).
    fuzzyInsideBrands: ['facebook', 'instagram', 'whatsapp', 'microsoft', 'telegram', 'linkedin', 'coinbase', 'metamask', 'aliexpress',
      'trustwallet', 'mastercard', 'americanexpress', 'bankofamerica', 'wellsfargo', 'steamcommunity'],
    embeddedBrandMinLength: 6, // R-04: a brand name this long inside a longer name is combo-squatting
    // Brand names that are also ordinary words or part of many real names: never judged by the 'name inside a longer name' check.
    embeddedBrandSkip: ['archive', 'office', 'stripe', 'booking', 'target', 'oracle', 'outlook', 'messenger', 'twitch', 'scotia', 'amazon', 'revolut', 'ledger', 'harvard', 'blogger', 'telegram', 'twitter', 'archives',
      'google', 'yahoo', 'apple', 'windows', 'support', 'account', 'service', 'online', 'orange', 'square', 'shopping', 'channel', 'network', 'website'],
    // Sites where anyone can publish a page: ending there is not proof the original link was fine.
    userContentHosts: ['docs.google.com', 'drive.google.com', 'sites.google.com', 'forms.gle', 'forms.office.com', 'sway.office.com',
      'dropbox.com', 'onedrive.live.com', '1drv.ms', 'notion.site', 'canva.com', 'wixsite.com', 'github.io', 'mega.nz', 'we.tl', 'wetransfer.com'],
    fuzzyMinBrandLength: 6,

    // Hosts where the registrable domain has three parts (public-suffix shortcut).
    multiPartSuffixes: ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'edu.au',
      'co.id', 'ac.id', 'go.id', 'or.id', 'web.id', 'sch.id', 'co.jp', 'co.nz', 'co.in', 'com.br',
      'com.sg', 'com.my', 'com.cn', 'github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'web.app',
      'firebaseapp.com', 'herokuapp.com', 'blogspot.com', 'workers.dev', 'onrender.com', 'azurewebsites.net']
  };

  const RULE_IDS = Object.keys(CONFIG.rules);
  let KNOWN = new Set();
  let PHISH = new Set();
  let FEED_HOSTS = new Set();
  let FEED_URLS = new Set();
  const SHORT = new Set(CONFIG.shorteners);
  const MULTI = new Set(CONFIG.multiPartSuffixes.concat(CONFIG.hostingPlatforms));
  const HOSTING = new Set(CONFIG.hostingPlatforms);

  // --------------------------------------------------------------- helpers
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  const isIp = (host) => IPV4.test(host) || host.startsWith('[');

  function parseUrl(input) {
    try { return new URL(input); } catch (e) { return null; }
  }

  function registrableDomain(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!host || isIp(host)) return host;
    const labels = host.split('.');
    if (labels.length <= 2) return host;
    const lastTwo = labels.slice(-2).join('.');
    return MULTI.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
  }

  function subdomainOf(host, registrable) {
    return host.length > registrable.length ? host.slice(0, host.length - registrable.length - 1) : '';
  }

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }

  const HOMOGLYPHS = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '$': 's', '@': 'a' };
  function normalizeLabel(label) {
    return label.replace(/[013457$@]/g, (c) => HOMOGLYPHS[c] || c)
      .replace(/rn|nn/g, 'm').replace(/vv/g, 'w').replace(/-/g, '');
  }

  // Punycode (xn--...) back to letters, then to a plain a-z "skeleton" so a look-alike letter (Cyrillic "а") shows up as the real one.
  function decodePunycode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const out = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-'); if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) out.push(input.charCodeAt(j));
    const adapt = (delta, num, first) => {
      let k = 0; delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    };
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) return null;
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1)); i %= out.length + 1;
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }
  const CONFUSABLE = { '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p', '\u0441': 'c', '\u0445': 'x', '\u0443': 'y',
    '\u0456': 'i', '\u0458': 'j', '\u0455': 's', '\u0501': 'd', '\u04bb': 'h', '\u04cf': 'l', '\u051b': 'q', '\u03bf': 'o',
    '\u03bd': 'v', '\u03b1': 'a', '\u03c1': 'p', '\u03b9': 'i', '\u0131': 'i', '\u0261': 'g', '\u1d0f': 'o', '\u1d00': 'a' };
  function skeletonOf(label) {
    if (!label.startsWith('xn--')) return null;
    let d; try { d = decodePunycode(label.slice(4)); } catch (e) { return null; }
    if (!d) return null;
    return d.normalize('NFKD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/./gu, (ch) => CONFUSABLE[ch] || ch).replace(/[^a-z0-9-]/g, '');
  }

  // gooogle for google: one letter typed twice (not a plural: archives)
  const isDoubled = (a, b) => a.length === b.length + 1 && [...a].some((ch, i) => i > 0 && ch === a[i - 1] && a.slice(0, i) + a.slice(i + 1) === b);

  // Real typos are: a missing letter, a doubled letter, two letters swapped, a neighbouring key, or a digit that
  // looks like a letter. A different letter on the other side of the keyboard (wikimedia / wikipedia) is not a typo.
  const KEYS = { q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij', i: 'uok', o: 'ipl', p: 'ol',
    a: 'qsz', s: 'awdxz', d: 'serfcx', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop',
    z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk' };
  const LOOKS_LIKE = { '0': 'o', '1': 'li', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g' };
  const near = (typed, meant) => (KEYS[meant] || '').includes(typed) || (LOOKS_LIKE[typed] || '').includes(meant);
  function isTypoOf(a, b) { // a is one slip away from b
    if (a === b) return false;
    const la = a.length, lb = b.length;
    let i = 0;
    if (la === lb) {
      while (a[i] === b[i]) i++;
      if (a.slice(i + 1) === b.slice(i + 1)) return near(a[i], b[i]);
      return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
    }
    if (la === lb + 1) { // one extra letter: doubled, or a neighbouring key
      while (i < lb && a[i] === b[i]) i++;
      if (a.slice(i + 1) !== b.slice(i)) return false;
      return a[i] === a[i - 1] || a[i] === b[i] || near(a[i], b[i - 1] || '') || near(a[i], b[i] || '');
    }
    if (la === lb - 1) { // one missing letter
      while (i < la && a[i] === b[i]) i++;
      return a.slice(i) === b.slice(i + 1);
    }
    return false;
  }

  const firstLabel = (domain) => domain.split('.')[0];
  let BRANDS = [];
  let ALL_LABELS = new Set();

  let PATH_BRANDS = [];
  let BRAND_DOMAINS = new Map(); // brand name -> its domains (built once per list change, so rules stay fast)
  function brandDomains(brand) {
    if (CONFIG.brandAliases[brand]) return [CONFIG.brandAliases[brand]];
    return BRAND_DOMAINS.get(brand) || [];
  }

  // google.co.id, amazon.co.uk ... : a brand that runs country sites, on a country domain
  function isBrandCountryDomain(registrable) {
    const label = firstLabel(registrable);
    const rest = registrable.slice(label.length + 1);
    const cc = rest.split('.').pop();
    return CONFIG.countryBrands.includes(label) && ALL_LABELS.has(label) && !CONFIG.abusedCountryEndings.includes(cc) &&
      /^([a-z]{2}|(co|com|ac|go|or|net|org|edu)\.[a-z]{2})$/.test(rest);
  }
  // pages.dev, vercel.app ... : the free platform a host sits on, or null
  function platformOf(registrable) {
    const rest = registrable.slice(firstLabel(registrable).length + 1);
    return HOSTING.has(rest) ? rest : null;
  }
  // Rebuild everything that is derived from the two domain lists.
  function rebuildLists() {
    KNOWN = new Set(CONFIG.knownDomains);
    PHISH = new Set(CONFIG.phishingDomains);
    FEED_HOSTS = new Set(CONFIG.feedHosts);
    FEED_URLS = new Set(CONFIG.feedUrls);
    BRANDS = [...new Set(CONFIG.knownDomains.map(firstLabel).concat(Object.keys(CONFIG.brandAliases)))]
      .filter((b) => b.length >= CONFIG.minBrandLength);
    ALL_LABELS = new Set(CONFIG.knownDomains.map(firstLabel).filter((l) => l.length >= 4));
    PATH_BRANDS = [...new Set(BRANDS.concat(CONFIG.extraBrands))];
    BRAND_DOMAINS = new Map();
    CONFIG.knownDomains.forEach((d) => { const b = firstLabel(d); if (!BRAND_DOMAINS.has(b)) BRAND_DOMAINS.set(b, []); BRAND_DOMAINS.get(b).push(d); });
  }

  // Reads a .txt list: one domain per line, "#" starts a comment, full links are accepted.
  // kind 'safe' keeps the main domain; kind 'phishing' keeps exactly what was written.
  function parseList(text, kind) {
    const domains = [], skipped = [];
    String(text || '').split(/\r?\n/).forEach((line) => {
      let v = line.replace(/#.*$/, '').trim().toLowerCase();
      if (!v) return;
      v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@/]*@/, '').split(/[/?#:]/)[0]
        .replace(/^\*\./, '').replace(/^\.+|\.+$/g, '').replace(/^www\./, '');
      if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v)) { skipped.push(line.trim()); return; }
      domains.push(kind === 'safe' ? registrableDomain(v) : v);
    });
    return { domains: [...new Set(domains)], skipped };
  }

  // OpenPhish feed lookup. Whole-site entries match the host and its parent hosts; page entries match
  // host+path (no query, no www) and anything below that folder. Mirrors backend/server.py Store.lookup.
  function inFeed(c) {
    if (!FEED_HOSTS.size && !FEED_URLS.size) return false;
    const host = c.host.replace(/^www\./, '');
    const parts = host.split('.');
    for (let i = 0; i <= parts.length - 2; i++) if (FEED_HOSTS.has(parts.slice(i).join('.'))) return true;
    if (FEED_URLS.size) {
      const path = safeDecode(c.url.pathname).toLowerCase().replace(/\/+$/, '');
      let p = path;
      for (;;) {
        if (FEED_URLS.has(host + p)) return true;
        const cut = p.lastIndexOf('/');
        if (cut < 0) break;
        p = p.slice(0, cut);
      }
    }
    return false;
  }

  // A protected brand (6+ letters) inside the first label of an unfamiliar domain, with other characters around it.
  const EMBED_SKIP = new Set(CONFIG.embeddedBrandSkip);
  function embeddedBrand(label) {
    for (const brand of PATH_BRANDS) {
      if (brand.length < CONFIG.embeddedBrandMinLength || label === brand || EMBED_SKIP.has(brand)) continue;
      if (label.includes(brand)) return brand;
    }
    return null;
  }

  const R6_SKIP = new Set(CONFIG.subdomainBrandSkip);   // ordinary words that are also brand names (archive, office...)
  const isUserContent = (host) => CONFIG.userContentHosts.some((h) => host === h || host.endsWith('.' + h));

  // A long brand name written with a slip or two INSIDE a longer made-up name: faiceboikonlineshoip.cc ~ facebook.
  const sound = (w) => w.replace(/([aeou])i/g, '$1');   // faiceboik sounds like facebook: an extra "i" after a vowel is ignored
  function fuzzyBrandInside(label) {
    const text = label.replace(/-/g, '');
    for (const brand of CONFIG.fuzzyInsideBrands) {
      const L = brand.length;
      if (text.includes(brand) || text.length < L - 1 || /telegraph/.test(text)) continue;
      for (let len = L - 2; len <= L + 2; len++) {
        for (let i = 0; i + len <= text.length; i++) {
          if (text[i] !== brand[0]) continue;
          const part = text.substr(i, len);
          if (part !== brand && levenshtein(sound(normalizeLabel(part)), sound(brand)) <= 1) return brand;
        }
      }
    }
    return null;
  }

  function setLists(lists) {
    CONFIG.knownDomains = (lists && lists.known) || [];
    CONFIG.phishingDomains = (lists && lists.phishing) || [];
    CONFIG.feedHosts = (lists && lists.feedHosts) || [];   // from the OpenPhish backend (see feed.js)
    CONFIG.feedUrls = (lists && lists.feedUrls) || [];
    rebuildLists();
  }

  const isKnownLike = (registrable) => KNOWN.has(registrable) || isBrandCountryDomain(registrable);
  const isInstitutional = (host) => CONFIG.trustedSuffixes.some((s) => host.endsWith('.' + s));
  const RISKY_TLD = new Set(CONFIG.riskyTlds);

  function sameOrganization(hostA, hostB) {
    const a = registrableDomain(hostA), b = registrableDomain(hostB);
    if (!a || !b) return false;
    if (a === b) return true;
    if (isKnownLike(a) && isKnownLike(b) && firstLabel(a) === firstLabel(b)) return true;
    return CONFIG.orgGroups.some((g) => g.includes(a) && g.includes(b));
  }

  // Used after a redirect: does the destination imitate the domain the link started at?
  function compareDomains(hostA, hostB) {
    const ra = registrableDomain(hostA), rb = registrableDomain(hostB);
    if (!ra || !rb || ra === rb || isIp(ra) || isIp(rb)) return null;
    const la = firstLabel(ra), lb = firstLabel(rb);
    if (la === lb || Math.min(la.length, lb.length) < CONFIG.fuzzyMinBrandLength) return null;
    const na = normalizeLabel(la), nb = normalizeLabel(lb);
    if (na === nb || levenshtein(na, nb) === 1) {
      return 'the link starts at ' + ra + ' but ends at ' + rb + ', which looks almost the same';
    }
    return null;
  }

  // Random-looking names, typical of throw-away scam hosts (at least 8 letters and next to no vowels).
  function looksRandomLabel(label) {
    const letters = label.replace(/[^a-z]/g, '');
    if (letters.length < 8) return false;
    const vowels = (letters.match(/[aeiou]/g) || []).length;
    if (vowels / letters.length < 0.1) return true;
    // six or more consonants in a row (iktcmbvfqa) almost never happens in a real word
    return label.length >= 8 && /[^aeiouy0-9-.]{6,}/.test(label);
  }

  // Names a machine made up: a number block then letters (000itkw), a hex-like code (0f33d29, 06bc828), a letter
  // followed by many digits (a0617382). Only used for the part in front of the main domain.
  function looksGeneratedLabel(l) {
    if (l.length < 6) return false;
    if (/^[a-z]?\d{5,}[a-z0-9]*$/.test(l)) return true;
    if (/^\d{3,}[a-z]{3,}\d*$/.test(l)) return true;
    return /^[0-9a-f]+$/.test(l) && /\d/.test(l) && /[a-f]/.test(l);
  }
  // Number stuck on the front or back of a plain word (holiday2000, 123people, news1130) is an ordinary name.
  const WORD_AND_NUMBER = /^\d{1,4}[a-z]{3,}$|^[a-z]{3,}\d{1,4}$/;

  // A long code that, read as base64, turns into an email address (tracking codes used by scam pages).
  function hidesEmail(text) {
    const parts = String(text).split(/[\/?&=#]/).filter((x) => x.length >= 16 && /^[A-Za-z0-9+_=-]+$/.test(x));
    for (const part of parts) {
      try {
        const decoded = (typeof atob === 'function' ? atob : (x) => Buffer.from(x, 'base64').toString('binary'))(part.replace(/-/g, '+').replace(/_/g, '/'));
        if (/^[\x20-\x7e]+$/.test(decoded) && /[\w.+-]+@[\w-]+\.[a-z]{2,}/i.test(decoded)) return true;
      } catch (e) { /* not base64 */ }
    }
    return false;
  }

  function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  // ----------------------------------------------------------------- rules
  // Each rule: (ctx) => null | { reasons: [string] }
  const checks = {
    'R-01': (c) => (c.url.protocol === 'http:' ? { reasons: [] } : null),

    'R-02': (c) => {
      if (c.trusted) return null;
      if (CONFIG.unfamiliarMode === 'strict') return { reasons: [] };
      const label = firstLabel(c.registrable);
      const tld = c.registrable.split('.').pop();
      const strong = [], weak = [];
      if (isIp(c.host)) strong.push('it is a raw IP address');
      if (CONFIG.reservedTlds.includes(tld)) strong.push('".' + tld + '" is not a real public domain ending');
      const dyn = CONFIG.throwawayHosts.find((h) => c.host === h || c.host.endsWith('.' + h));
      if (dyn) strong.push('it is a free, instant address on ' + dyn);
      if (RISKY_TLD.has(tld)) strong.push('".' + tld + '" is often used for throwaway sites');
      if ((label.match(/\d/g) || []).length >= CONFIG.minDigitsInLabel && !WORD_AND_NUMBER.test(label)) weak.push('the name contains many digits');
      const hostLabels = c.host.split('.').slice(0, -1); // every part except the ending
      if (hostLabels.some((l) => /[a-z]\d[a-z]/.test(l))) weak.push('a digit sits inside a word in the address');
      if (hostLabels.some(looksRandomLabel)) strong.push('part of the address looks random');
      if (label.length > CONFIG.maxLabelLength) strong.push('the name is very long');
      const sub = subdomainOf(c.host, c.registrable);
      if (sub && sub.split('.').some(looksGeneratedLabel)) strong.push('the first part of the address looks made up by a machine');
      if (strong.length || weak.length >= CONFIG.weakSignalsNeeded) return { reasons: strong.concat(weak) };
      return null;
    },

    'R-03': (c) => {
      const reasons = [];
      const { url, host } = c;
      if (isIp(host)) reasons.push('it uses a raw IP address instead of a name');
      if (url.username || url.password) reasons.push('it contains a username or password before the address');
      if (c.base.length > CONFIG.maxUrlLength) reasons.push('it is unusually long');
      if (host.split('.').length > CONFIG.maxHostLabels) reasons.push('the address has too many parts');
      if (host.split('.').some((l) => l.startsWith('xn--'))) reasons.push('it uses disguised international characters');
      if (url.port) reasons.push('it uses an unusual port (' + url.port + ')');
      if ((host.match(/-/g) || []).length > CONFIG.maxHostHyphens) reasons.push('the domain has many hyphens');
      if (/\/{2,}/.test(url.pathname)) reasons.push('the path has repeated slashes');
      if ((url.pathname.match(/%[0-9a-f]{2}/gi) || []).length > CONFIG.maxEncodedChars) reasons.push('it hides characters with encoding');
      if (SHORT.has(c.registrable)) reasons.push('it is a shortened link that hides the real destination');
      return reasons.length ? { reasons } : null;
    },

    'R-04': (c) => {
      if (c.trusted || isIp(c.host)) return null;
      const label = firstLabel(c.registrable);
      const norm = normalizeLabel(label);
      const ending = c.registrable.slice(label.length + 1);
      const onPlatform = !!platformOf(c.registrable);
      for (const brand of BRANDS) {
        if (label === brand) {
          // the exact brand name on an ending the brand does not use (steamcommunity.cfd, roblox.ly)
          if (!onPlatform && !CONFIG.commonEndings.includes(ending)) {
            return { reasons: ['it uses the name of ' + brandDomains(brand)[0] + ' on a different ending (".' + ending + '")'] };
          }
          continue;
        }
        if (norm === brand) return { reasons: ['it imitates ' + brandDomains(brand)[0]] };
        if (brand.length >= CONFIG.fuzzyMinBrandLength && (isTypoOf(norm, brand) || isTypoOf(label.replace(/-/g, ''), brand))) {
          return { reasons: ['it is one character away from ' + brandDomains(brand)[0]] };
        }
        // long brand names (10+ letters) leave room for two slips: steamcommmumity, steamcommunytiy
        if (brand.length >= 10 && norm[0] === brand[0] && Math.abs(norm.length - brand.length) <= 2 && levenshtein(norm, brand) <= 2) {
          return { reasons: ['it is a few letters away from ' + brandDomains(brand)[0]] };
        }
        if (label.includes('-') && label.split('-').includes(brand)) {
          return { reasons: ['it uses the name of ' + brandDomains(brand)[0] + ' on another domain'] };
        }
      }
      // look-alike letters from another alphabet (xn--pypal-4ve.com shows as "pаypal"), and typos hidden between hyphens
      const skel = skeletonOf(label);
      const pieces = (skel || label).split('-').filter((x) => x.length >= 4);
      for (const brand of BRANDS) {
        for (const part of (skel ? pieces.concat(skel.replace(/-/g, '')) : pieces)) {
          if (part === brand && !skel) continue;                       // exact brand between hyphens is handled above
          const np = normalizeLabel(part);
          if (np === brand || (brand.length >= CONFIG.fuzzyMinBrandLength && ((np.length === brand.length && isTypoOf(np, brand)) || isDoubled(np, brand)))) {
            return { reasons: ['it imitates ' + (brandDomains(brand)[0] || brand) + (skel ? ' using look-alike characters' : '')] };
          }
        }
      }
      // a brand name stuck inside a longer made-up name (studio9shopee.net, myshopeedeals.com): combo-squatting
      const squat = embeddedBrand(label);
      if (squat) {
        const real = brandDomains(squat)[0];
        return { reasons: ['the name contains "' + squat + '"' + (real ? ' but the real site is ' + real : ' but it is not the official site')] };
      }
      const fuzzy = fuzzyBrandInside(label);
      if (fuzzy) return { reasons: ['the name hides a misspelling of "' + fuzzy + '"' + (brandDomains(fuzzy)[0] ? ' (real site: ' + brandDomains(fuzzy)[0] + ')' : '')] };
      return null;
    },

    'R-05': (c) => {
      if (c.trusted && !isUserContent(c.host)) return null;
      const text = safeDecode(c.url.pathname + c.url.search).toLowerCase();
      const tokens = new Set(text.split(/[^a-z0-9]+/).filter(Boolean));
      const hits = [];
      CONFIG.strongKeywords.forEach((k) => tokens.has(k) && hits.push(k));
      CONFIG.strongPhrases.forEach((p) => text.includes(p) && hits.push(p));
      const weak = CONFIG.weakKeywords.filter((k) => tokens.has(k));
      const open = /[?&](url|redirect|redirect_uri|next|continue|dest|goto|link)=https?(:|%3a)/i.test(c.url.search);
      if (open) hits.push('a hidden redirect');
      if (hits.length || weak.length >= CONFIG.weakKeywordsNeeded) {
        return { reasons: hits.concat(weak.length >= CONFIG.weakKeywordsNeeded ? weak : []) };
      }
      return null;
    },

    'R-06': (c) => {
      if (c.knownLike || isIp(c.host)) return null;
      const plat = platformOf(c.registrable);
      if (plat) {
        const tokens = c.host.slice(0, c.host.length - plat.length - 1).split(/[.-]/).filter(Boolean);
        const brand = BRANDS.find((b) => tokens.includes(b));
        if (brand) return { reasons: ['it shows "' + brand + '" in the name of a free page on ' + plat] };
        const kw = CONFIG.subdomainKeywords.find((k) => tokens.includes(k));
        if (kw) return { reasons: ['it puts "' + kw + '" in the name of a free page on ' + plat] };
        return null;
      }
      const sub = subdomainOf(c.host, c.registrable);
      if (!sub) return null;
      const labels = sub.split('.');
      const joined = sub.toLowerCase();
      const dotted = '.' + joined.replace(/-/g, '.') + '.';   // whole labels only: "g.co" must not match inside "marriage-wedding.computer"
      for (const d of CONFIG.knownDomains) {
        if (dotted.includes('.' + d + '.')) return { reasons: ['it shows "' + d + '" in front of a different domain'] };
      }
      for (const brand of BRANDS) {
        if (R6_SKIP.has(brand)) continue;
        if (labels.some((l) => l === brand || l.split('-').includes(brand))) {
          return { reasons: ['it shows "' + brand + '" in front of a different domain'] };
        }
      }
      const extra = PATH_BRANDS.find((b) => !R6_SKIP.has(b) && labels.some((l) => l === b));
      if (extra) return { reasons: ['it shows "' + extra + '" in front of a different domain'] };
      const kw = CONFIG.subdomainKeywords.filter((k) => labels.some((l) => l.split('-').includes(k)));
      if (kw.length && (labels.length >= 2 || sub.includes('-'))) {
        return { reasons: ['it puts "' + kw[0] + '" in the address of an unfamiliar site'] };
      }
      return null;
    },

    // A second web address inside the link (?url=https://other.site), on a site we do not trust.
    'R-10': (c) => {
      if (c.trusted) return null;
      const inner = (v) => {
        let d = safeDecode(safeDecode(v)).trim().toLowerCase();
        if (/^\/\//.test(d)) d = 'https:' + d;
        if (!/^https?:\/\//.test(d)) return null;
        const u = parseUrl(d);
        return u && registrableDomain(u.hostname.toLowerCase()) !== c.registrable ? registrableDomain(u.hostname.toLowerCase()) : null;
      };
      for (const [k, v] of c.url.searchParams) {
        if (!CONFIG.redirectParams.includes(k.toLowerCase())) continue;
        const to = inner(v);
        if (to) return { reasons: ['it carries a second address inside it, pointing to ' + to] };
      }
      const m = c.url.pathname.match(/\/(https?:\/\/[^/?#]+|https?%3a%2f%2f[^/?#]+)/i);
      if (m) { const to = inner(m[1]); if (to) return { reasons: ['it carries a second address inside it, pointing to ' + to] }; }
      return null;
    },

    'R-12': (c) => {
      if (c.trusted) return null;
      return CONFIG.defaultHostNames.some((re) => re.test(c.host)) ? { reasons: ['the address is the automatic name of a free ' + platformOf(c.registrable) + ' site'] } : null;
    },

    // A program to run (.exe, .apk ...) from a site we do not trust.
    'R-11': (c) => {
      if (c.trusted) return null;
      const ext = safeDecode(c.url.pathname).toLowerCase().split('/').pop().split('.').pop();
      return CONFIG.programExtensions.includes(ext) && safeDecode(c.url.pathname).split('/').pop().includes('.')
        ? { reasons: ['it downloads a ".' + ext + '" file from an unfamiliar site'] } : null;
    },

    // A double ending that disguises a program as a document (invoice.pdf.exe). Anywhere.
    'R-13': (c) => {
      const parts = safeDecode(c.url.pathname).toLowerCase().split('/').pop().split('.');
      if (parts.length < 3) return null;
      const last = parts[parts.length - 1], prev = parts[parts.length - 2];
      return CONFIG.programExtensions.includes(last) && CONFIG.documentExtensions.includes(prev)
        ? { reasons: ['it looks like a ' + prev + ' file but ends in .' + last] } : null;
    },

    // Lure words inside the domain name itself (dhl-parcel-tracking.top, free-robux.com).
    'R-14': (c) => {
      if (c.trusted || isIp(c.host)) return null;
      const label = firstLabel(c.registrable);
      const tokens = label.split('-');
      const has = (w) => tokens.includes(w) || (w.length >= 5 && label.includes(w));
      const strong = CONFIG.lureWords.filter(has), weak = CONFIG.weakLureWords.filter(has);
      const found = strong.concat(weak);
      const shortBrand = CONFIG.shortBrands.find((b) => tokens.includes(b));
      if (strong.length >= 2 || (strong.length >= 1 && weak.length >= 1)) return { reasons: ['the name is made of lure words (' + found.slice(0, 3).join(', ') + ')'] };
      if (shortBrand && found.length >= 1) return { reasons: ['the name puts "' + shortBrand + '" next to "' + found[0] + '"'] };
      return null;
    },

    'R-07': (c) => {
      if (PHISH.has(c.host) || PHISH.has(c.registrable)) return { reasons: [] };
      const feedHit = inFeed(c);
      return feedHit ? { reasons: ['it is on a list of reported phishing sites (OpenPhish or phishunt.io)'] } : null;
    },

    // The name or domain of a well-known site inside the PATH of an unrelated site (/linkedin.com/login.php,
    // /paypal/signin). Never on trusted sites; the query string is not searched (it often holds harmless ref= values).
    'R-08': (c) => {
      if ((c.trusted && !isUserContent(c.host)) || isIp(c.host)) return null;
      const path = safeDecode(c.url.pathname).toLowerCase();
      const own = firstLabel(c.registrable);
      for (const d of CONFIG.knownDomains) {
        if (d === c.registrable || firstLabel(d) === own) continue;
        const i = path.indexOf(d);
        if (i >= 0 && (i === 0 || /[\/_.=-]/.test(path[i - 1])) && (i + d.length === path.length || /[\/_.=?&-]/.test(path[i + d.length]))) {
          return { reasons: ['the path contains "' + d + '"'] };
        }
      }
      const tokens = new Set(path.split(/[^a-z0-9]+/).filter(Boolean));
      const brand = PATH_BRANDS.find((b) => b !== own && !own.includes(b) && (tokens.has(b) || (b.length >= 6 && path.includes(b))));
      const word = CONFIG.sensitiveWords.find((w) => tokens.has(w) || (w.length >= 6 && path.includes(w)));
      if (brand && word) return { reasons: ['the path has "' + brand + '" next to "' + word + '"'] };
      return null;
    },

    // What copied sign-in pages (phishing kits) tend to look like. Never on trusted sites.
    'R-09': (c) => {
      if (c.trusted) return null;
      const path = safeDecode(c.url.pathname).toLowerCase();
      const query = safeDecode(c.url.search).toLowerCase();
      const reasons = [];
      const tokens = new Set((path + ' ' + query).split(/[^a-z0-9]+/).filter(Boolean));
      const kitWord = CONFIG.kitWords.find((w) => tokens.has(w));
      if (/\.(php|aspx?|jsp)(\/|$)/.test(path) && kitWord) reasons.push('a script page with "' + kitWord + '" in the link');
      else if (/\.html?$/.test(path) && CONFIG.htmlKitWords.some((w) => tokens.has(w))) reasons.push('a saved sign-in page ("' + CONFIG.htmlKitWords.find((w) => tokens.has(w)) + '" in the link)');
      if (new RegExp('[0-9a-f]{' + CONFIG.longCodeLength + ',}').test(path + query) && /\d/.test(path + query)) reasons.push('it carries a long random code');
      if (/(^|\/)\.(?!well-known)[a-z0-9_-]{2,}\//.test(path)) reasons.push('it uses a hidden folder');
      if (/[?&](email|e-mail|mail|user|username)=[^&]*@/.test(query)) reasons.push('it has an email address filled in');
      if (hidesEmail(c.url.pathname + c.url.search)) reasons.push('it hides an email address inside a code');
      if (/\/wp-(content|includes|admin)\/.*\.(php|html?)$/.test(path)) reasons.push('it points to a script inside a website\'s own files');
      return reasons.length ? { reasons } : null;
    }
  };

  // ------------------------------------------------------- public functions
  function runRules(href) {
    const url = parseUrl(href);
    if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) return [];
    url.hash = ''; // the #fragment never reaches the server (Google adds long text fragments)
    const host = url.hostname.toLowerCase();
    const registrable = registrableDomain(host);
    const knownLike = isKnownLike(registrable);
    const ctx = {
      url, href: url.href, base: url.origin + url.pathname, host, registrable,
      knownLike, trusted: knownLike || isInstitutional(host)
    };
    // Known phishing is checked first. The other rules still add to the score, except "unfamiliar domain":
    // a domain that is on a phishing list is not merely "unfamiliar", and that finding would only repeat the point.
    const out = [];
    try {
      const known = checks['R-07'](ctx);
      if (known) out.push(describe('R-07', known.reasons));
    } catch (e) { /* the other rules still run */ }
    const isKnownPhish = out.length > 0;
    RULE_IDS.forEach((id) => {
      if (id === 'R-07' || (isKnownPhish && id === 'R-02')) return;
      let res = null;
      try { res = checks[id](ctx); } catch (e) { res = null; } // a rule must never crash the extension
      if (res) out.push(describe(id, res.reasons));
    });
    return out;
  }

  // After a redirect: the link ended on a secure page of a trusted site. Then the original link's weaker findings
  // no longer matter, and a brand-named domain that leads to that very brand (canva.link -> canva.com) is just its
  // official short domain. Known phishing (R-07) and everything else High stays.
  function softenForTrustedDestination(originalMatches, originalUrl, finalUrl) {
    const o = parseUrl(originalUrl), f = parseUrl(finalUrl);
    if (!o || !f || f.protocol !== 'https:') return originalMatches;
    const fh = f.hostname.toLowerCase(), fr = registrableDomain(fh);
    if (CONFIG.userContentHosts.some((h) => fh === h || fh.endsWith('.' + h))) return originalMatches; // anyone can publish there
    if (!(isKnownLike(fr) || isInstitutional(fh))) return originalMatches;
    const oLabel = firstLabel(registrableDomain(o.hostname.toLowerCase()));
    const sameBrand = oLabel === firstLabel(fr);
    return originalMatches.filter((m) => {
      if (m.id === 'R-07') return true;
      if (m.severity === 'medium') return false;
      return !(sameBrand && m.id === 'R-04');
    });
  }

  function describe(id, reasons) {
    const r = CONFIG.rules[id];
    let explanation = r.explanation;
    if (reasons && reasons.length) explanation += ' Why: ' + reasons.join('; ') + '.';
    return { id, severity: r.severity, weight: r.weight, title: r.title, explanation };
  }

  // FR-15, FR-16, FR-17
  function scoreFrom(ruleIds) {
    const ids = [...new Set(ruleIds)].filter((id) => CONFIG.rules[id]);
    let score = ids.reduce((sum, id) => sum + CONFIG.rules[id].weight, 0);
    score = Math.min(score, CONFIG.maxScore);
    if (ids.some((id) => CONFIG.rules[id].severity === 'high') && score < CONFIG.highSeverityFloor) {
      score = CONFIG.highSeverityFloor;
    }
    return { score, status: statusFromScore(score) };
  }

  function statusFromScore(score) {
    if (score <= CONFIG.bands.safeMax) return 'safe';
    if (score <= CONFIG.bands.warningMax) return 'warning';
    return 'risky';
  }

  function analyze(href) {
    const matches = runRules(href);
    return Object.assign({ matches }, scoreFrom(matches.map((m) => m.id)));
  }

  const api = {
    CONFIG, RULE_IDS, analyze, softenForTrustedDestination, runRules, scoreFrom, statusFromScore, describe,
    registrableDomain, parseUrl, levenshtein, sameOrganization, compareDomains, parseList, setLists, isKnownDomain: (d) => KNOWN.has(d),
    isTrustedHost: (host) => { host = String(host || '').toLowerCase(); return isKnownLike(registrableDomain(host)) || isInstitutional(host); }
  };

  rebuildLists();
  root.PhantomRules = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
