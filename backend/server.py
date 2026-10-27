#!/usr/bin/env python3
# Data credits: OpenPhish community feed (https://openphish.com, non-commercial terms) and
# the phishunt.io free feed (https://phishunt.io, CC0). See NOTICE.md.
"""
Phantom Click feed backend.

Downloads the OpenPhish community feed (a plain text list of phishing URLs, one per line), cleans it,
and serves it to the Phantom Click extension from your own computer. Python 3.8+, standard library only.

  python server.py                       # serve on http://127.0.0.1:8787, refresh the feeds every 3 hours
  python server.py --feed-file feed.txt  # use a local file instead of downloading (testing, offline)

Why a backend at all: the extension downloads the cleaned list from here and checks links on the device, so the
addresses of the links you look at are never sent to anyone. The backend only talks to OpenPhish (to get the list)
and to the extension (to hand it over).

Please check OpenPhish's terms before use (the community feed is meant for non-commercial use as far as I know)
and keep the refresh interval reasonable. Default: 3 hours, minimum 1 hour.
"""
import argparse
import gzip
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FEED_URL = 'https://openphish.com/feed.txt'
MAX_FEED_BYTES = 30 * 1024 * 1024
MAX_URL_LEN = 2048

# Two-part endings and free hosting platforms, so "bad.co.uk" and "bad.pages.dev" are split the right way.
MULTI = {'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.id', 'ac.id', 'go.id',
         'or.id', 'web.id', 'sch.id', 'co.jp', 'co.nz', 'co.in', 'com.br', 'com.sg', 'com.my', 'com.cn', 'com.mx',
         'com.ar', 'com.co', 'com.tr', 'co.za', 'com.ng', 'com.ph', 'com.vn', 'com.hk', 'com.tw'}
PLATFORMS = {'pages.dev', 'workers.dev', 'vercel.app', 'netlify.app', 'github.io', 'gitlab.io', 'blogspot.com',
             'herokuapp.com', 'web.app', 'firebaseapp.com', 'onrender.com', 'azurewebsites.net', 'replit.app',
             'repl.co', 'glitch.me', 'weebly.com', 'wixsite.com', 'webflow.io', 'duckdns.org', 'ngrok.io',
             'ngrok-free.app', 'my.canva.site', 'canva.site', 'sites.google.com', 'forms.gle', 'notion.site',
             'carrd.co', 'godaddysites.com', 'yolasite.com', '000webhostapp.com', 'myshopify.com',
             'typeform.com', 'cloudfront.net', 'appspot.com', 'r2.dev', 'framer.website', 'fleek.co', 'ipfs.io'}
IPV4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def split_url(url):
    """Returns (host, path) in a plain, comparable form, or None if it is not a usable web link."""
    url = url.strip()
    if not url or len(url) > MAX_URL_LEN or not re.match(r'^https?://', url, re.I):
        return None
    try:
        u = urllib.parse.urlsplit(url)
        host = (u.hostname or '').lower().rstrip('.')
    except ValueError:
        return None
    if not host or ' ' in host:
        return None
    if host.startswith('www.'):
        host = host[4:]
    path = urllib.parse.unquote(u.path or '').lower().rstrip('/')
    return host, path


def registrable(host):
    if IPV4.match(host):
        return host
    parts = host.split('.')
    if len(parts) <= 2:
        return host
    two = '.'.join(parts[-2:])
    return '.'.join(parts[-3:]) if two in MULTI else two


def platform_of(host):
    for p in PLATFORMS:
        if host == p or host.endswith('.' + p):
            return p
    return None


def read_protected(path):
    """Domains from a plain list (one per line, # comments) that must never be blocked as a whole."""
    out = set()
    if path and os.path.exists(path):
        with open(path, encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                v = re.sub(r'#.*$', '', line).strip().lower()
                if v and re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', v):
                    out.add(registrable(v[4:] if v.startswith('www.') else v))
    return out


def build_lists(lines, protected, min_repeats=2):
    """Turns raw feed lines into two lists for the extension.

    hosts: whole sites to treat as phishing. Used for sites that are clearly the scammer's own (a free page on a
           hosting platform, a site that appears at least `min_repeats` times, a link with no path at all).
    urls:  exact pages (host + path, no query). Used for a page on a site that is probably hacked or shared, such as
           a phishing page inside a normal company's website or a Google Forms link.
    Whole-site entries are never made for a protected (well-known, safe-listed) domain or a bare hosting platform.
    """
    parsed = []
    seen = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        sp = split_url(line)
        if not sp or sp in seen:
            continue
        seen.add(sp)
        parsed.append(sp)
    count = {}
    for host, _ in parsed:
        count[host] = count.get(host, 0) + 1
    hosts, urls = set(), set()
    for host, path in parsed:
        reg = registrable(host)
        plat = platform_of(host)
        protected_site = reg in protected or any(host == p or host.endswith('.' + p) for p in protected)
        bare_platform = plat is not None and host == plat
        if protected_site or bare_platform:
            if path:
                urls.add(host + path)
            continue
        if plat:                                   # name.pages.dev: the page owner chose that name
            hosts.add(host)
        elif IPV4.match(host):
            hosts.add(host)
        elif not path or count[host] >= min_repeats:
            hosts.add(host if len(host.split('.')) > len(reg.split('.')) else reg)
        else:
            urls.add(host + path)
    # a page whose whole site is already listed does not need its own entry
    urls = {u for u in urls if not covered(u.split('/', 1)[0], hosts)}
    return sorted(hosts), sorted(urls)


def covered(host, hosts):
    h = host
    while h:
        if h in hosts:
            return True
        h = h.split('.', 1)[1] if '.' in h else ''
    return False


class Store:
    """Holds the cleaned lists in memory and in a cache file (so a restart does not need the internet)."""

    def __init__(self, cache_path):
        self.cache_path = cache_path
        self.lock = threading.Lock()
        self.data = {'updated': 0, 'source': '', 'hosts': [], 'urls': [], 'raw_count': 0, 'error': None, 'checked': 0}
        self.hosts_set, self.urls_set = set(), set()
        self._load()

    def _load(self):
        try:
            with open(self.cache_path, encoding='utf-8') as fh:
                d = json.load(fh)
            if isinstance(d, dict) and isinstance(d.get('hosts'), list) and isinstance(d.get('urls'), list):
                self.set(d, save=False)
        except (OSError, ValueError):
            pass

    def set(self, d, save=True):
        with self.lock:
            self.data = d
            self.hosts_set, self.urls_set = set(d['hosts']), set(d['urls'])
        if save:
            try:
                os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                tmp = self.cache_path + '.tmp'
                with open(tmp, 'w', encoding='utf-8') as fh:
                    json.dump(d, fh)
                os.replace(tmp, self.cache_path)
            except OSError as e:
                print('could not write the cache file:', e, file=sys.stderr)

    def note_error(self, message):
        with self.lock:
            self.data = dict(self.data, error=message, checked=int(time.time()))

    def lookup(self, url):
        sp = split_url(url)
        if not sp:
            return {'listed': False, 'match': None}
        host, path = sp
        with self.lock:
            hosts, urls = self.hosts_set, self.urls_set
        h = host
        while h:                                     # example.com also covers shop.example.com
            if h in hosts:
                return {'listed': True, 'match': 'host', 'entry': h}
            h = h.split('.', 1)[1] if '.' in h else ''
        p = path
        while p:                                     # a listed folder covers the pages inside it
            if host + p in urls:
                return {'listed': True, 'match': 'url', 'entry': host + p}
            p = p.rsplit('/', 1)[0]
        return {'listed': False, 'match': None}


def download(feed_url, timeout=30):
    req = urllib.request.Request(feed_url, headers={'User-Agent': 'PhantomClick-Backend/1.0 (student project)',
                                                    'Accept-Encoding': 'gzip'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(MAX_FEED_BYTES + 1)
        if len(raw) > MAX_FEED_BYTES:
            raise ValueError('the feed is larger than %d MB' % (MAX_FEED_BYTES // 1048576))
        if resp.headers.get('Content-Encoding') == 'gzip' or raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
    return raw.decode('utf-8', errors='ignore').splitlines()


# phishunt.io free phishing feed (CC0, public domain), one full URL per line, updated hourly.
PHISHUNT_URL = 'https://phishunt.io/feed.txt'
HOSTS_LINE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)')
URL_IN_TEXT = re.compile(r'https?://[^\s,"\'<>]+', re.I)


def extract_urls(lines):
    """Accepts a plain list (one link per line), a PhishTank-style JSON list, or CSV, and returns link lines."""
    text = '\n'.join(lines)
    head = text.lstrip()[:1]
    if head in '[{':
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else data.get('urls') or data.get('data') or []
            out = []
            for it in items:
                u = it.get('url') if isinstance(it, dict) else it
                if isinstance(u, str):
                    out.append(u)
            return out
        except ValueError:
            pass
    out = []
    for line in lines:
        line = line.strip()
        if not line or line[0] in '#![' or line.startswith('@@'):
            continue
        if line.startswith('||'):                       # ad-blocker style: ||host/path^$options
            body = line[2:].split('$')[0].rstrip('^*').strip()
            if body and ' ' not in body:
                out.append('https://' + body)
            continue
        m = HOSTS_LINE.match(line)                      # hosts-file style: 0.0.0.0 host
        if m:
            out.append('https://' + m.group(1))
            continue
        if re.match(r'^https?://', line, re.I) and ',' not in line.split('?')[0]:
            out.append(line)
        else:
            m = URL_IN_TEXT.search(line)
            if m:
                out.append(m.group(0))
    return out


def refresh(store, feed_url, feed_file, protected, extra_urls=()):
    """One refresh. Keeps the old lists if anything goes wrong. Returns True on success."""
    try:
        if feed_file:
            with open(feed_file, encoding='utf-8', errors='ignore') as fh:
                lines = fh.read().splitlines()
            source = 'file:' + os.path.basename(feed_file)
        else:
            lines = download(feed_url)
            source = feed_url
        sources = [source]
        for extra in extra_urls:           # more feeds: one that fails never spoils the others
            for mirror in extra.split('|'):    # "a|b|c" = the same feed on three mirrors, first that works
                try:
                    more = extract_urls(download(mirror))
                    lines = lines + more
                    sources.append(mirror)
                    print('extra feed ok: %d links from %s' % (len(more), mirror))
                    break
                except Exception as e:
                    print('extra feed failed (%s): %s' % (mirror, e), file=sys.stderr)
        source = ' + '.join(sources)
        hosts, urls = build_lists(lines, protected)
        if not hosts and not urls:
            raise ValueError('the feed had no usable links, so the old lists were kept')
        store.set({'updated': int(time.time()), 'checked': int(time.time()), 'source': source, 'hosts': hosts,
                   'urls': urls, 'raw_count': len(lines), 'error': None})
        print('feed updated: %d sites + %d pages from %d lines' % (len(hosts), len(urls), len(lines)))
        return True
    except Exception as e:  # keep serving the old data
        store.note_error(str(e)[:200])
        print('feed refresh failed:', e, file=sys.stderr)
        return False


def refresh_due(last_checked, now, interval, not_before=0):
    """True when a new download is due. Uses the wall clock, so a computer that was asleep catches up as soon as it wakes."""
    return now >= not_before and (now - last_checked) >= interval


def refresher(store, args, protected, stop):
    interval = max(1.0, args.refresh_hours) * 3600
    retry, not_before = 900, 0
    while not stop.is_set():
        last = store.data.get('checked') or store.data.get('updated') or 0
        if refresh_due(last, time.time(), interval, not_before):
            if refresh(store, args.feed_url, args.feed_file, protected, args.extra_feed):
                retry, not_before = 900, 0
            else:
                not_before = time.time() + retry
                retry = min(retry * 2, interval)
        stop.wait(60)   # look at the clock every minute (a long sleep would not notice a computer that slept)


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'PhantomClickBackend/1.0'

        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body, ctype='application/json', etag=None):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype + '; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Cache-Control', 'no-store')
            if etag:
                self.send_header('ETag', etag)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(data)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            d = store.data
            if u.path == '/api/v1/health':
                return self._send(200, {'ok': True, 'updated': d['updated'], 'checked': d.get('checked', 0),
                                        'source': d['source'], 'hosts': len(d['hosts']), 'urls': len(d['urls']),
                                        'error': d.get('error')})
            if u.path == '/api/v1/feed':
                print('%s  the extension asked for the list (%d sites, %d pages)'
                      % (time.strftime('%H:%M:%S'), len(d['hosts']), len(d['urls'])), flush=True)
                etag = '"%s-%d-%d"' % (d['updated'], len(d['hosts']), len(d['urls']))
                if self.headers.get('If-None-Match') == etag:
                    self.send_response(304)
                    self.send_header('ETag', etag)
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    return
                return self._send(200, {'updated': d['updated'], 'source': d['source'], 'hosts': d['hosts'],
                                        'urls': d['urls']}, etag=etag)
            if u.path == '/api/v1/lookup':
                q = urllib.parse.parse_qs(u.query).get('url', [''])[0]
                return self._send(200, store.lookup(q))
            return self._send(404, {'error': 'not found'})

    return Handler


def main(argv=None):
    ap = argparse.ArgumentParser(description='Phantom Click OpenPhish feed backend')
    ap.add_argument('--host', default='127.0.0.1', help='address to listen on (keep 127.0.0.1 unless you know why not)')
    ap.add_argument('--port', type=int, default=8787)
    ap.add_argument('--feed-url', default=DEFAULT_FEED_URL)
    ap.add_argument('--extra-feed', action='append', default=[], metavar='URL',
                    help='another feed of phishing links (repeat for more): plain list, CSV, PhishTank JSON or ad-blocker list. '
                         'Mirrors of one feed can be joined with |')
    ap.add_argument('--no-phishunt', action='store_true', help="do not add the phishunt.io feed (on by default)")
    ap.add_argument('--feed-file', help='read the feed from this local file instead of downloading it')
    ap.add_argument('--refresh-hours', type=float, default=3.0, help='how often to download the feeds (minimum 1; OpenPhish itself changes about every 12 h)')
    ap.add_argument('--data-dir', default=os.path.join(HERE, 'data'))
    ap.add_argument('--protected', default=os.path.join(HERE, '..', 'lists', 'known-safe.txt'),
                    help='list of well-known domains that are never blocked as a whole site')
    args = ap.parse_args(argv)
    if not args.no_phishunt and not args.feed_file:
        args.extra_feed = [PHISHUNT_URL] + args.extra_feed
    protected = read_protected(args.protected)
    store = Store(os.path.join(args.data_dir, 'feed-cache.json'))
    stop = threading.Event()
    threading.Thread(target=refresher, args=(store, args, protected, stop), daemon=True).start()
    srv = ThreadingHTTPServer((args.host, args.port), make_handler(store))
    print('Phantom Click feed backend on http://%s:%d  (feed: %s)' % (args.host, srv.server_address[1],
                                                                       args.feed_file or args.feed_url))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.server_close()


if __name__ == '__main__':
    main()
