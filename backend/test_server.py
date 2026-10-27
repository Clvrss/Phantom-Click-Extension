"""Run: python test_server.py   (standard library only, no internet needed)"""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import server

HERE = os.path.dirname(os.path.abspath(__file__))
FEED = os.path.join(HERE, 'sample-feed.txt')
PROTECTED = {'google.com'}


def lines():
    with open(FEED, encoding='utf-8') as fh:
        return fh.read().splitlines()


class BuildLists(unittest.TestCase):
    def setUp(self):
        self.hosts, self.urls = server.build_lists(lines(), PROTECTED)

    def test_hosts_repeated_platform_ip_and_root(self):
        self.assertIn('secure-login.evil-bank.xyz', self.hosts)        # seen twice
        self.assertIn('fake-paypal-login.pages.dev', self.hosts)       # free page: the owner chose the name
        self.assertIn('192.0.2.7', self.hosts)                         # raw IP
        self.assertIn('rootonly-scam.com', self.hosts)                 # link with no path

    def test_single_pages_stay_page_level(self):
        self.assertIn('danieltolson.com/token3.php', self.urls)        # probably a hacked site
        self.assertNotIn('danieltolson.com', self.hosts)
        self.assertIn('shop.hackedsite.org/wp-content/upgrade/gov', self.urls)

    def test_protected_and_bare_platform_never_whole_site(self):
        self.assertNotIn('docs.google.com', self.hosts)
        self.assertNotIn('google.com', self.hosts)
        self.assertIn('docs.google.com/forms/d/e/1faipqlsphishform/viewform', self.urls)
        self.assertNotIn('pages.dev', self.hosts)
        self.assertIn('pages.dev/some-page', self.urls)

    def test_www_query_fragment_and_duplicates(self):
        self.assertIn('bigscam.net/a/b/login.html', self.urls)
        self.assertEqual(len([u for u in self.urls if u.startswith('bigscam.net')]), 1)

    def test_junk_is_dropped(self):
        for entry in self.hosts + self.urls:
            self.assertNotIn('files.example.com', entry)
            self.assertNotIn(' ', entry)

    def test_page_inside_a_listed_site_is_not_repeated(self):
        self.assertFalse([u for u in self.urls if u.startswith('secure-login.evil-bank.xyz')])


class Lookup(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.store = server.Store(os.path.join(d, 'cache.json'))
        hosts, urls = server.build_lists(lines(), PROTECTED)
        self.store.set({'updated': 1, 'checked': 1, 'source': 't', 'hosts': hosts, 'urls': urls, 'raw_count': 13, 'error': None})

    def listed(self, u):
        return self.store.lookup(u)['listed']

    def test_site_and_subdomains(self):
        self.assertTrue(self.listed('https://rootonly-scam.com/anything'))
        self.assertTrue(self.listed('https://login.rootonly-scam.com/'))
        self.assertTrue(self.listed('https://www.rootonly-scam.com/'))
        self.assertFalse(self.listed('https://notrootonly-scam.com/'))

    def test_exact_host_only_for_subdomain_entries(self):
        self.assertTrue(self.listed('https://secure-login.evil-bank.xyz/x'))
        self.assertFalse(self.listed('https://evil-bank.xyz/'))
        self.assertFalse(self.listed('https://other.evil-bank.xyz/'))

    def test_folder_covers_pages_inside(self):
        self.assertTrue(self.listed('https://shop.hackedsite.org/wp-content/upgrade/gov/login.php?a=1'))
        self.assertFalse(self.listed('https://shop.hackedsite.org/wp-content/other/page.php'))
        self.assertFalse(self.listed('https://shop.hackedsite.org/'))

    def test_safe_sites_are_not_listed(self):
        self.assertFalse(self.listed('https://docs.google.com/forms/d/e/other/viewform'))
        self.assertTrue(self.listed('https://docs.google.com/forms/d/e/1FAIpQLSphishFORM/viewform'))
        self.assertFalse(self.listed('https://www.google.com/'))
        self.assertFalse(self.listed('javascript:alert(1)'))
        self.assertFalse(self.listed(''))

    def test_cache_survives_restart(self):
        again = server.Store(self.store.cache_path)
        self.assertTrue(again.lookup('https://rootonly-scam.com/')['listed'])


class Refresh(unittest.TestCase):
    def test_failed_refresh_keeps_old_lists(self):
        d = tempfile.mkdtemp()
        store = server.Store(os.path.join(d, 'cache.json'))
        self.assertTrue(server.refresh(store, None, FEED, PROTECTED))
        before = list(store.data['hosts'])
        self.assertFalse(server.refresh(store, None, os.path.join(d, 'missing.txt'), PROTECTED))
        self.assertEqual(store.data['hosts'], before)
        self.assertTrue(store.data['error'])

    def test_empty_feed_does_not_wipe_lists(self):
        d = tempfile.mkdtemp()
        store = server.Store(os.path.join(d, 'cache.json'))
        server.refresh(store, None, FEED, PROTECTED)
        empty = os.path.join(d, 'empty.txt')
        open(empty, 'w').write('# nothing\n')
        self.assertFalse(server.refresh(store, None, empty, PROTECTED))
        self.assertTrue(store.data['hosts'])


class ExtraFeeds(unittest.TestCase):
    def test_extract_urls_formats(self):
        self.assertEqual(server.extract_urls(['https://a.example/x', '# c', '']), ['https://a.example/x'])
        js = json.dumps([{'url': 'https://b.example/p', 'phish_id': 1}, {'url': 'http://c.example/'}])
        self.assertEqual(server.extract_urls([js]), ['https://b.example/p', 'http://c.example/'])
        csv = ['phish_id,url,phish_detail_url', '5,https://d.example/login,http://x/y']
        self.assertEqual(server.extract_urls(csv), ['https://d.example/login'])

    def test_extra_feed_is_merged_and_failure_is_harmless(self):
        d = tempfile.mkdtemp()
        extra = os.path.join(d, 'extra.json')
        open(extra, 'w').write(json.dumps([{'url': 'https://charming-madeleine-c3ccb3.netlify.app/'}]))
        store = server.Store(os.path.join(d, 'cache.json'))
        ok = server.refresh(store, None, FEED, PROTECTED, ['file://' + extra, 'file://' + os.path.join(d, 'nope.json')])
        self.assertTrue(ok)
        self.assertIn('charming-madeleine-c3ccb3.netlify.app', store.data['hosts'])
        self.assertIn('rootonly-scam.com', store.data['hosts'])   # the main feed is still there


class AdblockFormats(unittest.TestCase):
    def test_adblock_and_hosts_lines(self):
        lines = ['! Title: Phishing URL Blocklist', '[Adblock Plus]', '||bad-one.example^', '||bad-two.example/login/kit^$all',
                 '||evil.example/a/b.html', '@@||good.example^', '0.0.0.0 hosts-style.example', '# comment']
        self.assertEqual(server.extract_urls(lines), ['https://bad-one.example', 'https://bad-two.example/login/kit',
                                                      'https://evil.example/a/b.html', 'https://hosts-style.example'])

    def test_mirror_fallback(self):
        d = tempfile.mkdtemp()
        good = os.path.join(d, 'curben.txt')
        open(good, 'w').write('! x\n||curben-phish.example^\n')
        store = server.Store(os.path.join(d, 'cache.json'))
        mirrors = 'file://' + os.path.join(d, 'dead.txt') + '|file://' + good
        self.assertTrue(server.refresh(store, None, FEED, PROTECTED, [mirrors]))
        self.assertIn('curben-phish.example', store.data['hosts'])


class Schedule(unittest.TestCase):
    def test_due_uses_wall_clock_and_backoff(self):
        self.assertFalse(server.refresh_due(1000, 1000 + 3599, 3600))
        self.assertTrue(server.refresh_due(1000, 1000 + 3600, 3600))
        self.assertTrue(server.refresh_due(1000, 1000 + 16 * 3600, 6 * 3600))     # a computer that slept for 16 hours
        self.assertFalse(server.refresh_due(1000, 1000 + 16 * 3600, 6 * 3600, not_before=1000 + 17 * 3600))


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = tempfile.mkdtemp()
        cls.store = server.Store(os.path.join(d, 'cache.json'))
        server.refresh(cls.store, None, FEED, PROTECTED)
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), server.make_handler(cls.store))
        cls.base = 'http://127.0.0.1:%d' % cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        return urllib.request.urlopen(req, timeout=5)

    def test_health(self):
        body = json.load(self.get('/api/v1/health'))
        self.assertTrue(body['ok'])
        self.assertGreater(body['hosts'], 0)

    def test_feed_and_etag(self):
        r = self.get('/api/v1/feed')
        body = json.load(r)
        self.assertIn('rootonly-scam.com', body['hosts'])
        self.assertTrue(isinstance(body['urls'], list))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get('/api/v1/feed', {'If-None-Match': r.headers['ETag']})
        self.assertEqual(cm.exception.code, 304)

    def test_lookup_endpoint(self):
        q = urllib.parse.quote('https://rootonly-scam.com/x', safe='')
        self.assertTrue(json.load(self.get('/api/v1/lookup?url=' + q))['listed'])

    def test_unknown_path(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.get('/nope')
        self.assertEqual(cm.exception.code, 404)


import urllib.parse  # noqa: E402  (used by the tests above)

if __name__ == '__main__':
    unittest.main(verbosity=1)
