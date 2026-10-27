# Phantom Click feed backend

Downloads the OpenPhish community feed, cleans it, and serves it to the extension.
Python 3.8+, standard library only (nothing to install).

## Run it

    cd backend
    python server.py

(on Windows: `py server.py`). It listens on http://127.0.0.1:8787 and downloads the feed straight away,
then again every 3 hours (`--refresh-hours`, minimum 1). The free OpenPhish feed itself only changes
about every 12 hours, so asking much more often gives nothing new. The backend looks at the clock every minute,
so if the computer was asleep it downloads again as soon as it wakes up.

If a download fails, or comes back empty, the old list is kept and it retries after 15 minutes.
The last good list is saved in `backend/data/`, so a restart works even before the first download.

## Connect the extension

Nothing to click: the extension finds the backend by itself.
The default address already matches this server. The extension asks the backend every 5 minutes whether it has a newer list (a very small request) and downloads it right away when it does.

## phishunt.io feed (on by default)

The backend also downloads the free [phishunt.io](https://phishunt.io/feed/) feed (`https://phishunt.io/feed.txt`, one phishing URL per line), which its owner updates every hour.
It is released under CC0 (public domain); the terms ask only that you do not call a listed site "confirmed phishing" on the listing alone, and they limit requests to 10 per second (we make one every 3 hours). Turn it off with `python server.py --no-phishunt`.
I could not download it from where I built this, so it is tested with sample lines in the same format, not the real file. Check the first run's console output: it prints how many links each source gave.
Curben's phishing-filter (CC BY-SA 4.0) is no longer used by default; you can still add it with `--extra-feed`.

## More feeds (PhishTank and others)

OpenPhish is only one list, and a new phishing page can be on PhishTank hours before it reaches OpenPhish.
Add more sources with `--extra-feed` (repeat it for each one). Plain link lists, CSV and PhishTank JSON all work:

    python server.py --extra-feed https://data.phishtank.com/data/YOUR_APP_KEY/online-valid.json.gz

PhishTank needs a free app key from phishtank.com (check their terms and whether they are accepting new keys).
If one extra feed is down or refuses you, the others still load. I could not test the live PhishTank or OpenPhish downloads from where I built this; the merge itself is tested with local files.
Very large lists (like the whole Phishing.Database dump, over 700,000 links) are not a good fit: the extension keeps the list in the browser, so it would become slow.

## Useful options

    python server.py --port 8787 --refresh-hours 3
    python server.py --feed-file sample-feed.txt     # offline test with the small sample list

Check it: open http://127.0.0.1:8787/api/v1/health in a browser.

## Privacy

The extension downloads the whole cleaned list and matches links on your computer.
The links you browse are never sent to the backend.

## OpenPhish terms

The community feed is for **non-commercial use** and is subject to the OpenPhish Terms of Use
(https://openphish.com/terms.html). Read them before you use it beyond this course project.
The server uses a normal `GET` on `https://openphish.com/feed.txt`; do not lower the refresh interval to hammer it.

## Tests

    PYTHONPATH=. python test_server.py

## Is the extension fetching?

Every time the extension downloads the list, this window prints a line like:

    18:42:02  the extension asked for the list (404 sites, 7954 pages)

It does this when the browser starts, every hour after that, and a few minutes after you start the backend if it was off.
To see it happen right now: open `chrome://extensions`, click **service worker** under Phantom Click, and in the Console type `syncFeed()`.
