# Third-party data credits

Phantom Click's "Known phishing domain" check (rule R-07) uses lists of reported phishing sites from:

- **OpenPhish** - community feed, https://openphish.com. Used under OpenPhish's terms for the free community feed (non-commercial use). Check https://openphish.com before any commercial use.
- **phishunt.io** - free phishing feed, https://phishunt.io/feed/. Data released under **CC0 1.0 (public domain)**; attribution is welcome but not required. Terms: https://phishunt.io/tos/ (a listing is a suspicion, not a verdict).
- **Phishing.Database** (bundled snapshot in `lists/phishing-snapshot.json`) - https://github.com/mitchellkrogza/Phishing.Database. Check its license before redistributing.

The feed is downloaded by `backend/server.py`, cleaned, and served to the extension. Data is credited to its owners and is not our own work.
