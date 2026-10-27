# Phantom Click

Chrome / Edge (Manifest V3) extension that puts a **Safe / Warning / Risky** badge beside external links. Hover a badge for a quick result; click it for a detailed explanation that can use a separate URLvet server.

## Install
1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. **Load unpacked** and pick this folder (the one that contains `manifest.json`).
3. Serve the test page: `python -m http.server 8000` in this folder, then open `http://localhost:8000/test-page.html`.
4. After changing any file, press the reload arrow on the extension card, then refresh your pages with Ctrl+Shift+R.

## How the card works
| Action | What happens |
|---|---|
| Hover a badge | **Page 1** at once: status, risk score, checked type and domain, recommendation, the rules that matched. Uses only the local rules. Nothing is sent anywhere. |
| Click the badge, or press **More Detail analysis** | **Page 2**: checked and final domain, every rule explained, and the detailed analysis from URLvet (verdict, redirect chain, per-signal explanations). The card stays open until you press Esc or click elsewhere. |
| **Previous Page**, or click the badge again | Back to page 1. |
| Detailed analysis fails | The page-1 result stays. Page 2 says **Detailed analysis unavailable.** with a **Try again** button. |

The badge and page 1 never wait for URLvet: it is only requested when page 2 opens, and the badge is never changed by it.

## What gets a badge
| Kind | Badge position | Where the address comes from |
|---|---|---|
| Text link | Right after the end of the link text | the link's `href` |
| Image link (a link with no text: picture, icon) | **Top-right corner inside the picture** (beside it when the picture is smaller than about 60 x 40 px) | the link's `href` |
| Button | **Right beside the button** | the form's `action` (submit buttons), the button's `formaction`, or an address written in its `onclick` |

Only the page's markup is read; no page script is run. Links and buttons that stay on the same site (or the same owner's sites), buttons with no address, and plain-text URLs get no badge. The card's "Checked type" says Image link, Button or HTML link.

**Toolbar settings**
- *Show status text on badges*: turn it off and every badge shows only the status logo (blocked links get a ring around the logo).
- *Badge transparency*: a slider from 0% (solid) to 80% (very see-through). A badge turns solid when you point at it.
- *Dark mode*: dark colors for the toolbar menu and the hover card.
- *Detailed analysis (URLvet)*: on or off (see below).

## Detailed analysis with URLvet
Phantom Click calls the HTTP API of [URLvet](https://github.com/urlvet/urlvet), a separate program. No URLvet code or data lists are copied into this extension.

- **Nothing to set up:** it uses URLvet's public server (`https://api.url.vet`) automatically. The toolbar has one switch, **Detailed analysis (URLvet)** (on by default). Switch it off and page 2 says the analysis is turned off; nothing is ever sent.
- **When it runs:** only when you open page 2 of a link (click its badge or press More Detail analysis). Hovering never sends anything.
- **What is sent:** the address of that one link, to the URLvet server. The public server is meant for trying things out and limits each IP address to about 20 requests a minute; when the limit is hit, page 2 says so.
- **Using your own URLvet server instead** (for example a copy running on your computer): change the one line `DEFAULT_ENDPOINT` in `urlvet.js`, for example to `http://localhost:8080`. Plain `http://` is only accepted for localhost; any other server must use `https://`.

### Licence note (not legal advice)
URLvet is released under **AGPL-3.0** (with a separate commercial licence available from its authors). Calling its public API over HTTP from a separate program is the arrangement that keeps the two programs separate. Things that change the picture:
- Copying URLvet source or data into Phantom Click, or shipping URLvet inside the extension or a container you distribute, can make the combined work subject to AGPL: you would have to provide the corresponding source under the same licence.
- If you modify URLvet and let other people use that modified server over a network, AGPL section 13 requires you to offer them the source of your modified version.
- Using it unmodified for your own project, calling the API, is the simplest case. Check the AGPL text and URLvet's `COMMERCIAL.md` before distributing anything beyond your course or team.

## Editing the domain lists
Plain text files in `lists/`:

| File | What to put in it | Effect |
|---|---|---|
| `lists/known-safe.txt` | Trusted sites, one per line (`example.com`) | Not flagged as unfamiliar, path not checked for scam words, and the name is protected against lookalikes |
| `lists/known-phishing.txt` | Known scam domains, one per line | Always Risky (R-07). `example.com` covers its subdomains, `login.example.com` only that host |

Lines starting with `#` are comments, blank lines are ignored, and you can paste a full link (the extension keeps the domain). Saved results are cleared automatically when a list changes.

## Local rules (score and bands)
| Rule | Weight | Looks for |
|---|---|---|
| R-01 | 25 | `http://` instead of `https://` |
| R-02 | 25 | Unfamiliar domain with a warning sign (throwaway ending, many digits, random-looking name, raw IP, reserved `.example`) |
| R-03 | 30 | Unusual structure (IP address, `@`, very long, many parts, punycode, odd port, repeated slashes, shortener) |
| R-04 | 50 | Lookalike of a known brand (misspelling, digits for letters), the exact brand name on an ending the brand does not use, or a brand name stuck inside a longer made-up name (`studio9shopee.net`) |
| R-05 | 55 | Scam words in the path, or a hidden redirect address in the query |
| R-06 | 60 | A brand or login word in front of another domain, or in the name of a free page on a hosting platform |
| R-07 | 60 | Domain is in `lists/known-phishing.txt`, or on the OpenPhish or phishunt.io list from the feed backend |
| R-08 | 55 | The name or domain of another well-known site in the path (`/paypal/login`) |
| R-09 | 30 | Looks like a sign-in page kit (script page with sign-in words, long random code, hidden folder) |
| R-10 | 30 | A second web address hidden inside the link (`?url=https://other-site`) |
| R-13 | 55 | A file with a double ending that hides a program (`invoice.pdf.exe`) |
| R-14 | 30 | Scam lure words in the domain name itself (`dhl-parcel-tracking.top`, `free-robux.com`) |
| R-12 | 30 | The automatic name a free host gives a new site, left unchanged (`charming-madeleine-c3ccb3.netlify.app`) |
| R-11 | 30 | Downloads a program (`.exe`, `.apk`...) from an unfamiliar site; also flagged on any site when it hides behind a double ending like `.pdf.exe` |

Each matched rule counts once, the total is capped at 100, and a High rule (R-04 to R-08, R-13) raises the score to at least 51. Safe 0–20, Warning 21–50, Risky 51–100. A link that could not be checked scores at least 25 and is never Safe.

## Files
| File | Job |
|---|---|
| `manifest.json` | Extension definition and permissions (`storage` + http/https hosts) |
| `rules.js` | The seven rules, scoring, thresholds (`CONFIG`), list loading |
| `content.js` / `content.css` | Link detection, badges, the two-page card, block option, cache |
| `background.js` | Reads `lists/*.txt`, resolves redirects (HEAD, 5 s, queue of 4), calls the URLvet server on request |
| `urlvet.js` | Builds the URLvet request and turns its report into the summary shown on page 2 |
| `popup.html/css/js`, `theme.js` | Toolbar panel: page switch, badge text switch, transparency slider, dark mode, URLvet switch, excluded sites (`theme.js` applies dark mode before the menu is drawn) |
| `lists/*.txt` | Known safe and known phishing domains |
| `tests/` | `node tests/rules.test.js` and `node tests/urlvet.test.js` |
| `test-page.html` | Test links with calculated expected results, plus a box for your own links |

## Notes
- Redirects made by a page's own scripts (not by HTTP) are not followed by the quick check. URLvet's detailed analysis can reveal more of them.
- Links inside frames and web components get no badge. A button whose address is only set by a page script is not seen.
- Block URL (Warning and Risky links) cancels clicks from the page. It cannot stop "open in new tab" from the browser menu or dragging the link.
- Running the test page as a `file://` page needs "Allow access to file URLs" in the extension details.


## Phishing feed (OpenPhish) via the backend
`backend/server.py` downloads the OpenPhish community feed and the phishunt.io feed (CC0) every 3 hours (and right after the computer wakes from sleep) and serves a cleaned copy (setup, options and OpenPhish terms: `backend/README.md`).
The extension copies that list (checking hourly) and rule R-07 matches links against it on your computer, so the links you browse are never sent to the backend.
There is nothing to set up in the popup: it connects to the backend on this computer (http://localhost:8787) by itself.

After a redirect that ends on a secure page of a trusted site, the original link's weaker findings are dropped (for example `canva.link` leads to `canva.com`).
Things that need the internet (domain age, popularity ranking, DNS and email setup) are left to the URLvet detailed analysis.
Tests: `node tests/feed.test.js` and, in `backend/`, `PYTHONPATH=. python test_server.py`.

## Bundled phishing snapshot
`lists/phishing-snapshot.json` is a ready-made list that works without the backend: about 1,600 throwaway sites and 2,500 folders on hacked sites, cut down from the Phishing.Database list (about 790,000 links; check its licence before you share this project). The extension checks it together with the live feed.
It is deliberately small and careful: trusted sites, shared services (storage, IPFS, mail, forms), shorteners and raw IP addresses are never included, and ordinary-looking sites that were probably hacked are listed by folder, not as a whole site.
It goes out of date as phishing pages are taken down. To make a fresh one: `node tools/build-snapshot.js phishing-links-ACTIVE.txt lists/phishing-snapshot.json "Phishing.Database"`.

## Credits
Phishing data comes from OpenPhish and phishunt.io (CC0). Full credits and licence notes: `NOTICE.md`.
