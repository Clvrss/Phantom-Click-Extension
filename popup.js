/* Phantom Click - popup.js: page switch and excluded sites (FR-34..FR-37). */
'use strict';

const $ = (id) => document.getElementById(id);
const toggle = $('toggle'), list = $('excludeList'), msg = $('formMsg');
let excluded = [];
let pageHost = null;

const matches = (host, d) => host === d || host.endsWith('.' + d);

function normalize(input) {
  let v = String(input || '').trim().toLowerCase();
  if (!v) return null;
  v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].replace(/^www\./, '').replace(/:\d+$/, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(v) ? v : null;
}

function save(next) {
  excluded = [...new Set(next)];
  return chrome.storage.local.set({ excluded }).then(render);
}

function render() {
  list.textContent = '';
  excluded.forEach((d) => {
    const li = document.createElement('li');
    li.append(document.createTextNode(d));
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = '\u00d7';
    b.setAttribute('aria-label', 'Remove ' + d + ' from excluded sites');
    b.addEventListener('click', () => save(excluded.filter((x) => x !== d)));
    li.append(b);
    list.append(li);
  });
  if (pageHost) toggle.checked = !excluded.some((d) => matches(pageHost, d));
}

toggle.addEventListener('change', () => {
  if (!pageHost) return;
  if (toggle.checked) save(excluded.filter((d) => !matches(pageHost, d)));  // turn on: remove matching exclusions
  else save(excluded.concat(pageHost));                                      // turn off for this site
});

$('excludeForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const d = normalize($('excludeInput').value);
  msg.className = 'msg';
  if (!d) { msg.textContent = 'Enter a domain such as example.com.'; return; }
  if (excluded.includes(d)) { msg.textContent = d + ' is already excluded.'; return; }
  save(excluded.concat(d)).then(() => {
    $('excludeInput').value = '';
    msg.className = 'msg ok';
    msg.textContent = d + ' will not be checked.';
  });
});

// ---- display and analysis settings
$('labelToggle').addEventListener('change', (e) => chrome.storage.local.set({ badgeIconOnly: !e.target.checked }));
function applyTheme(on) {
  document.documentElement.dataset.theme = on ? 'dark' : 'light';
  try { localStorage.setItem('pcDark', on ? '1' : '0'); } catch (e) { /* ignore */ }
}
$('darkToggle').addEventListener('change', (e) => { applyTheme(e.target.checked); chrome.storage.local.set({ darkMode: e.target.checked }); });
$('urlvetToggle').addEventListener('change', (e) => chrome.storage.local.set({ urlvetEnabled: e.target.checked }));

const slider = $('transparency'), sliderOut = $('transparencyOut');
slider.addEventListener('input', () => {
  sliderOut.textContent = slider.value + '%';
  chrome.storage.local.set({ badgeTransparency: Number(slider.value) });   // applied live on open pages
});

(async function init() {
  const data = await chrome.storage.local.get(['excluded', 'badgeIconOnly', 'badgeTransparency', 'urlvetEnabled', 'darkMode']);
  excluded = Array.isArray(data.excluded) ? data.excluded : [];
  $('labelToggle').checked = !data.badgeIconOnly;
  $('urlvetToggle').checked = data.urlvetEnabled !== false;
  $('darkToggle').checked = !!data.darkMode;
  applyTheme(!!data.darkMode);
  const tr = Math.min(80, Math.max(0, Number(data.badgeTransparency) || 0));
  slider.value = String(tr);
  sliderOut.textContent = tr + '%';
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const u = tab && tab.url ? new URL(tab.url) : null;
    if (u && (u.protocol === 'http:' || u.protocol === 'https:')) {
      pageHost = u.hostname.replace(/^www\./, '');
      $('pageHost').textContent = pageHost;
    }
  } catch (e) { /* no active tab */ }
  if (!pageHost) {
    toggle.disabled = true;
    $('pageHost').textContent = 'Open a web page to use this switch.';
  }
  render();
})();
