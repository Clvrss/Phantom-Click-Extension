/* Phantom Click - theme.js: sets the popup's colours before it is drawn (no light flash in dark mode). */
try { if (localStorage.getItem('pcDark') === '1') document.documentElement.dataset.theme = 'dark'; } catch (e) { /* ignore */ }
