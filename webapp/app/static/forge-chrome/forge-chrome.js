/*!
 * forge-chrome.js — FORGE_CHROME_VERSION 1.0.0
 *
 * THE single markup renderer for the shared FORGE header/footer chrome.
 * SoT: (upstream forge_core)
 * (consumer apps carry a vendored copy under <static>/forge-chrome/ —
 * synced by forge_core/scripts/sync_chrome.py, never hand-edited).
 *
 * Ratified: PRESCAB full cabinet 2026-08-17 (10/10 YES, 3/3 rounds,
 * (upstream forge_core)), evolving the
 * 2026-08-01 chrome ruling. Spec:
 * /srv/forge/modules/ivaldi/docs/SPEC_forge_shared_chrome_20260811.md §3-§4, §6.
 *
 * Contract (spec §4.1/§4.2):
 *   - ES5-safe IIFE, zero dependencies, no build step, same-origin only.
 *   - window.ForgeChrome.mount(config) renders header+footer; pages emitted
 *     by forge_core.chrome's Python shims auto-mount via
 *     <div data-forge-chrome='{json}'> tags on DOMContentLoaded.
 *   - Modules dropdown hydrates async from config.modulesUrl (default
 *     /chrome/modules.json, served by forge_core.router). Fetch failure or
 *     404 degrades to "modules list unavailable" — never throws, never
 *     breaks the host page.
 *   - Command palette (Ctrl+K / Cmd+K): additive to the dropdown, does NOT
 *     share its state. Feature flag: mount({palette:false}) disables it
 *     per-app; default true (cabinet ratification condition, Item B).
 *   - Theme: canonical localStorage key 'forge-theme' -> data-theme on
 *     <html>; prefers-color-scheme is the unset-state fallback.
 *     config.legacyThemeKey migrates an app's old key once (spec §4.3).
 *   - Chrome touches only .forge-* classes / --fc-* tokens and never styles
 *     host elements; slots (headerTools/footerItems) are adopted into
 *     position, not restyled.
 */
(function () {
  'use strict';
  if (window.ForgeChrome) { return; } // idempotent under double-include

  var FORGE_CHROME_VERSION = '1.0.0';
  var THOTH_URL = '';            // HavnVard public copy: no default; pass cfg.thothUrl to show the link
  var DEFAULT_SUPPORT_URL = '';  // HavnVard public copy: no default; pass cfg.supportUrl to show the link
  var THEME_KEY = 'forge-theme'; // ONE fleet-wide key (spec §4.2) — follows you across apps
  var DEFAULT_MODULES_URL = '/chrome/modules.json';

  /* ------------------------------------------------------------------ *
   * shared state (module-scoped, one chrome per page)                   *
   * ------------------------------------------------------------------ */
  var pending = [];          // configs waiting for DOM ready
  var domReady = false;
  var globalsWired = false;  // document-level listeners installed once
  var themeInited = false;

  // modules dropdown / palette data. "modules" stays null until hydration
  // resolves; "modulesFailed" marks a fetch that came back bad.
  var modules = null;
  var modulesFailed = false;
  var modulesRequested = false;
  var menuPanels = [];       // every rendered .forge-menu-panel (usually 1)
  var currentModuleKey = ''; // excluded from the dropdown

  // command palette
  var paletteEnabled = true; // any mounted config with palette:false wins OFF
  var paletteNav = [];       // appNav entries searchable alongside modules
  var pal = null;            // { overlay, input, results }
  var palIndex = 0;
  var palRows = [];          // currently rendered result rows

  /* ------------------------------------------------------------------ *
   * tiny helpers                                                        *
   * ------------------------------------------------------------------ */
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }

  function el(tag, className, html) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (html != null) { node.innerHTML = html; }
    return node;
  }

  function lsGet(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function lsSet(key, val) {
    try { window.localStorage.setItem(key, val); } catch (e) { /* private mode etc. */ }
  }

  /* ------------------------------------------------------------------ *
   * theme — one key, data-theme on <html>, media-query fallback         *
   * ------------------------------------------------------------------ */
  function initTheme(legacyKey) {
    if (themeInited) { return; }
    themeInited = true;
    var saved = lsGet(THEME_KEY);
    if (!saved && legacyKey) {
      // one-time migration off a per-app key (ivaldi-theme, kvasir-theme, ...):
      // copy across, then only ever read forge-theme (spec §4.3).
      var legacy = lsGet(legacyKey);
      if (legacy === 'light' || legacy === 'dark') {
        saved = legacy;
        lsSet(THEME_KEY, legacy);
      }
    }
    if (saved === 'light' || saved === 'dark') {
      document.documentElement.setAttribute('data-theme', saved);
    }
    // unset -> leave attribute absent; CSS prefers-color-scheme decides.
  }

  function toggleTheme() {
    var root = document.documentElement;
    var cur = root.getAttribute('data-theme');
    if (cur !== 'light' && cur !== 'dark') {
      cur = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
        ? 'dark' : 'light';
    }
    var next = (cur === 'dark') ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    lsSet(THEME_KEY, next);
  }
  // back-compat with the previous CHROME_JS public hook
  window.forgeToggleTheme = toggleTheme;

  /* ------------------------------------------------------------------ *
   * modules list — async hydration, graceful degradation                *
   * ------------------------------------------------------------------ */
  function setPanelsHTML(html) {
    var i;
    for (i = 0; i < menuPanels.length; i++) { menuPanels[i].innerHTML = html; }
  }

  function renderModulesIntoPanels() {
    if (modulesFailed || modules === null) {
      setPanelsHTML('<span class="forge-menu-empty">modules list unavailable</span>');
      return;
    }
    var others = [];
    var i;
    for (i = 0; i < modules.length; i++) {
      if (modules[i] && modules[i].key !== currentModuleKey) { others.push(modules[i]); }
    }
    if (!others.length) {
      setPanelsHTML('<span class="forge-menu-empty">no other live modules found</span>');
      return;
    }
    var html = '';
    for (i = 0; i < others.length; i++) {
      html += '<a href="' + esc(others[i].url) + '" target="_blank" rel="noopener">'
        + esc(others[i].label) + '</a>';
    }
    setPanelsHTML(html);
  }

  function modulesArrived(list) {
    modules = list;
    modulesFailed = false;
    renderModulesIntoPanels();
    refreshPaletteResults();
  }

  function modulesUnavailable() {
    modulesFailed = true;
    renderModulesIntoPanels();
    refreshPaletteResults();
  }

  function hydrateModules(cfg) {
    if (modulesRequested) { return; }
    modulesRequested = true;

    // inline override (Python shim's modules= kwarg / tests): no fetch at all
    if (cfg.modules && cfg.modules.length !== undefined) {
      modulesArrived(cfg.modules);
      return;
    }
    var url = cfg.modulesUrl || DEFAULT_MODULES_URL;
    if (!window.fetch) { modulesUnavailable(); return; }
    try {
      window.fetch(url, { credentials: 'same-origin' })
        .then(function (res) {
          if (!res.ok) { throw new Error('HTTP ' + res.status); }
          return res.json();
        })
        .then(function (body) {
          if (!body || Object.prototype.toString.call(body.modules) !== '[object Array]') {
            throw new Error('bad modules.json shape');
          }
          modulesArrived(body.modules);
        })
        .catch(function () { modulesUnavailable(); }); // 404 / down / bad JSON: degrade, never throw
    } catch (e) {
      modulesUnavailable();
    }
  }

  /* ------------------------------------------------------------------ *
   * slots — adopt host DOM nodes into chrome positions (never restyle)  *
   * ------------------------------------------------------------------ */
  function adoptSlot(selector, container) {
    if (!selector || !container) { return; }
    var node = null;
    try { node = document.querySelector(selector); } catch (e) { /* bad selector: skip */ }
    if (node) { container.appendChild(node); }
  }

  /* ------------------------------------------------------------------ *
   * header / footer builders                                            *
   * ------------------------------------------------------------------ */
  function buildHeader(cfg) {
    var hdr = el('header', 'forge-hdr');
    hdr.setAttribute('data-fc-version', FORGE_CHROME_VERSION); // skew diagnosable from view-source (spec §6)
    if (cfg.moduleKey) { hdr.setAttribute('data-module', cfg.moduleKey); }

    var html = '<a class="forge-brand" href="' + esc(cfg.homeUrl || '/') + '">'
      + esc(cfg.moduleName || cfg.moduleKey || 'FORGE') + '</a>'
      + '<div class="forge-menu">'
      + '<button class="forge-menu-btn" type="button" aria-haspopup="true" '
      + 'aria-expanded="false" aria-label="other FORGE modules">modules ▾</button>'
      + '<div class="forge-menu-panel">'
      + '<span class="forge-menu-empty">loading…</span></div>'
      + '</div>';

    if (cfg.appNav && cfg.appNav.length) {
      html += '<nav class="forge-appnav" aria-label="' + esc(cfg.moduleName || '') + ' navigation">';
      var i;
      for (i = 0; i < cfg.appNav.length; i++) {
        var item = cfg.appNav[i] || {};
        html += '<a class="forge-appnav-link' + (item.active ? ' forge-appnav-active' : '')
          + '" href="' + esc(item.href || '#') + '"'
          + (item.active ? ' aria-current="page"' : '') + '>'
          + esc(item.label || '') + '</a>';
      }
      html += '</nav>';
    }

    html += '<span class="forge-tools"></span>'
      + '<div class="forge-right">';
    if (paletteEnabled) {
      html += '<button class="forge-palette-btn" type="button" '
        + 'title="command palette (Ctrl+K)" aria-label="open command palette">'
        + '⌘K</button>';
    }
    html += '<span class="forge-env" data-env="' + esc(cfg.env || 'prod') + '">'
      + esc(cfg.env || 'prod') + '</span>';
    if (cfg.settingsUrl) {
      html += '<a class="forge-settings" href="' + esc(cfg.settingsUrl) + '">settings</a>';
    }
    html += '<button class="forge-theme-btn" type="button" title="toggle theme" '
      + 'aria-label="toggle theme">◐</button>'
      + '</div>';

    hdr.innerHTML = html;
    menuPanels.push(hdr.querySelector('.forge-menu-panel'));
    adoptSlot(cfg.slots && cfg.slots.headerTools, hdr.querySelector('.forge-tools'));
    return hdr;
  }

  function footerLinks(cfg) {
    var links = [];
    var registry = cfg.thothUrl || THOTH_URL;
    var support = cfg.supportUrl || DEFAULT_SUPPORT_URL;
    if (registry) {
      links.push('<a href="' + esc(registry) + '" target="_blank" rel="noopener">what else is running</a>');
    }
    if (support) { links.push('<a href="' + esc(support) + '">feedback</a>'); }
    return links.join(' · ');
  }

  function buildFooter(cfg) {
    var ftr = el('footer', 'forge-ftr');
    if (cfg.moduleKey) { ftr.setAttribute('data-module', cfg.moduleKey); }
    var name = esc(cfg.moduleName || cfg.moduleKey || 'FORGE');
    var version = cfg.version ? ' · ' + esc(cfg.version) : '';
    ftr.innerHTML = '<span>' + name + version + '</span>'
      + '<span class="forge-ftr-items"></span>'
      + '<span>' + footerLinks(cfg) + '</span>';
    adoptSlot(cfg.slots && cfg.slots.footerItems, ftr.querySelector('.forge-ftr-items'));
    return ftr;
  }

  /* ------------------------------------------------------------------ *
   * dropdown open/close (event delegation, same pattern as before)      *
   * ------------------------------------------------------------------ */
  function closeMenus() {
    var open = document.querySelectorAll('.forge-menu.forge-open');
    var i;
    for (i = 0; i < open.length; i++) {
      open[i].classList.remove('forge-open');
      var btn = open[i].querySelector('.forge-menu-btn');
      if (btn) { btn.setAttribute('aria-expanded', 'false'); }
    }
  }

  function anyMenuOpen() {
    return !!document.querySelector('.forge-menu.forge-open');
  }

  /* ------------------------------------------------------------------ *
   * command palette (Ctrl+K / Cmd+K) — additive, own state, feature-    *
   * flagged. Search space = live modules list + appNav entries.         *
   * Behavior ported from the cabinet-selected Concept B mockup          *
   * ((upstream forge_core)). *
   * ------------------------------------------------------------------ */
  function ensurePalette() {
    if (pal || !paletteEnabled) { return; }
    var overlay = el('div', 'forge-palette-overlay');
    overlay.innerHTML =
      '<div class="forge-palette" role="dialog" aria-modal="true" aria-label="FORGE command palette">'
      + '<input class="forge-palette-input" type="text" '
      + 'placeholder="Jump to a module…" autocomplete="off" '
      + 'aria-label="search modules">'
      + '<div class="forge-palette-results"></div>'
      + '<div class="forge-palette-hint">↑↓ select · Enter open · Esc close</div>'
      + '</div>';
    document.body.appendChild(overlay);
    pal = {
      overlay: overlay,
      input: overlay.querySelector('.forge-palette-input'),
      results: overlay.querySelector('.forge-palette-results')
    };

    pal.input.addEventListener('input', function () { refreshPaletteResults(); });

    // focus trap + result navigation, on the overlay so it owns its keys
    overlay.addEventListener('keydown', function (e) {
      if (e.key === 'Tab') { // trap: focus stays in the input
        e.preventDefault();
        pal.input.focus();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        movePaletteSelection(1);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        movePaletteSelection(-1);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        activatePaletteSelection();
      }
      // Escape is handled by the document-level handler (closes whichever
      // of dropdown/palette is open — shared pattern, spec Item B).
    });

    // outside-click (backdrop) closes
    overlay.addEventListener('mousedown', function (e) {
      if (e.target === overlay) { closePalette(); }
    });
  }

  function paletteItems() {
    var items = [];
    var i;
    for (i = 0; i < paletteNav.length; i++) {
      items.push({
        label: paletteNav[i].label || '',
        href: paletteNav[i].href || '#',
        kind: 'page'
      });
    }
    if (modules && !modulesFailed) {
      for (i = 0; i < modules.length; i++) {
        items.push({
          label: modules[i].label || modules[i].key || '',
          href: modules[i].url || '#',
          kind: 'module'
        });
      }
    }
    return items;
  }

  function refreshPaletteResults() {
    if (!pal) { return; }
    var q = (pal.input.value || '').toLowerCase();
    var items = paletteItems();
    var shown = [];
    var i;
    for (i = 0; i < items.length; i++) {
      if (!q || items[i].label.toLowerCase().indexOf(q) !== -1) { shown.push(items[i]); }
    }
    var html = '';
    for (i = 0; i < shown.length; i++) {
      html += '<div class="forge-palette-result" data-href="' + esc(shown[i].href) + '">'
        + '<span>' + esc(shown[i].label) + '</span>'
        + '<span class="forge-palette-kind">' + shown[i].kind + '</span>'
        + '</div>';
    }
    if (!shown.length) {
      html = '<div class="forge-palette-empty">'
        + (modulesFailed && !paletteNav.length
          ? 'modules list unavailable' : 'no matches') + '</div>';
    }
    pal.results.innerHTML = html;
    palRows = pal.results.querySelectorAll('.forge-palette-result');
    palIndex = 0;
    markPaletteSelection();
  }

  function markPaletteSelection() {
    var i;
    for (i = 0; i < palRows.length; i++) {
      if (i === palIndex) { palRows[i].classList.add('forge-palette-sel'); }
      else { palRows[i].classList.remove('forge-palette-sel'); }
    }
    if (palRows.length && palRows[palIndex] && palRows[palIndex].scrollIntoView) {
      palRows[palIndex].scrollIntoView({ block: 'nearest' });
    }
  }

  function movePaletteSelection(delta) {
    if (!palRows.length) { return; }
    palIndex = (palIndex + delta + palRows.length) % palRows.length;
    markPaletteSelection();
  }

  function activatePaletteSelection() {
    if (!palRows.length || !palRows[palIndex]) { return; }
    var href = palRows[palIndex].getAttribute('data-href');
    if (href) { window.location.href = href; }
  }

  function openPalette() {
    if (!paletteEnabled) { return; }
    ensurePalette();
    if (!pal) { return; }
    closeMenus(); // palette and dropdown never open together (independent state otherwise)
    pal.overlay.classList.add('forge-palette-open');
    pal.input.value = '';
    refreshPaletteResults();
    window.setTimeout(function () { pal.input.focus(); }, 0);
  }

  function closePalette() {
    if (pal) { pal.overlay.classList.remove('forge-palette-open'); }
  }

  function paletteIsOpen() {
    return !!(pal && pal.overlay.classList.contains('forge-palette-open'));
  }

  /* ------------------------------------------------------------------ *
   * global listeners — installed once, event delegation on document     *
   * ------------------------------------------------------------------ */
  function wireGlobals() {
    if (globalsWired) { return; }
    globalsWired = true;

    document.addEventListener('click', function (e) {
      var t = e.target;
      var closest = t.closest ? function (sel) { return t.closest(sel); }
        : function () { return null; };

      var menuBtn = closest('.forge-menu-btn');
      if (menuBtn) {
        var menu = menuBtn.closest('.forge-menu');
        var wasOpen = menu.classList.contains('forge-open');
        closeMenus();
        if (!wasOpen) {
          menu.classList.add('forge-open');
          menuBtn.setAttribute('aria-expanded', 'true');
        } else {
          menuBtn.blur();
        }
        e.preventDefault();
        return;
      }
      if (closest('.forge-theme-btn')) { toggleTheme(); return; }
      if (closest('.forge-palette-btn')) { openPalette(); return; }
      var row = closest('.forge-palette-result');
      if (row) {
        var href = row.getAttribute('data-href');
        if (href) { window.location.href = href; }
        return;
      }
      if (!closest('.forge-menu-panel')) { closeMenus(); } // outside click
    });

    document.addEventListener('keydown', function (e) {
      var key = (e.key || '').toLowerCase();
      if ((e.ctrlKey || e.metaKey) && key === 'k' && paletteEnabled) {
        e.preventDefault();
        if (paletteIsOpen()) { closePalette(); } else { openPalette(); }
      } else if (e.key === 'Escape') {
        // closes whichever of dropdown/palette is open (spec Item B)
        if (paletteIsOpen()) { closePalette(); }
        else if (anyMenuOpen()) { closeMenus(); }
      }
    });
  }

  /* ------------------------------------------------------------------ *
   * mounting                                                            *
   * ------------------------------------------------------------------ */
  function mountOne(cfg, target) {
    if (cfg.palette === false) { paletteEnabled = false; }
    if (cfg.moduleKey) { currentModuleKey = cfg.moduleKey; }
    if (cfg.appNav && cfg.appNav.length) { paletteNav = cfg.appNav; }
    initTheme(cfg.legacyThemeKey);
    wireGlobals();

    var which = cfg.mount; // 'header' | 'footer' | undefined (= both)
    if (which !== 'footer') {
      var hdr = buildHeader(cfg);
      if (target) { target.appendChild(hdr); }
      else if (document.body.firstChild) { document.body.insertBefore(hdr, document.body.firstChild); }
      else { document.body.appendChild(hdr); }
    }
    if (which !== 'header') {
      var ftr = buildFooter(cfg);
      if (target && which === 'footer') { target.appendChild(ftr); }
      else { document.body.appendChild(ftr); }
    }
    if (which !== 'footer') { hydrateModules(cfg); } // header owns nav data
  }

  function flush() {
    // auto-mount shim tags first (their position in the page is meaningful)
    var tags = document.querySelectorAll('[data-forge-chrome]');
    var i;
    for (i = 0; i < tags.length; i++) {
      var node = tags[i];
      if (node.getAttribute('data-forge-chrome-mounted')) { continue; }
      var raw = node.getAttribute('data-forge-chrome');
      if (!raw) { continue; } // bare placeholder div: explicit mount() targets it? no — skip
      var cfg;
      try { cfg = JSON.parse(raw); } catch (e) { continue; } // bad config: never break the page
      node.setAttribute('data-forge-chrome-mounted', '1');
      mountOne(cfg, node);
    }
    // then explicit ForgeChrome.mount(config) calls (static apps)
    while (pending.length) { mountOne(pending.shift(), null); }
  }

  function onReady() {
    domReady = true;
    flush();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', onReady);
  } else {
    domReady = true;
    // shim tags may already be in the DOM (script is deferred): mount them
    window.setTimeout(flush, 0);
  }

  window.ForgeChrome = {
    version: FORGE_CHROME_VERSION,
    mount: function (config) {
      pending.push(config || {});
      if (domReady) { flush(); }
    }
  };
})();
