/* CT Search: certificates logged in public Certificate Transparency logs for a domain.
   Sources (both send Access-Control-Allow-Origin: *): crt.sh first, Cert Spotter as fallback.
   No dependencies, no inline code (CSP: script-src 'self'). */
(function () {
  'use strict';

  var CRT_BASE = 'https://crt.sh/';
  var SPOTTER_BASE = 'https://api.certspotter.com/v1/issuances';
  var CRT_TIMEOUT_MS = 45000;
  var SPOTTER_TIMEOUT_MS = 20000;
  var SPOTTER_MAX_PAGES = 8;   // up to 100 issuances per page; the free quota is ~10 requests per hour
  var CHUNK = 100;             // rows rendered per step
  var SOON_DAYS = 30;
  var DAY = 86400000;

  var $ = function (id) { return document.getElementById(id); };
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- Domain handling ----
  function normalizeDomain(input) {
    return String(input || '').trim().toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^.*@/, '').replace(/[\/?#:].*$/, '')
      .replace(/^\*\./, '').replace(/^\.+/, '').replace(/\.+$/, '');
  }
  // Strict hostname check: at least two LDH labels, no IP address, no empty labels, TLD not all digits.
  function validDomain(d) {
    if (!d || d.length > 253 || d.indexOf('.') === -1) return false;
    var labels = d.split('.');
    var ok = labels.every(function (l) { return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l); });
    if (!ok) return false;
    return /[a-z]/.test(labels[labels.length - 1]);
  }
  function crtUrl(domain, hideExpired) {
    return CRT_BASE + '?q=' + encodeURIComponent('%.' + domain) + '&output=json' + (hideExpired ? '&exclude=expired' : '');
  }
  function spotterUrl(domain, after) {
    return SPOTTER_BASE + '?domain=' + encodeURIComponent(domain) + '&include_subdomains=true&expand=dns_names&expand=issuer' +
      (after ? '&after=' + encodeURIComponent(after) : '');
  }
  function curlCommand(domain, hideExpired) {
    return "curl -s '" + crtUrl(domain, hideExpired) + "' | jq -r '.[] | [.not_before,.not_after,.issuer_name,.serial_number,(.name_value|gsub(\"\\n\";\" \"))] | @tsv'";
  }

  // ---- Fetching ----
  async function getJson(url, ms) {
    var ctl = new AbortController();
    var timer = setTimeout(function () { ctl.abort(); }, ms);
    try {
      var res = await fetch(url, { signal: ctl.signal, headers: { Accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (!res.ok) { var e = new Error('HTTP ' + res.status); e.status = res.status; throw e; }
      var text = await res.text();
      try { return JSON.parse(text); } catch (x) { throw new Error('the service did not return JSON'); }
    } catch (err) {
      if (err && err.name === 'AbortError') throw new Error('timed out after ' + Math.round(ms / 1000) + ' s');
      if (err instanceof TypeError) throw new Error('network error or blocked by the browser');
      throw err;
    } finally { clearTimeout(timer); }
  }

  function parseDate(s) {
    if (!s) return NaN;
    var t = String(s);
    if (!/[zZ]|[+-]\d\d:?\d\d$/.test(t)) t += 'Z'; // crt.sh dates are UTC without a zone mark
    return Date.parse(t);
  }

  // crt.sh row -> cert. A cert is logged as precert and final cert: rows are merged by issuer + serial.
  function fromCrt(rows) {
    var map = Object.create(null), out = [];
    rows.forEach(function (r) {
      if (!r || typeof r !== 'object') return;
      var key = r.issuer_ca_id + '|' + r.serial_number;
      var names = String(r.name_value || '').split('\n').map(function (n) { return n.trim().toLowerCase(); }).filter(Boolean);
      var c = map[key];
      if (!c) {
        c = map[key] = { cn: String(r.common_name || '').toLowerCase(), names: [], issuer: String(r.issuer_name || ''), nb: parseDate(r.not_before), na: parseDate(r.not_after), serial: String(r.serial_number || ''), entries: 0, nameSet: Object.create(null) };
        out.push(c);
      }
      c.entries++;
      names.forEach(function (n) { if (!c.nameSet[n]) { c.nameSet[n] = true; c.names.push(n); } });
    });
    return out;
  }
  // Cert Spotter issuance -> cert (no serial or common name in this response).
  function fromSpotter(rows) {
    var map = Object.create(null), out = [];
    rows.forEach(function (r) {
      if (!r || typeof r !== 'object') return;
      var key = r.cert_sha256 || r.id;
      if (map[key]) return;
      var names = (r.dns_names || []).map(function (n) { return String(n).trim().toLowerCase(); }).filter(Boolean);
      map[key] = true;
      out.push({ cn: '', names: names, issuer: r.issuer && r.issuer.name ? String(r.issuer.name) : (r.issuer && r.issuer.friendly_name) || '', nb: parseDate(r.not_before), na: parseDate(r.not_after), serial: '', entries: 1, revoked: r.revoked === true });
    });
    return out;
  }

  async function fetchCerts(domain, hideExpired, setStatus) {
    var errors = [];
    setStatus('Querying crt.sh (can take up to ' + Math.round(CRT_TIMEOUT_MS / 1000) + ' s for large domains)…');
    try {
      var rows = await getJson(crtUrl(domain, hideExpired), CRT_TIMEOUT_MS);
      if (!Array.isArray(rows)) throw new Error('unexpected response');
      return { source: 'crt.sh', certs: fromCrt(rows), notes: [] };
    } catch (e) { errors.push('crt.sh: ' + e.message); }

    setStatus('crt.sh failed (' + errors[0] + '). Trying Cert Spotter…');
    var all = [], after = '', truncated = false, notes = [];
    try {
      for (var pages = 0; pages < SPOTTER_MAX_PAGES; pages++) {
        var page = await getJson(spotterUrl(domain, after), SPOTTER_TIMEOUT_MS);
        if (!Array.isArray(page)) throw new Error('unexpected response');
        all = all.concat(page);
        setStatus('Cert Spotter: ' + all.length + ' issuances fetched…');
        if (page.length < 100) break;
        after = String(page[page.length - 1].id);
        if (!/^\d+$/.test(after)) break;
        if (pages === SPOTTER_MAX_PAGES - 1) truncated = true;
      }
    } catch (e) {
      errors.push('Cert Spotter: ' + e.message + (e.status === 429 ? ' (rate limit of the free tier reached)' : ''));
      if (!all.length) { throw new Error(errors.join('; ')); }
      truncated = true;
      notes.push('Cert Spotter stopped early (' + e.message + '); the list is incomplete.');
    }
    var certs = fromSpotter(all);
    if (hideExpired) { var now = Date.now(); certs = certs.filter(function (c) { return !(c.na < now); }); }
    notes.unshift('crt.sh was unavailable (' + errors[0].replace(/^crt\.sh: /, '') + '), so Cert Spotter was used. It does not provide serial numbers or common names.');
    if (truncated && notes.length === 1) notes.push('Only the first ' + all.length + ' issuances were fetched (free-tier limits); the list is incomplete.');
    return { source: 'Cert Spotter', certs: certs, notes: notes };
  }

  // ---- Analysis ----
  function inScope(name, domain) { return name === domain || name.slice(-(domain.length + 1)) === '.' + domain; }

  function issuerParts(dn) {
    var o = {};
    String(dn || '').split(/,\s*(?=[A-Za-z]+=)/).forEach(function (p) {
      var i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim().toUpperCase()] = p.slice(i + 1).trim();
    });
    return o;
  }
  function issuerShort(dn) { var p = issuerParts(dn); return p.CN || p.O || dn || 'unknown'; }
  function issuerOrg(dn) { var p = issuerParts(dn); return p.O && p.CN ? p.O : ''; }
  function fmtDate(t) { return isNaN(t) ? '' : new Date(t).toISOString().slice(0, 10); }

  function analyse(domain, certs) {
    var now = Date.now();
    var names = Object.create(null), issuers = Object.create(null);
    certs.forEach(function (c) {
      c.status = isNaN(c.na) ? 'unknown' : c.na < now ? 'expired' : (c.na - now <= SOON_DAYS * DAY ? 'soon' : 'valid');
      c.days = isNaN(c.na) ? null : Math.ceil((c.na - now) / DAY);
      c.cnShown = c.cn || c.names[0] || '';
      c.hay = (c.names.join(' ') + ' ' + c.cn + ' ' + c.issuer + ' ' + c.serial).toLowerCase();
      issuers[issuerShort(c.issuer)] = 1;
      c.names.forEach(function (n) {
        if (!inScope(n, domain)) return;
        var o = names[n] || (names[n] = { name: n, certs: 0, valid: 0 });
        o.certs++;
        if (c.status === 'valid' || c.status === 'soon') o.valid++;
      });
    });
    certs.sort(function (a, b) { return (b.nb || 0) - (a.nb || 0); });
    var list = Object.keys(names).map(function (k) { return names[k]; });
    list.sort(function (a, b) {
      var A = a.name.replace(/^\*\./, ''), B = b.name.replace(/^\*\./, '');
      return A < B ? -1 : A > B ? 1 : (a.name < b.name ? -1 : 1);
    });
    var wild = list.filter(function (n) { return n.name.charAt(0) === '*'; }).length;
    var count = function (s) { return certs.filter(function (c) { return c.status === s; }).length; };
    return {
      certs: certs, names: list,
      counts: { certs: certs.length, hosts: list.length - wild, wild: wild, issuers: Object.keys(issuers).length, valid: count('valid'), soon: count('soon'), expired: count('expired') }
    };
  }

  // ---- CSV (RFC 4180, with spreadsheet formula-injection guard) ----
  function csvCell(v) {
    v = String(v == null ? '' : v);
    if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
    return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  }
  function toCsv(rows) { return rows.map(function (r) { return r.map(csvCell).join(','); }).join('\r\n') + '\r\n'; }
  function csvCerts(certs) {
    var rows = [['common_name', 'names', 'issuer', 'not_before', 'not_after', 'status', 'serial']];
    certs.forEach(function (c) { rows.push([c.cnShown, c.names.join(' '), c.issuer, fmtDate(c.nb), fmtDate(c.na), c.status, c.serial]); });
    return toCsv(rows);
  }
  function csvNames(names) {
    var rows = [['name', 'wildcard', 'certificates', 'currently_valid_certificates']];
    names.forEach(function (n) { rows.push([n.name, n.name.charAt(0) === '*' ? 'yes' : 'no', n.certs, n.valid]); });
    return toCsv(rows);
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (e) { /* fall through */ }
    var ta = el('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.className = 'sr-only';
    document.body.append(ta); ta.select();
    var ok = false; try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove(); return ok;
  }

  // ---- Rendering ----
  var views = { placeholder: $('placeholderState'), records: $('recordsContainer'), error: $('errorContainer') };
  function setView(name) { Object.keys(views).forEach(function (k) { views[k].hidden = k !== name; }); }
  var statusEl = $('status');
  function setStatus(t) { statusEl.textContent = t || ''; }

  function flag(cls, text) { return el('span', 'flag ' + cls, text); }

  function certRow(c) {
    var tr = el('tr');
    var tdN = el('td', 'names');
    tdN.append(el('span', 'cn', c.cnShown || '(no name)'));
    var others = c.names.filter(function (n) { return n !== c.cnShown; });
    if (others.length) {
      others.slice(0, 4).forEach(function (n) { tdN.append(el('br'), el('span', 'san', n)); });
      var rest = others.slice(4);
      if (rest.length) {
        var d = el('details'); d.append(el('summary', null, '+' + rest.length + ' more name' + (rest.length > 1 ? 's' : '')));
        rest.forEach(function (n, i) { if (i) d.append(el('br')); d.append(el('span', 'san', n)); });
        tdN.append(d);
      }
    }
    tr.append(tdN);
    var tdI = el('td', 'issuer'); tdI.append(el('span', null, issuerShort(c.issuer)));
    var org = issuerOrg(c.issuer); if (org) tdI.append(el('br'), el('span', 'san', org));
    tr.append(tdI);
    tr.append(el('td', 'date', fmtDate(c.nb)));
    var tdE = el('td', 'date', fmtDate(c.na));
    if (c.status === 'expired') tdE.append(flag('expired', 'expired'));
    else if (c.status === 'soon') tdE.append(flag('soon', 'expires in ' + c.days + ' d'));
    else if (c.status === 'valid') tdE.append(flag('ok', 'valid'));
    if (c.revoked) tdE.append(flag('expired', 'revoked'));
    tr.append(tdE);
    tr.append(el('td', 'serial', c.serial || 'n/a'));
    return tr;
  }

  // Chunked list: draws CHUNK items at a time so thousands of rows never block the page.
  function pager(renderChunk, clear, countEl, moreBtn, label) {
    var items = [], shown = 0;
    function draw() {
      var end = Math.min(items.length, shown + CHUNK);
      renderChunk(items, shown, end);
      shown = end;
      countEl.textContent = 'Showing ' + shown + ' of ' + items.length + ' ' + label;
      moreBtn.hidden = shown >= items.length;
      moreBtn.textContent = 'Show ' + Math.min(CHUNK, items.length - shown) + ' more';
    }
    return {
      reset: function (newItems) { items = newItems; shown = 0; clear(); draw(); },
      more: draw
    };
  }

  function renderResult(domain, data, res, hideExpired) {
    var box = views.records;
    box.replaceChildren();
    var cts = data.counts;

    var head = el('div', cts.certs ? 'state ok' : 'state warn');
    head.append(el('h2', 'state-title', cts.certs ? cts.certs + ' certificate' + (cts.certs > 1 ? 's' : '') + ' logged' : 'No certificates found'));
    head.append(el('p', 'badge-domain', domain));
    head.append(el('p', null, 'Source: ' + res.source + (hideExpired ? ', expired certificates excluded' : '') + '.'));
    res.notes.forEach(function (n) { head.append(el('p', 'sub-note', n)); });
    box.append(head);
    if (!cts.certs) {
      head.append(el('p', null, 'Nothing is logged for ' + domain + ' and its subdomains in ' + res.source + '. That does not prove no certificate exists: a CA may not have logged it, or expired ones are hidden.'));
      box.append(siblingLinks(domain));
      return;
    }

    var stats = el('div', 'stats');
    [['certs', 'certificates', ''], ['hosts', 'unique hostnames', ''], ['wild', 'wildcard names', ''], ['issuers', 'issuers', ''],
     ['valid', 'valid now', ''], ['soon', 'expire within ' + SOON_DAYS + ' d', cts.soon ? 'warn' : ''], ['expired', 'expired', cts.expired ? 'fail' : '']].forEach(function (s) {
      var d = el('div', 'stat ' + s[2]); d.append(el('b', null, String(cts[s[0]])), el('span', null, s[1])); stats.append(d);
    });
    box.append(stats);

    // Filter
    var fr = el('div', 'field filter-row');
    var lab = el('label'); lab.htmlFor = 'filterInput'; lab.append(el('span', null, 'Filter'), el('i', null, 'name, issuer or serial; or: expired, expiring, valid'));
    var row = el('div', 'field-row'); var inp = el('input'); inp.type = 'text'; inp.id = 'filterInput'; inp.placeholder = 'e.g. mail'; inp.autocomplete = 'off'; inp.spellcheck = false;
    row.append(inp); fr.append(lab, row); box.append(fr);

    // Unique names
    box.append(el('h3', 'sub-title', 'Unique hostnames'));
    box.append(el('p', 'sub-note', cts.hosts + ' hostname' + (cts.hosts === 1 ? '' : 's') + ' and ' + cts.wild + ' wildcard name' + (cts.wild === 1 ? '' : 's') + ' under ' + domain + '. A wildcard (*.) hides which exact subdomains exist.'));
    var namesUl = el('ul', 'names-list');
    var namesCount = el('p', 'count'); namesCount.setAttribute('role', 'status');
    var namesMore = el('button', 'btn quiet', 'Show more'); namesMore.type = 'button';
    var namesCopy = el('button', 'btn quiet', 'Copy names as CSV'); namesCopy.type = 'button';
    var namesRow = el('div', 'more-row'); namesRow.append(namesCount, namesMore, namesCopy);
    box.append(namesUl, namesRow);

    // Certificates
    box.append(el('h3', 'sub-title', 'Certificates'));
    box.append(el('p', 'sub-note', 'Newest first. Duplicate log entries (precertificate and final certificate) are merged by issuer and serial.'));
    var wrap = el('div', 'tbl-wrap'); wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', 'Certificates table, scrollable');
    var table = el('table'); var thead = el('thead'); var htr = el('tr');
    ['Names', 'Issuer', 'Not before', 'Not after', 'Serial'].forEach(function (h) { var th = el('th', null, h); th.scope = 'col'; htr.append(th); });
    thead.append(htr); var tbody = el('tbody'); table.append(thead, tbody); wrap.append(table);
    var certCount = el('p', 'count'); certCount.setAttribute('role', 'status');
    var certMore = el('button', 'btn quiet', 'Show more'); certMore.type = 'button';
    var certCopy = el('button', 'btn quiet', 'Copy certificates as CSV'); certCopy.type = 'button';
    var certActions = el('div', 'more-row'); certActions.append(certCount, certMore, certCopy);
    var copyMsg = el('p', 'count'); copyMsg.setAttribute('role', 'status');
    box.append(wrap, certActions, copyMsg, siblingLinks(domain));

    var curCerts = data.certs, curNames = data.names;
    var np = pager(function (items, a, b) {
      var frag = document.createDocumentFragment();
      for (var i = a; i < b; i++) {
        var n = items[i], li = el('li'); li.append(el('span', null, n.name));
        if (n.name.charAt(0) === '*') li.append(flag('wild', 'wildcard'));
        li.append(el('span', 'n', n.certs + (n.certs === 1 ? ' cert' : ' certs')));
        frag.append(li);
      }
      namesUl.append(frag);
    }, function () { namesUl.replaceChildren(); }, namesCount, namesMore, 'names');
    var cp = pager(function (items, a, b) {
      var frag = document.createDocumentFragment();
      for (var i = a; i < b; i++) frag.append(certRow(items[i]));
      tbody.append(frag);
    }, function () { tbody.replaceChildren(); }, certCount, certMore, 'certificates');
    np.reset(curNames); cp.reset(curCerts);
    namesMore.addEventListener('click', np.more);
    certMore.addEventListener('click', cp.more);

    var timer = null;
    inp.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () {
        var q = inp.value.trim().toLowerCase();
        var stateWord = { expired: 'expired', expiring: 'soon', valid: 'valid' }[q];
        if (stateWord) { curCerts = data.certs.filter(function (c) { return c.status === stateWord; }); curNames = data.names; }
        else if (q) { curCerts = data.certs.filter(function (c) { return c.hay.indexOf(q) !== -1; }); curNames = data.names.filter(function (n) { return n.name.indexOf(q) !== -1; }); }
        else { curCerts = data.certs; curNames = data.names; }
        np.reset(curNames); cp.reset(curCerts);
      }, 150);
    });

    function doCopy(text, what) {
      copyText(text).then(function (ok) { copyMsg.textContent = ok ? 'Copied ' + what + ' to the clipboard.' : 'Copy failed: your browser blocked clipboard access.'; });
    }
    namesCopy.addEventListener('click', function () { doCopy(csvNames(curNames), curNames.length + ' names as CSV'); });
    certCopy.addEventListener('click', function () { doCopy(csvCerts(curCerts), curCerts.length + ' certificates as CSV'); });
  }

  function siblingLinks(domain) {
    var wrap = el('p', 'provider');
    wrap.append('Also check ' + domain + ': ');
    [['ssl', 'SSL'], ['caa', 'CAA'], ['dnssec', 'DNSSEC'], ['rdap', 'RDAP'], ['mx', 'MX'], ['spf', 'SPF'], ['dmarc', 'DMARC'], ['ip', 'IP']].forEach(function (t, i) {
      if (i) wrap.append(' \u00b7 ');
      var a = el('a', 'link', t[1]);
      a.href = 'https://' + t[0] + '.hbenali.ovh/?domain=' + encodeURIComponent(domain);
      a.target = '_blank'; a.rel = 'noopener noreferrer';
      wrap.append(a);
    });
    return wrap;
  }

  function renderError(domain, msg, blocked) {
    var box = views.error;
    box.replaceChildren();
    var s = el('div', 'state fail error-message');
    s.setAttribute('role', 'alert');
    s.append(el('h2', 'state-title', domain ? 'No result for ' + domain : 'Error'));
    s.append(el('p', null, msg));
    if (blocked) s.append(el('p', null, 'Nothing was invented to fill the gap. Run the curl command shown at the bottom of this page from a terminal, or try again later.'));
    box.append(s);
  }

  // ---- Flow ----
  var form = $('searchForm'), domainInput = $('domainInput'), checkBtn = $('checkBtn'), btnText = $('btnText'), btnLoader = $('btnLoader');
  var hideExpiredBox = $('hideExpired'), curlBox = $('curlBox');
  var busy = false;

  function setLoading(on) {
    busy = on; checkBtn.disabled = on;
    btnText.textContent = on ? 'Searching' : 'Search';
    btnLoader.hidden = !on; btnLoader.className = on ? 'loader' : '';
  }
  function updateCurl(domain) { curlBox.textContent = curlCommand(validDomain(domain) ? domain : 'example.com', hideExpiredBox.checked); }

  async function performLookup() {
    if (busy) return;
    var domain = normalizeDomain(domainInput.value);
    if (!domain) { setView('error'); renderError('', 'Please enter a domain name.'); return; }
    if (!validDomain(domain)) { setView('error'); renderError('', 'That is not a valid domain name. Use a hostname such as example.com (letters, digits and hyphens, no spaces, no IP addresses).'); return; }
    domainInput.value = domain;
    updateCurl(domain);
    try { history.replaceState(null, '', '?domain=' + encodeURIComponent(domain)); } catch (e) { /* ignore */ }
    setLoading(true);
    var hide = hideExpiredBox.checked;
    try {
      var res = await fetchCerts(domain, hide, setStatus);
      setStatus('Analyzing ' + res.certs.length + ' certificates…');
      await new Promise(function (r) { setTimeout(r, 0); });
      var data = analyse(domain, res.certs);
      renderResult(domain, data, res, hide);
      setView('records');
      setStatus('Done: ' + data.counts.certs + ' certificates, ' + data.counts.hosts + ' unique hostnames from ' + res.source + '.');
    } catch (err) {
      renderError(domain, 'The public CT search services could not be reached from this browser (' + (err.message || 'unknown error') + ').', true);
      setView('error');
      setStatus('');
    } finally { setLoading(false); }
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); performLookup(); });
  hideExpiredBox.addEventListener('change', function () { updateCurl(normalizeDomain(domainInput.value)); });
  domainInput.addEventListener('input', function () { updateCurl(normalizeDomain(domainInput.value)); });
  $('copyCurl').addEventListener('click', function () {
    var b = $('copyCurl');
    copyText(curlBox.textContent).then(function (ok) { b.textContent = ok ? 'Copied' : 'Copy failed'; setTimeout(function () { b.textContent = 'Copy command'; }, 1800); });
  });

  updateCurl('example.com');
  var param = new URLSearchParams(window.location.search).get('domain');
  if (param) { domainInput.value = param; updateCurl(normalizeDomain(param)); performLookup(); }
})();
