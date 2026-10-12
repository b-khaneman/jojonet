'use strict';

(function () {
  const BASE = String((document.documentElement && document.documentElement.dataset.base) || '').replace(/\/$/, '');
  function withBase(path) {
    if (typeof path !== 'string' || path.charAt(0) !== '/') return path;
    if (BASE && (path === BASE || path.indexOf(BASE + '/') === 0)) return path;
    return BASE + path;
  }
  const NET_ERR = 'ارتباط با سرور برقرار نشد. اتصال شبکه را بررسی کنید.';
  const SESSION_EXPIRED = 'نشست شما منقضی شده است. لطفاً دوباره وارد شوید.';
  const POLL_MS = 5000;
  const JOB_POLL_MS = 2000;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const TABS = ['servers', 'tunnels', 'relays', 'panels', 'outbounds', 'jobs', 'users'];
  const XRAY_TUNNEL_MODES = new Set(['dokodemo', 'xray_reverse']);

  const ROLE_LABEL = { iran: 'ایران', kharej: 'خارج' };
  const JOB_STATUS = {
    queued: ['muted', 'در صف'],
    running: ['info', 'در حال اجرا'],
    ok: ['ok', 'موفق'],
    failed: ['err', 'ناموفق'],
  };
  const TUNNEL_STATUS = {
    deploying: ['info', 'در حال استقرار'],
    ok: ['ok', 'سالم'],
    degraded: ['warn', 'ناقص'],
    failed: ['err', 'ناموفق'],
    deleting: ['info', 'در حال حذف'],
  };
  const RELAY_STATUS = TUNNEL_STATUS;
  const RELAY_ENGINE = {
    iptables: 'iptables',
    gost: 'GOST',
    haproxy: 'HAProxy',
    socat: 'Socat',
    xray: 'Xray dokodemo',
  };
  const PORTS_SPEC_RE = /^[0-9]{1,5}(:[0-9]{1,5})?(,[0-9]{1,5}(:[0-9]{1,5})?){0,15}$/;
  const RELAY_NAME_RE = /^[a-z0-9][a-z0-9-]{0,23}$/;
  const DOMAIN_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
  const STEP_STATUS = {
    pending: ['..', 'در انتظار'],
    running: ['>>', 'در حال اجرا'],
    ok: ['OK', 'انجام شد'],
    failed: ['ER', 'ناموفق'],
    skipped: ['--', 'رد شد'],
  };
  const JOB_CODE = { queued: 'WAIT', running: 'RUN', ok: 'OK', failed: 'FAIL' };
  const LOG_KIND_LABEL = {
    step: 'مرحله',
    ok: 'موفق',
    warn: 'هشدار',
    err: 'خطا',
    cred: 'ورود',
    info: 'اطلاعات',
    facts: 'جزئیات',
  };
  const JOB_KIND_LABEL = {
    server_test: 'تست اتصال',
    server_install: 'نصب پیش‌نیازها',
    tunnel_deploy: 'ساخت تانل',
    tunnel_redeploy: 'استقرار مجدد تانل',
    tunnel_verify: 'بررسی تانل',
    tunnel_delete: 'حذف تانل',
    tunnel_delete_remote: 'حذف تانل از سرور',
    tunnel_enable_boot: 'ماندن بعد از ریبوت',
    spoof_check: 'بررسی Spoof',
    relay_deploy: 'ساخت رله',
    relay_delete: 'حذف رله',
    ping_test: 'تست پینگ',
    dns_set: 'تنظیم DNS',
    os_update: 'آپدیت سیستم',
    vpn_panel: 'نصب پنل VPN',
  };

  const THEME_KEY = 'jojonet-theme-2';
  const THEMES = ['jojo', 'day', 'night'];
  const THEME_DEFAULT = 'night';

  const state = {
    csrf: '',
    me: null,
    info: null,
    loggedIn: false,
    tab: 'servers',
    pollTimer: null,
    jobView: null,
    vpnMon: null,
    sessionJobs: new Set(),
    notified: new Set(),
  };
  const hxTerms = { left: null, right: null };

  /* ---------- DOM helpers ---------- */

  const $ = (sel, root) => (root || document).querySelector(sel);
  const PROPS = new Set(['value', 'checked', 'disabled', 'selected', 'hidden', 'required', 'readOnly']);

  function addChildren(el, children) {
    for (const c of children) {
      if (c == null || c === false || c === true) continue;
      if (Array.isArray(c)) addChildren(el, c);
      else el.append(c instanceof Node ? c : String(c));
    }
  }

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k === 'dataset') Object.assign(el.dataset, v);
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (PROPS.has(k)) el[k] = v;
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    addChildren(el, children);
    return el;
  }

  let uidCounter = 0;
  const uid = (p) => `${p || 'u'}-${++uidCounter}`;
  const enc = (id) => encodeURIComponent(String(id));
  const ltr = (v) => h('bdi', { dir: 'ltr' }, v == null || v === '' ? '—' : String(v));
  const infoText = (v) => (v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v));
  const isActive = (status) => status === 'queued' || status === 'running';

  function showErr(box, msg) {
    box.textContent = msg;
    box.hidden = false;
    box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  function hideErr(box) {
    box.textContent = '';
    box.hidden = true;
  }

  function loadingState(text) {
    return h('div', { class: 'state state-loading', role: 'status' },
      h('span', { class: 'spinner', 'aria-hidden': 'true' }),
      h('span', null, text || 'در حال بارگذاری…'));
  }

  function emptyState(title, text) {
    return h('div', { class: 'state state-empty' },
      h('p', { class: 'state-title' }, title),
      text ? h('p', { class: 'muted' }, text) : null);
  }

  function errorState(msg, retry) {
    return h('div', { class: 'state state-error', role: 'alert' },
      h('p', { class: 'state-title' }, 'بارگذاری با خطا مواجه شد'),
      h('p', { class: 'muted' }, msg),
      retry ? h('button', { type: 'button', class: 'btn btn-sm', onclick: retry }, 'تلاش دوباره') : null);
  }

  function badge(kind, label, live) {
    return h('span', { class: `badge badge-${kind}${live ? ' badge-live' : ''}` }, label);
  }

  function kv(label, value) {
    return [h('dt', null, label), h('dd', null, value == null || value === '' ? '—' : value)];
  }

  /* ---------- formatting ---------- */

  let dtf = null;
  let nf = null;
  try {
    dtf = new Intl.DateTimeFormat('fa-IR', {
      numberingSystem: 'latn',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    nf = new Intl.NumberFormat('fa-IR', { numberingSystem: 'latn' });
  } catch (e) {
    dtf = null;
    nf = null;
  }

  function parseTime(iso) {
    if (!iso) return null;
    let s = String(iso);
    if (/^\d{4}-\d\d-\d\dT[\d:.]+$/.test(s)) s += 'Z';
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  }

  function fmtTime(iso) {
    const d = parseTime(iso);
    if (!d) return iso ? String(iso) : '—';
    return dtf ? dtf.format(d) : d.toLocaleString('en-GB');
  }

  const fmtNum = (n) => (nf ? nf.format(n) : String(n));

  function fmtDuration(start, end) {
    const a = parseTime(start);
    const b = parseTime(end);
    if (!a || !b) return '—';
    let sec = Math.max(0, Math.round((b - a) / 1000));
    if (sec < 60) return `${fmtNum(sec)} ثانیه`;
    const m = Math.floor(sec / 60);
    sec %= 60;
    return sec ? `${fmtNum(m)} دقیقه و ${fmtNum(sec)} ثانیه` : `${fmtNum(m)} دقیقه`;
  }

  function fmtPorts(v) {
    if (v == null || v === '') return '—';
    if (Array.isArray(v)) return v.length ? v.join('، ') : '—';
    return String(v);
  }

  /* ---------- API ---------- */

  class ApiError extends Error {
    constructor(message, status) {
      super(message);
      this.status = status;
    }
  }

  function detailMsg(data) {
    if (!data || typeof data !== 'object') return '';
    const d = data.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
      return d.map((x) => (x && typeof x === 'object' ? (x.msg || JSON.stringify(x)) : String(x))).join('؛ ');
    }
    if (d && typeof d === 'object' && d.msg) return String(d.msg);
    return '';
  }

  function statusMsg(s) {
    if (s === 400 || s === 422) return 'اطلاعات ارسال‌شده نامعتبر است.';
    if (s === 401) return 'احراز هویت ناموفق بود.';
    if (s === 403) return 'دسترسی رد شد. صفحه را دوباره بارگذاری کنید.';
    if (s === 404) return 'مورد درخواستی یافت نشد.';
    if (s === 409) return 'این عملیات با وضعیت فعلی تداخل دارد.';
    if (s === 429) return 'تعداد درخواست‌ها بیش از حد مجاز است. کمی بعد دوباره تلاش کنید.';
    if (s >= 500) return 'خطای داخلی سرور پنل. کمی بعد دوباره تلاش کنید.';
    return `خطای ناشناخته (کد ${s}).`;
  }

  async function api(method, path, body) {
    const headers = { Accept: 'application/json' };
    const opts = { method, credentials: 'same-origin', cache: 'no-store', headers };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    if (method !== 'GET' && path !== '/api/login' && state.csrf) headers['X-CSRF-Token'] = state.csrf;

    let res;
    try {
      res = await fetch(withBase(path), opts);
    } catch (e) {
      throw new ApiError(NET_ERR, 0);
    }
    let data = null;
    let text = '';
    try {
      text = await res.text();
    } catch (e) {
      text = '';
    }
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (e) {
        data = null;
      }
    }
    if (res.status === 401 && path !== '/api/login') {
      if (state.loggedIn) showLogin(SESSION_EXPIRED);
      throw new ApiError(detailMsg(data) || SESSION_EXPIRED, 401);
    }
    if (!res.ok) throw new ApiError(detailMsg(data) || statusMsg(res.status), res.status);
    return data;
  }

  /* ---------- toasts ---------- */

  function toast(msg, type, ms) {
    const kind = type || 'info';
    const root = $('#toast-root');
    let timer = null;
    const dismiss = () => {
      clearTimeout(timer);
      el.classList.add('is-leaving');
      setTimeout(() => el.remove(), 200);
    };
    const el = h('div', { class: `toast toast-${kind}`, role: 'status' },
      h('span', { class: 'toast-msg' }, msg),
      h('button', { type: 'button', class: 'toast-close', 'aria-label': 'بستن اعلان', onclick: dismiss }, '×'));
    root.append(el);
    while (root.children.length > 5) root.firstElementChild.remove();
    timer = setTimeout(dismiss, ms || (kind === 'error' ? 8000 : 5000));
  }

  /* ---------- modals ---------- */

  const modalStack = [];
  const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

  function focusables(root) {
    return Array.from(root.querySelectorAll(FOCUSABLE)).filter((x) => x.offsetParent !== null);
  }

  function openModal(opts) {
    const prevFocus = document.activeElement;
    const titleId = uid('mt');
    const titleEl = h('h2', { id: titleId, class: 'modal-title' }, opts.title);
    let closed = false;
    const m = { titleEl, close };
    const closeBtn = h('button', { type: 'button', class: 'icon-btn', 'aria-label': 'بستن', onclick: () => close() }, '×');
    const dialog = h('div', {
      class: `modal${opts.wide ? ' modal-wide' : ''}${opts.ops ? ' modal-ops' : ''}`,
      role: opts.alert ? 'alertdialog' : 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': titleId,
    },
    h('div', { class: 'modal-head' }, titleEl, closeBtn),
    h('div', { class: 'modal-body' }, opts.body),
    opts.footer ? h('div', { class: 'modal-foot' }, opts.footer) : null);
    const overlay = h('div', { class: 'overlay' }, dialog);
    overlay.addEventListener('mousedown', (e) => {
      if (e.target === overlay && !opts.sticky) close();
    });
    m.dialog = dialog;

    function close(result) {
      if (closed) return;
      closed = true;
      overlay.remove();
      const i = modalStack.indexOf(m);
      if (i >= 0) modalStack.splice(i, 1);
      if (!modalStack.length) document.body.classList.remove('modal-open');
      if (opts.onClose) opts.onClose(result);
      if (prevFocus && typeof prevFocus.focus === 'function' && document.contains(prevFocus)) prevFocus.focus();
    }

    modalStack.push(m);
    $('#modal-root').append(overlay);
    document.body.classList.add('modal-open');
    setTimeout(() => {
      if (closed) return;
      const target = opts.focusEl
        || dialog.querySelector('.modal-body input:not([type=hidden]):not([disabled]):not([type=radio]):not([type=checkbox]), .modal-body select, .modal-body textarea')
        || dialog.querySelector('.modal-foot button')
        || closeBtn;
      target.focus();
    }, 0);
    return m;
  }

  function closeAllModals() {
    while (modalStack.length) modalStack[modalStack.length - 1].close();
  }

  document.addEventListener('keydown', (e) => {
    const top = modalStack[modalStack.length - 1];
    if (!top) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      top.close();
      return;
    }
    if (e.key === 'Tab') {
      const f = focusables(top.dialog);
      if (!f.length) return;
      const first = f[0];
      const last = f[f.length - 1];
      const inside = top.dialog.contains(document.activeElement);
      if (e.shiftKey && (!inside || document.activeElement === first)) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (!inside || document.activeElement === last)) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  function confirmDialog(opts) {
    return new Promise((resolve) => {
      let result = null;
      let cb = null;
      const body = [h('p', { class: 'confirm-msg' }, opts.message)];
      if (opts.checkboxLabel) {
        const id = uid('cf');
        cb = h('input', { type: 'checkbox', id });
        body.push(h('label', { class: 'check', for: id }, cb, h('span', null, opts.checkboxLabel)));
      }
      const cancel = h('button', { type: 'button', class: 'btn', onclick: () => m.close() }, 'انصراف');
      const ok = h('button', {
        type: 'button',
        class: opts.danger ? 'btn btn-danger' : 'btn btn-primary',
        onclick: () => {
          result = { checked: cb ? cb.checked : false };
          m.close();
        },
      }, opts.okText || 'تأیید');
      const m = openModal({
        title: opts.title || 'تأیید عملیات',
        body,
        footer: [cancel, ok],
        alert: true,
        focusEl: cancel,
        onClose: () => resolve(result),
      });
    });
  }

  /* ---------- actions helpers ---------- */

  async function act(btn, fn, busyLabel) {
    if (btn && btn.disabled) return;
    const old = btn ? btn.textContent : '';
    if (btn) {
      btn.disabled = true;
      btn.setAttribute('aria-busy', 'true');
      if (busyLabel) btn.textContent = busyLabel;
    }
    try {
      await fn();
    } catch (err) {
      if (err && err.status !== 401) toast(err.message || NET_ERR, 'error');
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.removeAttribute('aria-busy');
        if (busyLabel) btn.textContent = old;
      }
    }
  }

  function trackJob(id) {
    if (id != null) state.sessionJobs.add(String(id));
  }

  function startedJob(r, okMsg) {
    if (okMsg) toast(okMsg, 'success');
    if (r && r.job_id != null) {
      trackJob(r.job_id);
      openJobView(r.job_id);
      load('jobs', true);
    }
  }

  function notifyDone(id, status, title) {
    const key = String(id);
    if (!state.sessionJobs.has(key) || state.notified.has(key)) return;
    state.notified.add(key);
    const name = title ? `«${title}»` : '';
    if (status === 'ok') toast(`کار ${name} با موفقیت به پایان رسید.`, 'success');
    else toast(`کار ${name} ناموفق بود. جزئیات را در بخش کارها ببینید.`, 'error');
    load('servers', true);
    load('tunnels', true);
    load('relays', true);
    load('jobs', true);
    if (liveState.data || state.tab === 'tunnels') loadLiveTunnels(true);
  }

  /* ---------- list loaders ---------- */

  const lists = {
    servers: { path: '/api/servers', el: '#servers-list', render: renderServers, after: () => { updateTunnelForm(); updateRelayForm(); updateVpnPanelForm(); fillTermSelects(); refreshMe(); } },
    tunnels: { path: '/api/tunnels', el: '#tunnels-list', render: renderTunnels, after: renderOutbounds },
    relays: { path: '/api/relays', el: '#relays-list', render: renderRelays, after: updateRelayForm },
    jobs: { path: '/api/jobs?limit=50', el: '#jobs-list', render: renderJobs, after: checkSessionJobs },
    users: { path: '/api/users', el: '#users-list', render: renderUsers },
  };

  const liveState = { data: null, loading: false, error: null, scannedAt: null };

  function isOwner() {
    return !!(state.me && state.me.role === 'owner');
  }

  function can(flag) {
    return isOwner() || !!(state.me && state.me[flag]);
  }

  function canTerm() {
    const me = state.me || {};
    if (me.terms_enabled === false) return false;
    return isOwner() || !!me.allow_term;
  }

  function applyTermUI() {
    const on = canTerm();
    const app = $('#app-view');
    if (app) app.classList.toggle('no-terms', !on);
    if (!on) {
      if (hxTerms.left) hxTerms.left.disconnect();
      if (hxTerms.right) hxTerms.right.disconnect();
      ['left', 'right'].forEach((side) => {
        const dock = $(`#hx-${side}`);
        if (dock) dock.classList.remove('is-open');
        const fab = $(`#hx-toggle-${side}`);
        if (fab) fab.setAttribute('aria-pressed', 'false');
      });
    }
    const box = $('#set-terms-enabled');
    if (box) box.checked = meTermsEnabled();
  }

  function meTermsEnabled() {
    const me = state.me || {};
    return me.terms_enabled !== false;
  }

  function ownerChip(row) {
    if (!isOwner() || !row || !row.owner_username) return null;
    return h('span', { class: 'owner-chip', title: 'مالک منبع' }, row.owner_username);
  }

  function limitText(used, max, word) {
    const body = (max == null || max === '') ? fmtNum(used) : `${used}/${max}`;
    return word ? `${word} ${body}` : body;
  }

  function applyRoleUI() {
    const owner = isOwner();
    const usersBtn = $('#tabbtn-users');
    if (usersBtn) usersBtn.hidden = !owner;
    const relayBtn = $('#tabbtn-relays');
    if (relayBtn) relayBtn.hidden = !can('allow_relay');
    const panelBtn = $('#tabbtn-panels');
    if (panelBtn) panelBtn.hidden = !can('allow_vpn');
    const outboundBtn = $('#tabbtn-outbounds');
    if (outboundBtn) outboundBtn.hidden = !can('allow_vpn');
    if (state.tab === 'users' && !owner) switchTab('servers');
    if (owner) loadListen();
    if (state.tab === 'relays' && !can('allow_relay')) switchTab('servers');
    if ((state.tab === 'panels' || state.tab === 'outbounds') && !can('allow_vpn')) switchTab('servers');
    paintHeader();
    applyTermUI();
  }

  function paintHeader() {
    const me = state.me || {};
    const userEl = $('#hdr-user');
    const quotaEl = $('#hdr-quota');
    if (userEl) userEl.textContent = me.username || '';
    const entryEl = $('#hdr-entry');
    if (entryEl) entryEl.textContent = me.base_path || '';
    if (!quotaEl) return;
    if (me.role === 'owner') {
      quotaEl.hidden = true;
      quotaEl.textContent = '';
      return;
    }
    const bits = [];
    if (me.days_left != null) bits.push(`${fmtNum(me.days_left)} روز مانده`);
    const lim = (me.limits || {});
    const use = (me.usage || {});
    bits.push(limitText(use.servers || 0, lim.max_servers, 'سرور'));
    quotaEl.textContent = bits.join(' · ');
    quotaEl.hidden = !bits.length;
  }

  function resetLists() {
    for (const L of Object.values(lists)) {
      L.key = null;
      L.loaded = false;
      L.data = [];
      $(L.el).replaceChildren(loadingState());
    }
  }

  function load(name, silent) {
    const L = lists[name];
    if (!state.loggedIn) return Promise.resolve();
    if (L.inflight) return L.inflight;
    L.inflight = (async () => {
      try {
        const data = await api('GET', L.path);
        if (!state.loggedIn) return;
        const arr = Array.isArray(data) ? data : [];
        const key = JSON.stringify(arr);
        const changed = !L.loaded || key !== L.key;
        L.key = key;
        L.data = arr;
        L.loaded = true;
        if (changed) L.render();
        if (L.after) L.after();
      } catch (err) {
        if (err.status === 401) return;
        if (!L.loaded) {
          $(L.el).replaceChildren(errorState(err.message, () => {
            $(L.el).replaceChildren(loadingState());
            load(name);
          }));
        } else if (!silent) {
          toast(err.message, 'error');
        }
      } finally {
        L.inflight = null;
      }
    })();
    return L.inflight;
  }

  async function loadInfo() {
    try {
      const info = await api('GET', '/api/info');
      if (!state.loggedIn) return;
      state.info = info || {};
      setVersions(state.info.panel_version, state.info.jojonet_version);
      updateTunnelForm();
      if (lists.tunnels.loaded) renderTunnels();
    } catch (err) {
      if (err.status !== 401) toast(`دریافت اطلاعات پنل ناموفق بود: ${err.message}`, 'error');
    }
  }

  function startPolling() {
    stopPolling();
    state.pollTimer = setInterval(() => {
      if (!state.loggedIn || document.hidden) return;
      load('jobs', true);
      const transient = lists.tunnels.data.some((t) => t.status === 'deploying' || t.status === 'deleting')
        || (lists.relays.data || []).some((t) => t.status === 'deploying' || t.status === 'deleting');
      if (transient) {
        load('tunnels', true);
        load('relays', true);
      }
    }, POLL_MS);
  }

  function stopPolling() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = null;
  }

  function checkSessionJobs() {
    for (const j of lists.jobs.data) {
      if (j && state.sessionJobs.has(String(j.id)) && (j.status === 'ok' || j.status === 'failed')) {
        notifyDone(j.id, j.status, j.title);
      }
    }
  }

  /* ---------- servers ---------- */

  function checkBadge(lc) {
    if (!lc) return badge('muted', 'بررسی نشده');
    return lc.ok ? badge('ok', 'در دسترس') : badge('err', 'خطا در اتصال');
  }

  function renderServers() {
    const box = $(lists.servers.el);
    const data = lists.servers.data;
    if (!data.length) {
      box.replaceChildren(emptyState('هنوز سروری اضافه نشده است.', 'با دکمه «افزودن سرور» یک سرور ایران و یک سرور خارج ثبت کنید.'));
      return;
    }
    const groups = ['iran', 'kharej'].map((role) => {
      const items = data.filter((s) => s.role === role);
      return h('section', { class: 'group' },
        h('h3', { class: 'group-title' }, `سرورهای ${ROLE_LABEL[role]}`, h('span', { class: 'count' }, fmtNum(items.length))),
        items.length
          ? h('div', { class: 'cards' }, items.map(serverCard))
          : emptyState(`سروری با نقش ${ROLE_LABEL[role]} ثبت نشده است.`));
    });
    box.replaceChildren(h('div', { class: 'server-groups' }, groups));
  }

  function serverCard(s) {
    const lc = s.last_check;
    const testBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'تست اتصال');
    testBtn.addEventListener('click', () => act(testBtn, async () => {
      startedJob(await api('POST', `/api/servers/${enc(s.id)}/test`));
    }));

    const installBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'نصب پیش‌نیازها و اسکریپت');
    installBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'نصب پیش‌نیازها',
        message: `پیش‌نیازها و اسکریپت جوجونت روی سرور «${s.name}» نصب شود؟ این عملیات ممکن است چند دقیقه طول بکشد.`,
        okText: 'شروع نصب',
      });
      if (!ok) return;
      act(installBtn, async () => {
        startedJob(await api('POST', `/api/servers/${enc(s.id)}/install`), 'نصب آغاز شد.');
      });
    });

    const pingBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'تست پینگ');
    pingBtn.addEventListener('click', () => act(pingBtn, async () => {
      startedJob(await api('POST', `/api/servers/${enc(s.id)}/ping-test`), 'تست پینگ آغاز شد.');
    }));

    const dnsBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'تنظیم DNS');
    dnsBtn.addEventListener('click', () => openDnsForm(s));

    const updBtn = can('allow_os_update') ? h('button', { type: 'button', class: 'btn btn-sm' }, 'آپدیت سیستم') : null;
    if (updBtn) updBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'آپدیت بسته‌های سیستم',
        message: `بسته‌های سیستم روی سرور «${s.name}» به‌روز شوند؟ این کار ممکن است چند دقیقه طول بکشد.`,
        okText: 'شروع آپدیت',
      });
      if (!ok) return;
      act(updBtn, async () => {
        startedJob(await api('POST', `/api/servers/${enc(s.id)}/update-os`), 'آپدیت سیستم آغاز شد.');
      });
    });

    const editBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'ویرایش');
    editBtn.addEventListener('click', () => openServerForm(s));

    const delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف');
    delBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'حذف سرور',
        message: `سرور «${s.name}» (${s.host}) از پنل حذف شود؟ این کار روی خود سرور تغییری نمی‌دهد.`,
        okText: 'حذف',
        danger: true,
      });
      if (!ok) return;
      act(delBtn, async () => {
        await api('DELETE', `/api/servers/${enc(s.id)}`);
        toast(`سرور «${s.name}» حذف شد.`, 'success');
        await load('servers');
      });
    });

    return h('article', { class: 'card server-card' },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, s.name, ownerChip(s)),
          h('span', { class: `role-chip role-${s.role}` }, ROLE_LABEL[s.role] || s.role)),
        checkBadge(lc)),
      h('dl', { class: 'kv' },
        kv('آدرس', ltr(`${s.host}:${s.port}`)),
        kv('کاربر', ltr(s.username)),
        kv('احراز هویت', s.auth_type === 'key' ? 'کلید SSH' : 'رمز عبور'),
        kv('رمز sudo', s.has_sudo_password ? 'ثبت شده' : 'ندارد'),
        kv('اثر انگشت میزبان', s.hostkey_fingerprint ? h('code', { class: 'fp', dir: 'ltr' }, s.hostkey_fingerprint) : 'هنوز ثبت نشده'),
        kv('آخرین بررسی', lc ? fmtTime(lc.at) : '—')),
      lc && lc.info ? h('p', { class: `check-info${lc.ok ? '' : ' is-err'}` }, infoText(lc.info)) : null,
      h('div', { class: 'card-actions' }, testBtn, installBtn, pingBtn, dnsBtn, updBtn, editBtn, delBtn));
  }

  function openDnsForm(s) {
    const errBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
    const d1 = h('input', { id: uid('f'), type: 'text', dir: 'ltr', required: true, value: '1.1.1.1' });
    const d2 = h('input', { id: uid('f'), type: 'text', dir: 'ltr', value: '1.0.0.1' });
    const form = h('form', { class: 'form', novalidate: true },
      errBox,
      field('DNS اول', d1),
      field('DNS دوم (اختیاری)', d2));
    form.id = uid('dns');
    const saveBtn = h('button', { type: 'submit', class: 'btn btn-primary', form: form.id }, 'اعمال');
    const m = openModal({
      title: `تنظیم DNS روی «${s.name}»`,
      body: form,
      footer: [h('button', { type: 'button', class: 'btn', onclick: () => m.close() }, 'انصراف'), saveBtn],
    });
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      hideErr(errBox);
      const dns1 = d1.value.trim();
      const dns2 = d2.value.trim();
      if (!IPV4_RE.test(dns1)) return showErr(errBox, 'DNS اول باید IPv4 معتبر باشد.');
      if (dns2 && !IPV4_RE.test(dns2)) return showErr(errBox, 'DNS دوم باید IPv4 معتبر باشد.');
      act(saveBtn, async () => {
        startedJob(await api('POST', `/api/servers/${enc(s.id)}/dns`, { dns1, dns2: dns2 || null }), 'تنظیم DNS آغاز شد.');
        m.close();
      });
    });
  }

  function field(label, input, hint, extraClass) {
    let hintEl = null;
    if (hint) {
      hintEl = h('p', { class: 'hint', id: `${input.id}-hint` }, hint);
      input.setAttribute('aria-describedby', hintEl.id);
    }
    return h('div', { class: `field${extraClass ? ` ${extraClass}` : ''}` }, h('label', { for: input.id }, label), input, hintEl);
  }

  function openServerForm(server) {
    const edit = !!server;
    const s = server || {};
    const formId = uid('sf');
    const errBox = h('div', { class: 'form-error', role: 'alert', hidden: true });

    const fName = h('input', { id: uid('f'), type: 'text', maxlength: '40', autocomplete: 'off', required: true, value: s.name || '' });
    const fRole = h('select', { id: uid('f'), required: true },
      h('option', { value: 'iran' }, 'ایران'),
      h('option', { value: 'kharej' }, 'خارج'));
    fRole.value = s.role || 'iran';
    const fHost = h('input', { id: uid('f'), type: 'text', dir: 'ltr', inputmode: 'decimal', placeholder: '203.0.113.10', autocomplete: 'off', spellcheck: 'false', required: true, value: s.host || '' });
    const fPort = h('input', { id: uid('f'), type: 'number', dir: 'ltr', min: '1', max: '65535', required: true, value: String(s.port || 22) });
    const fUser = h('input', { id: uid('f'), type: 'text', dir: 'ltr', autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', required: true, value: s.username || 'root' });

    const authName = uid('auth');
    const rPass = h('input', { type: 'radio', name: authName, value: 'password', id: uid('f') });
    const rKey = h('input', { type: 'radio', name: authName, value: 'key', id: uid('f') });
    if (s.auth_type === 'key') rKey.checked = true;
    else rPass.checked = true;

    const keepHint = 'قبلاً ذخیره شده؛ برای حفظ مقدار فعلی خالی بگذارید.';
    const fPass = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'new-password', placeholder: edit && s.has_password ? '•••••• (بدون تغییر)' : '' });
    const fKey = h('textarea', {
      id: uid('f'), dir: 'ltr', rows: '7', class: 'mono', spellcheck: 'false', autocomplete: 'off',
      placeholder: edit && s.has_key ? '(کلید فعلی حفظ می‌شود)' : '-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----',
    });
    const fPassphrase = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'new-password' });
    const fSudo = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'new-password', placeholder: edit && s.has_sudo_password ? '•••••• (بدون تغییر)' : '' });
    const fReset = edit ? h('input', { type: 'checkbox', id: uid('f') }) : null;

    const pwSection = h('div', { class: 'auth-section' },
      field('رمز عبور SSH', fPass, edit && s.has_password ? keepHint : null));
    const keySection = h('div', { class: 'auth-section' },
      field('کلید خصوصی (PEM)', fKey, edit && s.has_key ? keepHint : 'متن کامل کلید خصوصی را اینجا قرار دهید.'),
      field('عبارت عبور کلید (اختیاری)', fPassphrase, 'فقط اگر کلید رمزگذاری شده است.'));

    const syncAuth = () => {
      pwSection.hidden = rKey.checked;
      keySection.hidden = !rKey.checked;
    };
    rPass.addEventListener('change', syncAuth);
    rKey.addEventListener('change', syncAuth);
    syncAuth();

    const authGroup = h('fieldset', { class: 'field field-wide radio-group' },
      h('legend', null, 'روش احراز هویت'),
      h('label', { class: 'radio', for: rPass.id }, rPass, h('span', null, 'رمز عبور')),
      h('label', { class: 'radio', for: rKey.id }, rKey, h('span', null, 'کلید SSH')));

    const form = h('form', { id: formId, class: 'form', novalidate: true },
      errBox,
      h('div', { class: 'form-grid' },
        field('نام سرور', fName, 'بین 1 تا 40 کاراکتر.'),
        field('نقش', fRole),
        field('آدرس IPv4', fHost),
        field('پورت SSH', fPort),
        field('نام کاربری', fUser, null, 'field-wide'),
        authGroup),
      pwSection,
      keySection,
      field('رمز sudo (اختیاری)', fSudo, edit && s.has_sudo_password ? keepHint : 'فقط وقتی کاربر root نیست و sudo رمز می‌خواهد لازم است.'),
      fReset ? h('label', { class: 'check', for: fReset.id }, fReset,
        h('span', null, 'بازنشانی کلید میزبان (وقتی سرور دوباره نصب شده و اثر انگشت آن تغییر کرده است)')) : null);

    for (const el of [fName, fHost, fPort, fUser, fPass, fKey]) {
      el.addEventListener('input', () => el.removeAttribute('aria-invalid'));
    }

    const cancelBtn = h('button', { type: 'button', class: 'btn', onclick: () => m.close() }, 'انصراف');
    const saveBtn = h('button', { type: 'submit', form: formId, class: 'btn btn-primary' }, edit ? 'ذخیره تغییرات' : 'افزودن سرور');

    const m = openModal({
      title: edit ? `ویرایش سرور «${s.name}»` : 'افزودن سرور',
      body: form,
      footer: [cancelBtn, saveBtn],
      sticky: true,
    });

    const fail = (el, msg) => {
      el.setAttribute('aria-invalid', 'true');
      showErr(errBox, msg);
      el.focus();
      return false;
    };

    function validate() {
      const name = fName.value.trim();
      if (name.length < 1 || name.length > 40) return fail(fName, 'نام سرور باید بین 1 تا 40 کاراکتر باشد.');
      if (!IPV4_RE.test(fHost.value.trim())) return fail(fHost, 'آدرس IPv4 معتبر نیست (مثال: 203.0.113.10).');
      const port = Number(fPort.value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return fail(fPort, 'پورت باید عددی بین 1 تا 65535 باشد.');
      if (!fUser.value.trim()) return fail(fUser, 'نام کاربری را وارد کنید.');
      if (rKey.checked) {
        const key = fKey.value.trim();
        if (!key && !(edit && s.has_key)) return fail(fKey, 'کلید خصوصی SSH را وارد کنید.');
        if (key && !/PRIVATE KEY/.test(key)) return fail(fKey, 'متن کلید خصوصی معتبر به نظر نمی‌رسد (باید شامل PRIVATE KEY باشد).');
      } else if (!fPass.value && !(edit && s.has_password)) {
        return fail(fPass, 'رمز عبور SSH را وارد کنید.');
      }
      return true;
    }

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      hideErr(errBox);
      if (!validate()) return;
      const payload = {
        name: fName.value.trim(),
        role: fRole.value,
        host: fHost.value.trim(),
        port: Number(fPort.value),
        username: fUser.value.trim(),
        auth_type: rKey.checked ? 'key' : 'password',
      };
      if (rKey.checked) {
        if (fKey.value.trim()) payload.private_key = `${fKey.value.trim()}\n`;
        if (fPassphrase.value) payload.key_passphrase = fPassphrase.value;
      } else if (fPass.value) {
        payload.password = fPass.value;
      }
      if (fSudo.value) payload.sudo_password = fSudo.value;
      if (edit) payload.reset_hostkey = !!(fReset && fReset.checked);

      (async () => {
        saveBtn.disabled = true;
        saveBtn.setAttribute('aria-busy', 'true');
        try {
          if (edit) await api('PUT', `/api/servers/${enc(s.id)}`, payload);
          else await api('POST', '/api/servers', payload);
          toast(edit ? 'تغییرات سرور ذخیره شد.' : 'سرور اضافه شد.', 'success');
          m.close();
          load('servers');
        } catch (err) {
          if (err.status !== 401) showErr(errBox, err.message);
        } finally {
          saveBtn.disabled = false;
          saveBtn.removeAttribute('aria-busy');
        }
      })();
    });
  }

  /* ---------- tunnels ---------- */

  function modeInfo(id) {
    const modes = (state.info && Array.isArray(state.info.modes)) ? state.info.modes : [];
    return modes.find((m) => m.id === id) || null;
  }

  function fillSelect(sel, items, placeholder) {
    const prev = sel.value;
    const opts = [h('option', { value: '' }, placeholder)];
    for (const it of items) opts.push(h('option', { value: String(it.value) }, it.label));
    sel.replaceChildren(...opts);
    sel.value = items.some((it) => String(it.value) === prev) ? prev : '';
  }

  function selectedUsers() {
    const canDirect = (state.info && Array.isArray(state.info.direct_modes))
      ? state.info.direct_modes.includes($('#tf-mode').value)
      : ($('#tf-mode').value === 'dnstt' || $('#tf-mode').value === 'icmp');
    return canDirect && $('#tf-direct') && $('#tf-direct').checked ? 'kharej' : 'iran';
  }

  function updateModeDesc() {
    const desc = $('#tf-mode-desc');
    const m = modeInfo($('#tf-mode').value);
    const mode = $('#tf-mode').value;
    $('#tf-spoof').hidden = mode !== 'spoof';
    $('#tf-xray').hidden = mode !== 'dokodemo' && mode !== 'xray_reverse';
    $('#tf-dnstt').hidden = mode !== 'dnstt';
    $('#tf-icmp').hidden = mode !== 'icmp';
    const canDirect = (state.info && Array.isArray(state.info.direct_modes))
      ? state.info.direct_modes.includes(mode)
      : (mode === 'dnstt' || mode === 'icmp');
    const wrap = $('#tf-direct-wrap');
    if (wrap) wrap.hidden = !canDirect;
    if (!canDirect && $('#tf-direct')) $('#tf-direct').checked = false;

    const direct = canDirect && $('#tf-direct') && $('#tf-direct').checked;
    const iranField = $('#tf-iran-field');
    if (iranField) iranField.hidden = !!direct;
    if ($('#tf-iran')) $('#tf-iran').required = !direct;
    if (!m) {
      desc.textContent = 'یک نوع تانل انتخاب کنید تا توضیحات آن نمایش داده شود.';
      return;
    }
    const side = m.first === 'iran' ? 'ایران' : 'خارج';
    const extra = direct
      ? ' حالت مستقیم: فقط سرور خارج مستقر می‌شود؛ کلاینت روی دستگاه کاربر است.'
      : selectedUsers() === 'kharej'
        ? ' کاربران روی خارج: ورودی روی خارج، سرویس روی ایران (تانل خارج → ایران).'
        : ` کاربران روی ایران: ورودی روی ایران، سرویس روی خارج (تانل ایران → خارج). ترتیب استقرار: ابتدا سمت ${side}.`;
    desc.replaceChildren(
      h('span', null, m.desc || ''),
      h('span', { class: 'hint-strong' }, extra));
  }

  function updateTunnelForm() {
    const modeSel = $('#tf-mode');
    const iranSel = $('#tf-iran');
    const kharejSel = $('#tf-kharej');
    const modes = (state.info && Array.isArray(state.info.modes)) ? state.info.modes : null;
    if (modes) fillSelect(modeSel, modes.map((m) => ({ value: m.id, label: m.label || m.id })), 'انتخاب نوع تانل…');
    else fillSelect(modeSel, [], 'در حال بارگذاری…');
    modeSel.disabled = !modes;

    const servers = lists.servers.data;
    const opt = (s) => ({ value: s.id, label: `${s.name} (${s.host})` });
    const iran = servers.filter((s) => s.role === 'iran').map(opt);
    const kharej = servers.filter((s) => s.role === 'kharej').map(opt);
    const loaded = lists.servers.loaded;
    fillSelect(iranSel, iran, !loaded ? 'در حال بارگذاری…' : iran.length ? 'انتخاب سرور ایران…' : 'سرور ایرانی ثبت نشده است');
    fillSelect(kharejSel, kharej, !loaded ? 'در حال بارگذاری…' : kharej.length ? 'انتخاب سرور خارج…' : 'سرور خارجی ثبت نشده است');
    iranSel.disabled = !iran.length;
    kharejSel.disabled = !kharej.length;
    const canDirect = (state.info && Array.isArray(state.info.direct_modes))
      ? state.info.direct_modes.includes($('#tf-mode').value)
      : false;
    const direct = canDirect && $('#tf-direct') && $('#tf-direct').checked;
    $('#tf-submit').disabled = !modes || !kharej.length || (!direct && !iran.length);
    updateModeDesc();
  }

  /* Returns the spoof options object, or a Persian error message. */
  function readSpoofForm() {
    const val = (id) => $(id).value.trim();
    const port = (id, label) => {
      const v = val(id);
      const n = Number(v);
      return /^\d{1,5}$/.test(v) && n >= 1 && n <= 65535 ? n : `${label} باید عددی بین 1 تا 65535 باشد.`;
    };
    const iranIp = val('#tf-sp-iran');
    const kharejIp = val('#tf-sp-kharej');
    if (!IPV4_RE.test(iranIp)) return 'IP جعلی سمت ایران را به‌صورت IPv4 معتبر وارد کنید.';
    if (!IPV4_RE.test(kharejIp)) return 'IP جعلی سمت خارج را به‌صورت IPv4 معتبر وارد کنید.';
    const forward = val('#tf-sp-forward');
    const fm = /^(.+):(\d{1,5})$/.exec(forward);
    if (!fm || !(fm[1] === 'localhost' || IPV4_RE.test(fm[1])) || Number(fm[2]) < 1 || Number(fm[2]) > 65535) {
      return 'مقصد فوروارد باید به شکل IP:PORT باشد (مثلاً 127.0.0.1:443).';
    }
    const ports = {
      listen_port: port('#tf-sp-listen', 'پورت ورودی ایران'),
      up_port: port('#tf-sp-upport', 'پورت رفت'),
      down_port: port('#tf-sp-downport', 'پورت برگشت'),
      spoof_port: port('#tf-sp-sport', 'پورت مبدأ جعلی'),
    };
    for (const v of Object.values(ports)) if (typeof v === 'string') return v;
    if (ports.up_port === ports.down_port) return 'پورت رفت و برگشت نباید یکی باشد.';
    return {
      iran_spoof_ip: iranIp,
      kharej_spoof_ip: kharejIp,
      listen_public: $('#tf-sp-public').checked,
      forward,
      up_transport: $('#tf-sp-up').value,
      down_transport: $('#tf-sp-down').value,
      skip_check: $('#tf-sp-skip').checked,
      ...ports,
    };
  }

  function readXrayForm() {
    const net = $('#tf-xr-net').value;
    if (!['tcp', 'ws', 'grpc'].includes(net)) return 'انتقال Xray باید tcp، ws یا grpc باشد.';
    const ctrlRaw = $('#tf-xr-ctrl').value.trim();
    let ctrl_port = null;
    if (ctrlRaw) {
      const n = Number(ctrlRaw);
      if (!/^\d{1,5}$/.test(ctrlRaw) || n < 1 || n > 65535) return 'پورت کنترل باید بین 1 تا 65535 باشد.';
      ctrl_port = n;
    }
    const ports = $('#tf-xr-ports').value.replace(/\s+/g, '');
    if (!ports) return 'حداقل یک پورت فوروارد لازم است.';
    if (!PORTS_SPEC_RE.test(ports)) {
      return 'پورت‌ها باید به شکل 443 یا 8443:443 باشند.';
    }
    return { net, ctrl_port, ports };
  }

  function readDnsttForm() {
    const domain = $('#tf-dt-domain').value.trim().toLowerCase().replace(/\.+$/, '');
    if (!DOMAIN_RE.test(domain) || !domain.includes('.')) return 'دامنه DNSTT را به‌صورت FQDN وارد کنید (مثلاً t.example.com).';
    const resolver_mode = $('#tf-dt-mode').value;
    if (!['doh', 'dot', 'udp'].includes(resolver_mode)) return 'حالت resolver باید DoH، DoT یا UDP باشد.';
    const resolver = $('#tf-dt-resolver').value.trim();
    if (resolver) {
      if (resolver_mode === 'doh' && !/^https:\/\/[A-Za-z0-9./_~:?&=%+-]+$/.test(resolver)) {
        return 'آدرس DoH باید با https:// شروع شود.';
      }
      if (resolver_mode !== 'doh' && resolver.length < 3) return 'آدرس resolver نامعتبر است.';
    }
    const dnsRaw = $('#tf-dt-dnsport').value.trim();
    let dns_port = null;
    if (dnsRaw) {
      const n = Number(dnsRaw);
      if (!/^\d{1,5}$/.test(dnsRaw) || n < 1 || n > 65535) return 'پورت UDP خارج باید بین 1 تا 65535 باشد.';
      dns_port = n;
    }
    const ports = $('#tf-dt-ports').value.replace(/\s+/g, '');
    if (ports && !PORTS_SPEC_RE.test(ports)) return 'پورت‌ها باید به شکل 443 یا 8443:443 باشند.';
    const out = { domain, resolver_mode };
    if (resolver) out.resolver = resolver;
    if (dns_port) out.dns_port = dns_port;
    if (ports) out.ports = ports;
    return out;
  }

  function readIcmpForm() {
    const ports = $('#tf-ic-ports').value.replace(/\s+/g, '');
    if (ports && !PORTS_SPEC_RE.test(ports)) return 'پورت‌ها باید به شکل 443 یا 8443:443 باشند.';
    return ports ? { ports } : {};
  }

  async function onSpoofCheck(e) {
    const errBox = $('#tf-error');
    hideErr(errBox);
    const findSrv = (v) => lists.servers.data.find((s) => String(s.id) === v);
    const iran = findSrv($('#tf-iran').value);
    const kharej = findSrv($('#tf-kharej').value);
    if (!iran) return showErr(errBox, 'سرور ایران را انتخاب کنید.');
    if (!kharej) return showErr(errBox, 'سرور خارج را انتخاب کنید.');
    const spoof = readSpoofForm();
    if (typeof spoof === 'string') return showErr(errBox, spoof);
    spoof.skip_check = false;
    return act(e.currentTarget, async () => {
      startedJob(await api('POST', '/api/spoof-check', { iran_id: iran.id, kharej_id: kharej.id, spoof }), 'بررسی آمادگی Spoof آغاز شد.');
    }, 'در حال ارسال…');
  }

  async function onCreateTunnel(e) {
    e.preventDefault();
    const errBox = $('#tf-error');
    const btn = $('#tf-submit');
    hideErr(errBox);
    const mode = $('#tf-mode').value;
    const findSrv = (v) => lists.servers.data.find((s) => String(s.id) === v);
    const canDirect = (state.info && Array.isArray(state.info.direct_modes))
      ? state.info.direct_modes.includes(mode)
      : (mode === 'dnstt' || mode === 'icmp');
    const direct = canDirect && $('#tf-direct') && $('#tf-direct').checked;
    const iran = findSrv($('#tf-iran').value);
    const kharej = findSrv($('#tf-kharej').value);
    if (!mode) return showErr(errBox, 'نوع تانل را انتخاب کنید.');
    if (!kharej) return showErr(errBox, 'سرور خارج را انتخاب کنید.');
    if (!direct && !iran) return showErr(errBox, 'سرور ایران را انتخاب کنید.');
    const payload = { mode, kharej_id: kharej.id, users: direct ? 'kharej' : 'iran' };
    if (direct) payload.direct = true;
    else payload.iran_id = iran.id;
    if (mode === 'spoof') {
      const spoof = readSpoofForm();
      if (typeof spoof === 'string') return showErr(errBox, spoof);
      payload.spoof = spoof;
    }
    if (mode === 'dokodemo' || mode === 'xray_reverse') {
      const xray = readXrayForm();
      if (typeof xray === 'string') return showErr(errBox, xray);
      payload.xray = xray;
    }
    if (mode === 'dnstt') {
      const dnstt = readDnsttForm();
      if (typeof dnstt === 'string') return showErr(errBox, dnstt);
      payload.dnstt = dnstt;
    }
    if (mode === 'icmp') {
      const icmp = readIcmpForm();
      if (typeof icmp === 'string') return showErr(errBox, icmp);
      if (icmp && Object.keys(icmp).length) payload.icmp = icmp;
    }
    if (btn.disabled) return undefined;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = 'در حال ارسال…';
    try {
      const r = await api('POST', '/api/tunnels', payload);
      startedJob(r, 'ساخت تانل آغاز شد.');
      load('tunnels');
    } catch (err) {
      if (err.status !== 401) showErr(errBox, err.message);
    } finally {
      btn.removeAttribute('aria-busy');
      btn.textContent = 'ساخت تانل';
      updateTunnelForm();
    }
    return undefined;
  }

  function renderTunnels() {
    const box = $(lists.tunnels.el);
    const data = lists.tunnels.data;
    if (!data.length) {
      box.replaceChildren(emptyState('هنوز تانلی ساخته نشده است.', 'از فرم «ساخت تانل» در بالا اولین تانل را بسازید.'));
      return;
    }
    box.replaceChildren(h('div', { class: 'cards' }, data.map(tunnelCard)));
  }

  function tunnelCard(t) {
    const [kind, label] = TUNNEL_STATUS[t.status] || ['muted', t.status || 'نامشخص'];
    const transient = t.status === 'deploying' || t.status === 'deleting';
    const lc = t.last_check;
    const mi = modeInfo(t.mode);
    const sp = t.mode === 'spoof' && t.options && typeof t.options === 'object' ? t.options : null;
    const xr = (t.mode === 'dokodemo' || t.mode === 'xray_reverse') && t.options && typeof t.options === 'object' ? t.options : null;
    const dt = t.mode === 'dnstt' && t.options && typeof t.options === 'object' ? t.options : null;
    const ic = t.mode === 'icmp' && t.options && typeof t.options === 'object' ? t.options : null;

    const verifyBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'بررسی');
    verifyBtn.addEventListener('click', () => act(verifyBtn, async () => {
      startedJob(await api('POST', `/api/tunnels/${enc(t.id)}/verify`));
      load('tunnels', true);
    }));

    const redeployBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'استقرار مجدد');
    redeployBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'استقرار مجدد تانل',
        message: t.direct
          ? `تانل ${mi ? mi.label : t.mode} مستقیم روی «${t.kharej_name}» دوباره مستقر شود؟ ممکن است اتصال برای مدت کوتاهی قطع شود.`
          : `تانل ${mi ? mi.label : t.mode} بین «${t.iran_name}» و «${t.kharej_name}» دوباره روی هر دو سرور مستقر شود؟ ممکن است اتصال برای مدت کوتاهی قطع شود.`,
        okText: 'استقرار مجدد',
      });
      if (!ok) return;
      act(redeployBtn, async () => {
        startedJob(await api('POST', `/api/tunnels/${enc(t.id)}/redeploy`), 'استقرار مجدد آغاز شد.');
        load('tunnels', true);
      });
    });

    const outboundBtn = can('allow_vpn')
      ? h('button', { type: 'button', class: 'btn btn-sm' }, 'اوتباند X-UI')
      : null;
    if (outboundBtn) {
      outboundBtn.addEventListener('click', () => {
        switchTab('outbounds');
        requestAnimationFrame(() => {
          const el = document.getElementById(`outbound-${t.id}`);
          if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      });
    }

    const logBtn = t.last_job_id != null
      ? h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: () => openJobView(t.last_job_id) }, 'آخرین کار')
      : null;

    const delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف');
    delBtn.addEventListener('click', async () => {
      const res = await confirmDialog({
        title: 'حذف تانل',
        message: t.direct
          ? `تانل مستقیم «${t.kharej_name}» از روی سرور خارج و از پنل حذف شود؟`
          : `تانل بین «${t.iran_name}» و «${t.kharej_name}» از روی هر دو سرور و از پنل حذف شود؟`,
        okText: 'حذف تانل',
        danger: true,
        checkboxLabel: 'حذف اجباری از پنل حتی اگر سرور در دسترس نباشد',
      });
      if (!res) return;
      act(delBtn, async () => {
        startedJob(await api('DELETE', `/api/tunnels/${enc(t.id)}`, { force: !!res.checked }), 'حذف تانل آغاز شد.');
        load('tunnels', true);
      });
    });

    const bootBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'ماندن بعد از ریبوت');
    bootBtn.addEventListener('click', async () => {
      const sides = t.direct
        ? [{ id: t.kharej_id, name: t.kharej_name }]
        : [
          { id: t.iran_id, name: t.iran_name },
          { id: t.kharej_id, name: t.kharej_name },
        ].filter((s, i, arr) => s.id != null && arr.findIndex((x) => x.id === s.id) === i);
      const ok = await confirmDialog({
        title: 'ماندن بعد از ریبوت',
        message: `سرویس تانل روی ${sides.map((s) => `«${s.name}»`).join(' و ')} برای بالا آمدن بعد از ریبوت فعال شود؟`,
        okText: 'فعال‌سازی',
      });
      if (!ok) return;
      act(bootBtn, async () => {
        for (const s of sides) {
          startedJob(await api('POST', `/api/servers/${enc(s.id)}/enable-boot`), `ماندن بعد از ریبوت روی ${s.name}`);
        }
      });
    });

    return h('article', { class: 'card tunnel-card' },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, mi ? mi.label : t.mode, ownerChip(t)),
          h('span', { class: 'mode-chip', dir: 'ltr' }, t.mode)),
        badge(kind, label, transient)),
      h('div', { class: 'route' },
        t.direct
          ? h('span', { class: 'route-end role-kharej' }, h('small', null, 'مستقیم / خارج'), t.kharej_name || '—')
          : h('span', { class: 'route-end role-iran' }, h('small', null, 'ایران'), t.iran_name || '—'),
        t.direct ? null : h('span', { class: 'route-link', 'aria-hidden': 'true' }),
        t.direct ? null : h('span', { class: 'route-end role-kharej' }, h('small', null, 'خارج'), t.kharej_name || '—')),
      t.direct ? null : h('p', { class: 'hint' },
        t.users === 'kharej' ? 'کاربران روی خارج — تانل خارج → ایران' : 'کاربران روی ایران — تانل ایران → خارج'),
      h('dl', { class: 'kv' },
        ...(xr ? [
          kv('انتقال Xray', ltr(xr.net || 'tcp')),
          kv('پورت کنترل', xr.ctrl_port ? ltr(xr.ctrl_port) : 'خودکار'),
          kv('پورت‌های Xray', ltr(xr.ports || '')),
        ] : dt ? [
          kv('دامنه DNSTT', ltr(dt.domain || '—')),
          kv('Resolver', ltr(`${dt.resolver_mode || 'doh'} ${dt.resolver || ''}`)),
        ] : ic ? [
          kv('حامل', 'ICMP echo + ChaCha20 (pingtunnel)'),
        ] : sp ? [
          kv('IP جعلی ایران / خارج', ltr(`${sp.iran_spoof_ip || '—'} / ${sp.kharej_spoof_ip || '—'}`)),
          kv('پروتکل رفت / برگشت', ltr(`${sp.up_transport || '—'}:${sp.up_port || '—'} / ${sp.down_transport || '—'}:${sp.down_port || '—'}`)),
        ] : [
          kv('IP تانل ایران', ltr(t.tun_iran_ip)),
          kv('IP تانل خارج', ltr(t.tun_kharej_ip)),
          kv('اینترفیس‌ها', ltr(`${t.iran_iface || '—'} / ${t.kharej_iface || '—'}`)),
        ]),
        ...(t.direct ? [kv('حالت', 'مستقیم — کلاینت روی دستگاه کاربر')] : []),
        kv('پورت‌های فوروارد', ltr(fmtPorts(t.forward_ports))),
        kv('آخرین بررسی', lc ? fmtTime(lc.at) : '—'),
        kv('زمان ساخت', fmtTime(t.created_at))),
      lc && lc.info ? h('p', { class: `check-info${lc.ok ? '' : ' is-err'}` }, infoText(lc.info)) : null,
      h('div', { class: 'card-actions' }, verifyBtn, outboundBtn, redeployBtn, bootBtn, logBtn, delBtn));
  }

  function liveStatusBadge(st) {
    const s = String(st || '').toUpperCase();
    if (s === 'UP') return badge('ok', 'فعال', true);
    if (s === 'FAIL') return badge('err', 'خطا');
    return badge('muted', s === 'DOWN' ? 'خاموش' : (st || 'نامشخص'));
  }

  async function loadLiveTunnels(force) {
    const box = $('#live-tunnels-list');
    if (!box) return;
    if (liveState.loading && !force) return;
    liveState.loading = true;
    liveState.error = null;
    if (!liveState.data) box.replaceChildren(loadingState());
    try {
      const data = await api('GET', '/api/tunnels/live');
      liveState.data = data.servers || [];
      liveState.scannedAt = data.scanned_at || null;
      renderLiveTunnels();
    } catch (e) {
      liveState.error = e.message || String(e);
      box.replaceChildren(emptyState('اسکن زنده ناموفق بود.', liveState.error));
    } finally {
      liveState.loading = false;
    }
  }

  function renderLiveTunnels() {
    const box = $('#live-tunnels-list');
    if (!box) return;
    const servers = liveState.data;
    if (!servers) {
      box.replaceChildren(emptyState('هنوز اسکن نشده است.', 'دکمه «بروزرسانی اسکن» را بزنید تا تانل‌های روی سرورها خوانده شوند.'));
      return;
    }
    if (!servers.length) {
      box.replaceChildren(emptyState('سروری ثبت نشده است.', 'اول از تب سرورها یک سرور اضافه کنید.'));
      return;
    }
    const groups = servers.map((srv) => {
      const roleLabel = srv.role === 'iran' ? 'ایران' : (srv.role === 'kharej' ? 'خارج' : srv.role);
      const head = h('div', { class: 'live-server-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, srv.name || '—'),
          h('span', { class: 'mode-chip', dir: 'ltr' }, `${roleLabel} · ${srv.host || ''}`)),
        srv.ok ? badge('ok', `${(srv.tunnels || []).length} تانل`) : badge('err', 'قطع'));
      const bootBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: !srv.ok }, 'ماندن بعد از ریبوت');
      bootBtn.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: 'ماندن بعد از ریبوت',
          message: `همه تانل‌های سرور «${srv.name}» برای بالا آمدن بعد از ریبوت فعال شوند؟`,
          okText: 'فعال‌سازی',
        });
        if (!ok) return;
        act(bootBtn, async () => {
          startedJob(await api('POST', `/api/servers/${enc(srv.id)}/enable-boot`), `ماندن بعد از ریبوت روی ${srv.name}`);
        });
      });
      let body;
      if (!srv.ok) {
        body = h('p', { class: 'check-info is-err' }, srv.error || 'اتصال یا خواندن لیست ناموفق بود.');
      } else if (!(srv.tunnels || []).length) {
        body = h('p', { class: 'muted' }, 'روی این سرور تانلی پیدا نشد.');
      } else {
        body = h('div', { class: 'live-tunnel-rows' }, (srv.tunnels || []).map((t) => {
          const mi = modeInfo(t.mode);
          const delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف کامل');
          delBtn.addEventListener('click', async () => {
            const res = await confirmDialog({
              title: t.orphan ? 'حذف تانل یتیم' : 'حذف تانل',
              message: t.orphan
                ? `تانل «${t.name}» فقط روی سرور «${srv.name}» است و در پنل نیست. از روی سرور حذف شود؟`
                : `تانل «${t.name}» (ثبت‌شده در پنل #${t.panel_tunnel_id}) حذف کامل شود؟`,
              okText: 'حذف',
              danger: true,
              checkboxLabel: 'حذف اجباری حتی اگر سرور پاسخ ندهد',
            });
            if (!res) return;
            act(delBtn, async () => {
              startedJob(
                await api('DELETE', `/api/servers/${enc(srv.id)}/remote-tunnels/${enc(t.name)}`, { force: !!res.checked }),
                'حذف تانل آغاز شد.',
              );
              load('tunnels', true);
              loadLiveTunnels(true);
            });
          });
          return h('div', { class: 'live-tunnel-row' },
            h('div', { class: 'live-tunnel-meta' },
              h('strong', { dir: 'ltr' }, t.name),
              h('span', { class: 'mode-chip', dir: 'ltr' }, mi ? mi.label : (t.mode || '?')),
              liveStatusBadge(t.status),
              badge(t.boot ? 'ok' : 'muted', t.boot ? 'boot: on' : 'boot: off'),
              t.orphan ? badge('warn', 'یتیم') : badge('info', `#${t.panel_tunnel_id}`)),
            h('dl', { class: 'kv live-kv' },
              kv('نقش', t.role || '—'),
              kv('IP محلی / مقابل', ltr(`${t.local_ip || '—'} / ${t.remote_ip || '—'}`)),
              kv('واحد', ltr(t.unit || '—'))),
            h('div', { class: 'card-actions' }, delBtn));
        }));
      }
      return h('article', { class: 'card live-server-card' },
        head,
        h('div', { class: 'card-actions' }, bootBtn),
        body);
    });
    const note = liveState.scannedAt
      ? h('p', { class: 'muted live-scan-meta' }, `آخرین اسکن: ${fmtTime(liveState.scannedAt)}`)
      : null;
    box.replaceChildren(note, h('div', { class: 'live-server-groups' }, groups));
  }

  function serverById(id) {
    return lists.servers.data.find((s) => s.id === id) || null;
  }

  function outboundGuide(t) {
    const mi = modeInfo(t.mode);
    const onKharej = !!(t.direct || t.users === 'kharej');
    const srv = serverById(onKharej ? t.kharej_id : t.iran_id);
    const panel = {
      name: onKharej ? (t.kharej_name || 'سرور خارج') : (t.iran_name || 'سرور ایران'),
      host: srv ? srv.host : '',
      role: onKharej ? 'خارج' : 'ایران',
      sendThrough: onKharej ? t.tun_kharej_ip : t.tun_iran_ip,
      peer: onKharej ? t.tun_iran_ip : t.tun_kharej_ip,
    };
    if (t.direct) return { kind: 'direct', t, mi, panel };
    if (XRAY_TUNNEL_MODES.has(t.mode)) return { kind: 'xray', t, mi, panel };
    if (!panel.sendThrough) return { kind: 'noip', t, mi, panel };
    return { kind: 'freedom', t, mi, panel, tag: `jojonet-${t.id}` };
  }

  function outboundCopyRow(title, value) {
    const copy = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, 'کپی');
    copy.addEventListener('click', () => copyVpnField(value));
    return h('div', { class: 'vpn-creds-row' },
      h('span', { class: 'vpn-creds-k' }, title),
      h('span', { dir: 'ltr', class: 'vpn-creds-value' }, value),
      copy);
  }

  function renderOutboundCard(t) {
    const g = outboundGuide(t);
    const label = g.mi ? g.mi.label : t.mode;
    const pair = t.direct
      ? `تانل مستقیم روی «${t.kharej_name || 'خارج'}»`
      : `تانل ${label} بین «${t.iran_name || 'ایران'}» و «${t.kharej_name || 'خارج'}»`;
    let body;
    if (g.kind === 'direct') {
      body = h('p', { class: 'muted' }, 'این تانل مستقیم است؛ کلاینت روی دستگاه کاربر اجرا می‌شود و اوتباند X-UI لازم نیست.');
    } else if (g.kind === 'xray') {
      body = h('p', { class: 'muted' }, 'این تانل خودش Xray است. در 3x-ui / X-UI اوتباند Freedom جدا برایش نگذارید.');
    } else if (g.kind === 'noip') {
      body = h('p', { class: 'muted' }, 'IP تانل این نوع هنوز آماده نیست یا این حالت overlay کلاسیک ندارد. بعد از سبز شدن تانل دوباره همین صفحه را باز کنید.');
    } else {
      const where = g.panel.host
        ? `پنل X-UI را روی سرور ${g.panel.role} «${g.panel.name}» (${g.panel.host}) باز کنید و این outbound را آنجا بگذارید.`
        : `پنل X-UI را روی سرور ${g.panel.role} «${g.panel.name}» باز کنید و این outbound را آنجا بگذارید.`;
      body = [
        h('p', { class: 'outbound-where' }, where),
        h('div', { class: 'vpn-creds-fields' },
          outboundCopyRow('پروتکل', 'Freedom'),
          outboundCopyRow('تگ', g.tag),
          outboundCopyRow('Send Through', g.panel.sendThrough),
          g.panel.peer ? outboundCopyRow('پینگ سمت مقابل', g.panel.peer) : null),
        h('ol', { class: 'outbound-steps' },
          h('li', null, 'وارد 3x-ui یا X-UI همان سرور شوید.'),
          h('li', null, 'Xray Settings ← Outbounds ← Add Outbound.'),
          h('li', null, `پروتکل Freedom، تگ ${g.tag}، فیلد Send Through را ${g.panel.sendThrough} بگذارید.`),
          h('li', null, `در Routing همین تگ را outbound پیش‌فرض کنید، ذخیره کنید و Xray را ری‌استارت کنید.`),
          h('li', null, 'اگر درست باشد IP خروجی کاربر می‌شود IP سرور خارج.')),
      ];
    }
    return h('article', { class: 'card outbound-card', id: `outbound-${t.id}` },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, pair),
          h('span', { class: 'mode-chip', dir: 'ltr' }, t.mode)),
        badge(t.status === 'ok' ? 'ok' : (t.status === 'failed' ? 'err' : 'muted'), t.status === 'ok' ? 'تانل آماده' : 'تانل')),
      body);
  }

  function renderOutbounds() {
    const box = $('#outbounds-list');
    if (!box) return;
    if (!lists.tunnels.loaded) {
      box.replaceChildren(loadingState());
      return;
    }
    const data = lists.tunnels.data || [];
    if (!data.length) {
      box.replaceChildren(emptyState(
        'هنوز تانلی ساخته نشده است.',
        'اول از تب تانل‌ها یک تانل بسازید؛ بعد اینجا می‌گوید اوتباند X-UI را روی کدام سرور و با چه مقادیری بگذارید.',
      ));
      return;
    }
    box.replaceChildren(...data.map(renderOutboundCard));
  }

  /* ---------- relays ---------- */

  function validRelayTarget(value, ipv4Only) {
    const v = (value || '').trim();
    if (IPV4_RE.test(v)) return true;
    if (ipv4Only) return false;
    return DOMAIN_RE.test(v) && v.includes('.') && !/^[0-9.]+$/.test(v);
  }

  function updateRelayEngine() {
    const engine = $('#rf-engine').value;
    const proto = $('#rf-proto');
    const isHa = engine === 'haproxy';
    for (const opt of proto.options) {
      if (opt.value === 'udp' || opt.value === 'both') opt.disabled = isHa;
    }
    if (isHa) proto.value = 'tcp';
  }

  function updateRelayForm() {
    const iranSel = $('#rf-iran');
    if (!iranSel) return;
    const servers = lists.servers.data;
    const opts = servers.map((s) => ({
      value: s.id,
      label: `${s.name} (${s.host}) — ${s.role === 'kharej' ? 'خارج' : 'ایران'}`,
    }));
    const loaded = lists.servers.loaded;
    fillSelect(iranSel, opts, !loaded ? 'در حال بارگذاری…' : opts.length ? 'انتخاب سرور…' : 'سروری ثبت نشده است');
    iranSel.disabled = !opts.length;
    $('#rf-submit').disabled = !opts.length;
    updateRelayEngine();
  }

  const VPN_PANEL_META = {
    xui: {
      label: '3x-ui سنایی',
      confirm: (name) => `پنل 3x-ui سنایی روی سرور «${name}» نصب شود؟ نصب رسمی است و ممکن است چند دقیقه طول بکشد. با X-UI اصلی همزمان نصب نمی‌شود.`,
    },
    xui_classic: {
      label: 'X-UI اصلی',
      confirm: (name) => `پنل X-UI اصلی (علیرضا) روی سرور «${name}» نصب شود؟ نصب رسمی است و ممکن است چند دقیقه طول بکشد. اگر 3x-ui سنایی نصب باشد باید اول حذف شود.`,
    },
    pasarguard: {
      label: 'پاسارگارد',
      confirm: (name) => `پنل پاسارگارد روی سرور «${name}» نصب شود؟ به Docker نیاز دارد و روی سرور 1 گیگ ممکن است سنگین باشد. نصب ممکن است چند دقیقه طول بکشد.`,
    },
  };

  const ANSI_RE = /\u001b\[[0-9;]*[A-Za-z]/g;
  const BOX_RE = /[┌┐└┘│─━═╭╮╰╯]/;
  const LOG_HUMAN = [
    [/Installing official.*3x-ui|official MHSanaei 3x-ui/i, 'info', 'در حال نصب پنل 3x-ui سنایی'],
    [/Installing official.*classic|official alireza0|Installing official.*X-UI/i, 'info', 'در حال نصب پنل X-UI اصلی'],
    [/Installing official.*PasarGuard|Installing PasarGuard/i, 'info', 'در حال نصب پنل پاسارگارد'],
    [/credentials are printed/i, 'info', 'بعد از نصب، مشخصات ورود همین‌جا نشان داده می‌شود'],
    [/3x-ui install finished/i, 'ok', 'نصب 3x-ui تمام شد'],
    [/Classic X-UI install finished/i, 'ok', 'نصب X-UI اصلی تمام شد'],
    [/PasarGuard install finished/i, 'ok', 'نصب پاسارگارد تمام شد'],
    [/already installed and running/i, 'warn', 'این پنل از قبل روی سرور نصب و روشن است'],
    [/already installed/i, 'warn', 'این پنل از قبل نصب است'],
    [/همین پنل از قبل/i, 'warn', 'همین پنل از قبل روی این سرور نصب است؛ نصب دوباره انجام نشد'],
    [/نصب دوباره انجام نشد/i, 'warn', 'نصب دوباره انجام نشد'],
    [/قبلاً X-UI اصلی نصب/i, 'err', 'روی این سرور قبلاً X-UI اصلی نصب شده است'],
    [/قبلاً 3x-ui سنایی نصب/i, 'err', 'روی این سرور قبلاً 3x-ui سنایی نصب شده است'],
    [/Could not download/i, 'err', 'دانلود نصب‌کننده ناموفق بود'],
    [/installer failed/i, 'err', 'نصب‌کننده پنل با خطا متوقف شد'],
    [/X-UI is not installed/i, 'warn', 'پنل X-UI روی این سرور نصب نیست'],
    [/PasarGuard is not installed/i, 'warn', 'پاسارگارد روی این سرور نصب نیست'],
    [/root required|needs root/i, 'err', 'برای نصب باید با کاربر root وصل شوید'],
    [/Cancelled\.?$/i, 'warn', 'نصب لغو شد'],
    [/Another X-UI flavor/i, 'err', 'نوع دیگری از X-UI نصب است؛ اول باید حذف شود'],
    [/3x-ui \(Sanaei\) is installed/i, 'err', '3x-ui سنایی نصب است؛ برای X-UI اصلی اول آن را حذف کنید'],
    [/X-UI classic is installed/i, 'err', 'X-UI اصلی نصب است؛ برای 3x-ui اول آن را حذف کنید'],
    [/systemd is required/i, 'err', 'این سرور systemd ندارد و نصب پنل ممکن نیست'],
    [/No VPN panel login found/i, 'warn', 'مشخصات ورود پیدا نشد'],
    [/مشخصات ورود در خروجی نصب پیدا نشد/, 'warn', 'مشخصات ورود در خروجی نصب پیدا نشد'],
    [/^try\s+https?:\/\//i, 'info', 'در حال دانلود نصب‌کننده…'],
    [/Access URL:\s*(\S+)/i, 'cred', (m) => `آدرس ورود: ${m[1]}`],
    [/^Username:\s*(\S+)/i, 'cred', (m) => `نام کاربری: ${m[1]}`],
    [/^Password:\s*\S+/i, 'cred', 'رمز عبور آماده شد'],
    [/^Port:\s*(\S+)/i, 'info', (m) => `پورت پنل: ${m[1]}`],
    [/unit:\s*active/i, 'ok', 'سرویس پنل روی سرور فعال است'],
    [/unit:\s*not installed/i, 'warn', 'سرویس پنل هنوز نصب نشده'],
    [/Web server running HTTP/i, 'ok', 'وب‌سرور پنل بالا آمد'],
    [/first login:/i, null, null],
    [/separate from JojoNet tunnels/i, null, null],
  ];

  function stripAnsi(s) {
    return String(s || '').replace(ANSI_RE, '').replace(/\r/g, '');
  }

  function isNoiseLog(body) {
    const t = body.trim();
    if (!t) return true;
    if (/^[=─\-━_]{4,}$/.test(t)) return true;
    if (/JOJONET_VPN_CREDS/.test(t)) return true;
    if (/^(kind|label|url|username|password|note)=/.test(t)) return true;
    if (/^-----/.test(t)) return true;
    if (t === 'این مشخصات را ذخیره کنید.') return true;
    if (BOX_RE.test(t)) return true;
    if (/x-ui control menu|Admin Management Script|Current Status|Check logs|Update to Dev|Legacy version|Check Fail2ban/i.test(t)) return true;
    if (/^The OS release is/i.test(t)) return true;
    if (/ignored "true"|put flags before/i.test(t)) return true;
    if (/^current panel settings/i.test(t)) return true;
    if (/^Warning: Panel is not secure/i.test(t)) return true;
    if (/^Database: SQLite/i.test(t)) return true;
    if (/No SSL certificate|Let's Encrypt certificate|main menu option/i.test(t)) return true;
    if (/^Invalid subcommands/i.test(t)) return true;
    if (/^hasDefaultCredential/i.test(t)) return true;
    if (/^webBasePath:/i.test(t)) return true;
    if (/^cli:\s|^\s*bin:\s/i.test(t)) return true;
    if (/^(Loaded|Drop-In|Active|Invocation|Main PID|Tasks|Memory|CPU|CGroup|Process|Docs):/i.test(t)) return true;
    if (/^[├└│●]/.test(t)) return true;
    if (/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+/i.test(t)) return true;
    if (/systemd\[\d+\]:|x-ui\[\d+\]:/.test(t)) return true;
    if (/^listen:\s/i.test(t)) return true;
    if (/^---\s/.test(t)) return true;
    if (/Starting x-ui|GC percent|Go memory|restart Xray|XRAY:/i.test(t)) return true;
    return false;
  }

  function classifyLogLine(line) {
    const clean = stripAnsi(line).replace(/\s+$/, '');
    if (!clean.trim()) return null;
    const pref = /^\[([^\]]+)\]\s*(.*)$/.exec(clean);
    const server = pref ? pref[1] : '';
    const body = (pref ? pref[2] : clean).trim();
    if (isNoiseLog(body)) return null;
    if (/^▶\s*/.test(body)) return { kind: 'step', text: body.replace(/^▶\s*/, ''), server: '' };
    if (/^✖\s*/.test(body)) return { kind: 'err', text: body.replace(/^✖\s*/, ''), server };
    if (/^\s*پنل:/.test(body) || /^\s*آدرس:/.test(body) || /^\s*کاربر:/.test(body)) {
      return { kind: 'cred', text: body.replace(/^\s+/, ''), server };
    }
    if (/^\s*رمز:/.test(body)) return { kind: 'cred', text: 'رمز عبور در کارت مشخصات ورود ذخیره شد', server };
    if (/^\s*نکته:/.test(body)) return { kind: 'info', text: body.replace(/^\s+نکته:\s*/, ''), server };
    for (const [re, kind, msg] of LOG_HUMAN) {
      const m = re.exec(body);
      if (!m) continue;
      if (!kind) return null;
      return { kind, text: typeof msg === 'function' ? msg(m) : msg, server };
    }
    if (/\[!\]/.test(body) || /error|failed|ناموفق|خطا/i.test(body)) {
      return { kind: 'err', text: body.replace(/^\[!\]\s*/, ''), server };
    }
    if (/\[\+\]/.test(body) || /finished|موفق|تمام شد/i.test(body)) {
      return { kind: 'ok', text: body.replace(/^\[\+\]\s*/, ''), server };
    }
    if (/\[\*\]/.test(body)) return { kind: 'info', text: body.replace(/^\[\*\]\s*/, ''), server };
    return { kind: 'info', text: body, server };
  }

  function isFactLine(text) {
    return /^[A-Za-z][\w./-]*:\s+\S/.test(String(text || ''));
  }

  function splitFact(text) {
    const i = String(text).indexOf(':');
    return i < 0 ? [text, ''] : [text.slice(0, i), text.slice(i + 1).trim()];
  }

  function collapseFactRows(rows) {
    const out = [];
    let bag = [];
    const flush = () => {
      if (!bag.length) return;
      if (bag.length === 1) out.push(bag[0]);
      else out.push({ kind: 'facts', facts: bag.map((r) => r.text), server: bag[0].server, count: 1 });
      bag = [];
    };
    for (const row of rows) {
      if (row.kind === 'info' && isFactLine(row.text)) bag.push(row);
      else {
        flush();
        out.push(row);
      }
    }
    flush();
    return out;
  }

  function logRowEl(row, grouped) {
    const label = LOG_KIND_LABEL[row.kind] || 'اطلاعات';
    const count = row.count > 1 ? h('span', { class: 'log-count' }, `${row.count} بار`) : null;
    const src = (!grouped && row.server) ? h('div', { class: 'log-src' }, row.server) : null;
    if (row.kind === 'facts') {
      return h('article', { class: 'log-card log-card-facts log-row-info' },
        h('span', { class: 'log-card-mark', 'aria-hidden': 'true' }),
        h('div', { class: 'log-card-body' },
          h('div', { class: 'log-card-top' }, h('span', { class: 'log-kind log-kind-info' }, 'جزئیات سیستم')),
          h('dl', { class: 'log-facts' },
            ...(row.facts || []).flatMap((line) => {
              const [k, v] = splitFact(line);
              return [h('dt', null, k), h('dd', { dir: 'ltr' }, v || '—')];
            })),
          src));
    }
    return h('article', { class: `log-card log-row-${row.kind}` },
      h('span', { class: 'log-card-mark', 'aria-hidden': 'true' }),
      h('div', { class: 'log-card-body' },
        h('div', { class: 'log-card-top' },
          h('span', { class: `log-kind log-kind-${row.kind}` }, label),
          count),
        h('p', { class: 'log-text' }, row.text),
        src));
  }

  function paintLogFeed(jv) {
    if (!jv.feedEl) return;
    const rows = [];
    let prev = null;
    for (const line of (jv.rawLog || '').split('\n')) {
      const row = classifyLogLine(line);
      if (!row || row.kind === 'step') continue;
      if (prev && prev.text === row.text && prev.kind === row.kind && prev.server === row.server) {
        prev.count = (prev.count || 1) + 1;
        continue;
      }
      row.count = 1;
      rows.push(row);
      prev = row;
    }
    if (!rows.length) {
      jv.feedEl.replaceChildren(h('div', { class: 'log-empty' }, 'هنوز گزارشی ثبت نشده است.'));
      jv.lastHuman = '';
      return;
    }
    const groups = [];
    for (const row of collapseFactRows(rows)) {
      const key = row.server || '';
      const last = groups[groups.length - 1];
      if (!last || last.server !== key) groups.push({ server: key, rows: [row] });
      else last.rows.push(row);
    }
    const nodes = [];
    for (const g of groups) {
      if (g.server) nodes.push(h('div', { class: 'log-group-head' }, g.server));
      for (const row of g.rows) nodes.push(logRowEl(row, !!g.server));
    }
    jv.feedEl.replaceChildren(...nodes);
    jv.lastHuman = rows[rows.length - 1].text;
    if (jv.nowEl) {
      const live = jv.job && (jv.job.status === 'running' || jv.job.status === 'queued');
      jv.nowEl.hidden = !live;
      if (live) jv.nowEl.textContent = jv.lastHuman;
    }
  }

  function setLogText(jv, text) {
    jv.rawLog = text || '';
    if (jv.rawEl) jv.rawEl.textContent = jv.rawLog;
    paintLogFeed(jv);
    if (jv.barEl) refreshVpnCreds(jv.rawLog);
  }

  function appendLiveLog(jv, line) {
    jv.rawLog = `${jv.rawLog || ''}${line}\n`;
    if (jv.rawEl) jv.rawEl.textContent = jv.rawLog;
    paintLogFeed(jv);
    if (jv.barEl) refreshVpnCreds(jv.rawLog);
  }

  function toggleRawLog(jv) {
    jv.showRaw = !jv.showRaw;
    if (jv.feedEl) jv.feedEl.hidden = !!jv.showRaw;
    if (jv.rawEl) jv.rawEl.hidden = !jv.showRaw;
    const btn = jv.rawBtn;
    if (btn) btn.textContent = jv.showRaw ? 'گزارش ساده' : 'جزئیات فنی';
    scrollLog(jv);
  }

  function bindLogScroll(el, jv) {
    if (!el) return;
    el.addEventListener('scroll', () => {
      jv.stick = el.scrollTop + el.clientHeight >= el.scrollHeight - 24;
      if (jv.followBtn) jv.followBtn.hidden = jv.stick;
    });
  }

  function parseVpnCreds(text) {
    if (!text) return null;
    const start = text.lastIndexOf('===== JOJONET_VPN_CREDS =====');
    if (start < 0) return null;
    const rest = text.slice(start);
    const end = rest.indexOf('===== END_JOJONET_VPN_CREDS =====');
    const block = end >= 0 ? rest.slice(0, end) : rest;
    const out = {};
    for (const raw of block.split('\n')) {
      const line = raw.replace(/^\[[\s\S]*?\]\s*/, '').trim();
      const m = /^(kind|label|url|username|password|note)=(.*)$/.exec(line);
      if (m && m[2]) out[m[1]] = m[2];
    }
    return (out.url || out.username || out.password) ? out : null;
  }

  async function copyVpnField(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('کپی شد.', 'success');
    } catch (err) {
      toast('کپی نشد؛ دستی کپی کنید.', 'error');
    }
  }

  function hideVpnCreds() {
    const box = $('#vpn-creds');
    if (!box) return;
    box.hidden = true;
    const fields = $('#vpn-creds-fields');
    if (fields) fields.replaceChildren();
    const note = $('#vpn-creds-note');
    if (note) {
      note.hidden = true;
      note.textContent = '';
    }
    const label = $('#vpn-creds-label');
    if (label) label.textContent = '';
  }

  function renderVpnCreds(creds) {
    const box = $('#vpn-creds');
    if (!box) return;
    if (!creds) {
      box.hidden = true;
      return;
    }
    const labelEl = $('#vpn-creds-label');
    if (labelEl) labelEl.textContent = creds.label || 'پنل VPN';
    const rows = [];
    const add = (title, value, href) => {
      if (!value) return;
      const valEl = href
        ? h('a', { href, target: '_blank', rel: 'noopener noreferrer', dir: 'ltr', class: 'vpn-creds-value' }, value)
        : h('span', { dir: 'ltr', class: 'vpn-creds-value' }, value);
      const copy = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, 'کپی');
      copy.addEventListener('click', () => copyVpnField(value));
      rows.push(h('div', { class: 'vpn-creds-row' },
        h('span', { class: 'vpn-creds-k' }, title),
        valEl,
        copy));
    };
    add('آدرس', creds.url, /^https?:\/\//.test(creds.url || '') ? creds.url : '');
    add('کاربر', creds.username);
    add(creds.kind === 'pasarguard' ? 'کلید موقت' : 'رمز', creds.password);
    const fields = $('#vpn-creds-fields');
    if (fields) fields.replaceChildren(...rows);
    const note = $('#vpn-creds-note');
    if (note) {
      if (creds.note) {
        note.hidden = false;
        note.textContent = creds.note;
      } else {
        note.hidden = true;
        note.textContent = '';
      }
    }
    box.hidden = false;
  }

  function refreshVpnCreds(text) {
    const creds = parseVpnCreds(text || '');
    if (creds) renderVpnCreds(creds);
  }

  function openVpnMonitor(id, title, subtitle) {
    const box = $('#vpn-monitor');
    if (!box) {
      openJobView(id);
      return;
    }
    if (state.vpnMon) stopJobView(state.vpnMon);
    box.hidden = false;
    $('#vpn-mon-title').textContent = title || 'مانیتور نصب';
    $('#vpn-mon-sub').textContent = subtitle || '';
    $('#vpn-mon-bar').style.width = '6%';
    $('#vpn-mon-pct').textContent = '0٪';
    $('#vpn-mon-steps').replaceChildren();
    const nowEl = $('#vpn-mon-now');
    if (nowEl) {
      nowEl.hidden = false;
      nowEl.textContent = 'در انتظار شروع…';
    }
    box.classList.remove('is-ok', 'is-failed');
    box.classList.add('is-running');
    hideVpnCreds();
    box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    const jv = {
      id,
      closed: false,
      done: false,
      es: null,
      pollTimer: null,
      stick: true,
      showRaw: false,
      rawLog: '',
      lastHuman: '',
      job: null,
      statusEl: $('#vpn-mon-status'),
      metaEl: h('dl'),
      stepsEl: $('#vpn-mon-steps'),
      feedEl: $('#vpn-mon-log'),
      rawEl: $('#vpn-mon-rawlog'),
      nowEl,
      logEl: $('#vpn-mon-log'),
      followBtn: $('#vpn-mon-follow'),
      rawBtn: $('#vpn-mon-raw'),
      barEl: $('#vpn-mon-bar'),
      pctEl: $('#vpn-mon-pct'),
      m: { titleEl: $('#vpn-mon-title') },
    };
    if (jv.feedEl) {
      jv.feedEl.hidden = false;
      jv.feedEl.replaceChildren();
    }
    if (jv.rawEl) {
      jv.rawEl.hidden = true;
      jv.rawEl.textContent = '';
    }
    if (jv.rawBtn) jv.rawBtn.textContent = 'جزئیات فنی';
    if (jv.followBtn) jv.followBtn.hidden = true;
    state.vpnMon = jv;
    (async () => {
      try {
        const job = await api('GET', `/api/jobs/${enc(id)}`);
        if (jv.closed) return;
        renderJob(jv, job);
        if (isActive(job.status)) {
          trackJob(id);
          startStream(jv);
        } else {
          jv.done = true;
          updateVpnProgress(jv);
        }
      } catch (err) {
        if (jv.closed || err.status === 401) return;
        jv.statusEl.replaceChildren(errorState(err.message));
      }
    })();
  }

  function updateVpnPanelForm() {
    const sel = $('#vpf-server');
    if (!sel) return;
    const servers = lists.servers.data;
    const opts = servers.map((s) => ({
      value: s.id,
      label: `${s.name} (${s.host}) — ${s.role === 'kharej' ? 'خارج' : 'ایران'}`,
    }));
    const loaded = lists.servers.loaded;
    fillSelect(sel, opts, !loaded ? 'در حال بارگذاری…' : opts.length ? 'انتخاب سرور…' : 'سروری ثبت نشده است');
    sel.disabled = !opts.length;
    const ready = !!opts.length;
    for (const btn of document.querySelectorAll('.vpn-panel-card')) btn.disabled = !ready;
  }

  async function onInstallVpnPanel(e) {
    const btn = e.currentTarget;
    const kind = btn && btn.dataset ? btn.dataset.kind : '';
    const errBox = $('#vpf-error');
    hideErr(errBox);
    const sid = $('#vpf-server').value;
    const srv = lists.servers.data.find((s) => String(s.id) === sid);
    if (!srv) {
      showErr(errBox, 'اول یک سرور انتخاب کنید.');
      return;
    }
    const meta = VPN_PANEL_META[kind];
    if (!meta) {
      showErr(errBox, 'نوع پنل نامعتبر است.');
      return;
    }
    let pre = null;
    try {
      pre = await api('GET', `/api/servers/${enc(sid)}/vpn-panels?kind=${enc(kind)}`);
    } catch (err) {
      pre = null;
    }
    if (pre && pre.conflict) {
      showErr(errBox, pre.message || 'نوع دیگری از X-UI روی این سرور نصب است. اول باید حذف شود.');
      return;
    }
    let title = `تأیید نصب ${meta.label}`;
    let message = meta.confirm(srv.name);
    let okText = 'شروع نصب';
    let toastMsg = `نصب ${meta.label} پس از تأیید شما شروع شد.`;
    if (pre && pre.already) {
      title = `${meta.label} از قبل نصب است`;
      message = `${pre.message || `همین پنل روی «${srv.name}» نصب است.`} نصب دوباره انجام نمی‌شود. مشخصات ورود نمایش داده شود؟`;
      okText = 'نمایش مشخصات';
      toastMsg = `${meta.label} از قبل روی سرور نصب بود.`;
    }
    const ok = await confirmDialog({ title, message, okText });
    if (!ok) return;
    await act(btn, async () => {
      const r = await api('POST', `/api/servers/${enc(sid)}/vpn-panel`, { kind });
      if (r && r.job_id != null) {
        trackJob(r.job_id);
        load('jobs', true);
        openVpnMonitor(r.job_id, pre && pre.already ? `وضعیت ${meta.label}` : `نصب ${meta.label}`, `${srv.name} · ${srv.host}`);
        toast(toastMsg, pre && pre.already ? 'info' : 'success');
      }
    }, pre && pre.already ? 'در حال خواندن وضعیت…' : 'در حال ارسال…');
  }

  async function onCreateRelay(e) {
    e.preventDefault();
    const errBox = $('#rf-error');
    const btn = $('#rf-submit');
    hideErr(errBox);
    const engine = $('#rf-engine').value;
    const findSrv = (v) => lists.servers.data.find((s) => String(s.id) === v);
    const iran = findSrv($('#rf-iran').value);
    const target = $('#rf-target').value.trim();
    const ports = $('#rf-ports').value.replace(/\s+/g, '');
    const proto = $('#rf-proto').value;
    const nameRaw = $('#rf-name').value.trim().toLowerCase();
    if (!['iptables', 'gost', 'haproxy', 'socat', 'xray'].includes(engine)) return showErr(errBox, 'موتور رله را انتخاب کنید.');
    if (!iran) return showErr(errBox, 'سرور را انتخاب کنید.');
    if (!validRelayTarget(target, engine === 'iptables')) {
      return showErr(errBox, engine === 'iptables' ? 'مقصد رله باید IPv4 معتبر باشد.' : 'مقصد رله باید IPv4 یا دامنه معتبر باشد.');
    }
    if (!ports || !PORTS_SPEC_RE.test(ports)) return showErr(errBox, 'پورت‌ها باید به شکل 443 یا 2096:443 باشند.');
    if (engine === 'haproxy' && proto !== 'tcp') return showErr(errBox, 'رله HAProxy فقط TCP است.');
    if (nameRaw && !RELAY_NAME_RE.test(nameRaw)) return showErr(errBox, 'نام رله: حروف کوچک انگلیسی، عدد و خط تیره (حداکثر 24).');
    const payload = { engine, iran_id: iran.id, target, ports, proto };
    if (nameRaw) payload.name = nameRaw;
    if (btn.disabled) return undefined;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = 'در حال ارسال…';
    try {
      const r = await api('POST', '/api/relays', payload);
      startedJob(r, 'ساخت رله آغاز شد.');
      load('relays');
      $('#rf-name').value = '';
    } catch (err) {
      if (err.status !== 401) showErr(errBox, err.message);
    } finally {
      btn.removeAttribute('aria-busy');
      btn.textContent = 'ساخت رله';
      updateRelayForm();
    }
    return undefined;
  }

  function renderRelays() {
    const box = $(lists.relays.el);
    const data = lists.relays.data;
    if (!data.length) {
      box.replaceChildren(emptyState('هنوز رله‌ای ساخته نشده است.', 'از فرم «ساخت رله» در بالا اولین رله را روی سرور ایران بسازید.'));
      return;
    }
    box.replaceChildren(h('div', { class: 'cards' }, data.map(relayCard)));
  }

  function relayCard(r) {
    const [kind, label] = RELAY_STATUS[r.status] || ['muted', r.status || 'نامشخص'];
    const transient = r.status === 'deploying' || r.status === 'deleting';
    const lc = r.last_check;

    const statsBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'آمار');
    statsBtn.addEventListener('click', () => act(statsBtn, async () => {
      startedJob(await api('POST', `/api/relays/${enc(r.id)}/stats`));
      load('relays', true);
    }));

    const logBtn = r.last_job_id != null
      ? h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: () => openJobView(r.last_job_id) }, 'آخرین کار')
      : null;

    const delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف');
    delBtn.addEventListener('click', async () => {
      const res = await confirmDialog({
        title: 'حذف رله',
        message: `رله «${r.name}» از روی سرور «${r.server_name || '—'}» و از پنل حذف شود؟`,
        okText: 'حذف رله',
        danger: true,
        checkboxLabel: 'حذف اجباری از پنل حتی اگر سرور در دسترس نباشد',
      });
      if (!res) return;
      act(delBtn, async () => {
        startedJob(await api('DELETE', `/api/relays/${enc(r.id)}`, { force: !!res.checked }), 'حذف رله آغاز شد.');
        load('relays', true);
      });
    });

    return h('article', { class: 'card tunnel-card' },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, r.name || 'رله', ownerChip(r)),
          h('span', { class: 'mode-chip', dir: 'ltr' }, RELAY_ENGINE[r.engine] || r.engine)),
        badge(kind, label, transient)),
      h('dl', { class: 'kv' },
        kv('سرور ایران', r.server_name || '—'),
        kv('مقصد', ltr(r.target)),
        kv('پورت‌ها', ltr(r.ports)),
        kv('پروتکل', ltr(r.proto || 'both')),
        kv('آخرین بررسی', lc ? fmtTime(lc.at) : '—'),
        kv('زمان ساخت', fmtTime(r.created_at))),
      lc && lc.info ? h('p', { class: `check-info${lc.ok ? '' : ' is-err'}` }, infoText(lc.info)) : null,
      h('div', { class: 'card-actions' }, statsBtn, logBtn, delBtn));
  }

  /* ---------- users (owner) ---------- */

  function showOnceSecret(title, password, extra) {
    const box = h('code', { class: 'fp', dir: 'ltr' }, password);
    let m;
    m = openModal({
      title,
      body: [
        h('p', { class: 'confirm-msg' }, extra || 'این رمز فقط یک بار نمایش داده می‌شود. همین حالا ذخیره کنید.'),
        h('p', null, box),
      ],
      footer: [h('button', { type: 'button', class: 'btn btn-primary', onclick: () => m.close() }, 'متوجه شدم')],
    });
  }

  function renderUsers() {
    const box = $(lists.users.el);
    const data = lists.users.data || [];
    if (!data.length) {
      box.replaceChildren(emptyState('هنوز مشتری‌ای ساخته نشده است.', 'از فرم بالا یک حساب مشتری بسازید.'));
      return;
    }
    box.replaceChildren(h('div', { class: 'cards' }, data.map(userCard)));
  }

  function userCard(u) {
    const owner = u.role === 'owner';
    const usage = u.usage || {};
    const days = u.days_left;
    const status = !u.enabled ? ['err', 'غیرفعال'] : (days === 0 ? ['warn', 'منقضی'] : ['ok', 'فعال']);

    const extendBtn = owner ? null : h('button', { type: 'button', class: 'btn btn-sm' }, 'تمدید روز');
    if (extendBtn) extendBtn.addEventListener('click', () => openExtendUser(u));

    const toggleBtn = owner ? null : h('button', { type: 'button', class: 'btn btn-sm' }, u.enabled ? 'غیرفعال' : 'فعال');
    if (toggleBtn) toggleBtn.addEventListener('click', () => act(toggleBtn, async () => {
      await api('PATCH', `/api/users/${enc(u.id)}`, { enabled: !u.enabled });
      toast(u.enabled ? `حساب «${u.username}» غیرفعال شد.` : `حساب «${u.username}» فعال شد.`, 'success');
      await load('users');
    }));

    const pwBtn = owner ? null : h('button', { type: 'button', class: 'btn btn-sm' }, 'بازنشانی رمز');
    if (pwBtn) pwBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'بازنشانی رمز',
        message: `رمز «${u.username}» عوض شود؟ نشست‌های فعلی قطع می‌شوند.`,
        okText: 'بازنشانی',
      });
      if (!ok) return;
      act(pwBtn, async () => {
        const r = await api('POST', `/api/users/${enc(u.id)}/password`, {});
        if (r && r.password) showOnceSecret(`رمز جدید «${u.username}»`, r.password);
        toast('رمز بازنشانی شد.', 'success');
      });
    });

    const termBtn = owner ? null : h('button', { type: 'button', class: 'btn btn-sm' }, u.allow_term !== false ? 'بستن ترمینال' : 'باز کردن ترمینال');
    if (termBtn) termBtn.addEventListener('click', () => act(termBtn, async () => {
      const next = u.allow_term === false;
      await api('PATCH', `/api/users/${enc(u.id)}`, { allow_term: next });
      toast(next ? `ترمینال «${u.username}» روشن شد.` : `ترمینال «${u.username}» بسته شد.`, 'success');
      await load('users');
    }));

    const delBtn = owner ? null : h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف');
    if (delBtn) delBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'حذف مشتری',
        message: `حساب «${u.username}» حذف شود؟ نشست‌ها قطع می‌شوند.`,
        okText: 'حذف',
        danger: true,
      });
      if (!ok) return;
      act(delBtn, async () => {
        await api('DELETE', `/api/users/${enc(u.id)}`);
        toast(`حساب «${u.username}» حذف شد.`, 'success');
        await load('users');
      });
    });

    return h('article', { class: 'card user-card' },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, u.username),
          h('span', { class: 'mode-chip' }, owner ? 'مالک' : 'مشتری')),
        badge(status[0], status[1])),
      h('dl', { class: 'kv' },
        kv('انقضا', owner ? 'بدون انقضا' : (u.expires_at ? `${fmtTime(u.expires_at)}${days != null ? ` (${fmtNum(days)} روز)` : ''}` : 'بدون انقضا')),
        kv('سرور', limitText(usage.servers || 0, u.max_servers, '')),
        kv('تانل', limitText(usage.tunnels || 0, u.max_tunnels, '')),
        kv('رله', limitText(usage.relays || 0, u.max_relays, '')),
        kv('VPN / رله / آپدیت / ترمینال', `${u.allow_vpn ? 'بله' : 'خیر'} / ${u.allow_relay ? 'بله' : 'خیر'} / ${u.allow_os_update ? 'بله' : 'خیر'} / ${u.allow_term !== false ? 'بله' : 'خیر'}`),
        kv('یادداشت', u.note || '—')),
      h('div', { class: 'card-actions' }, extendBtn, toggleBtn, termBtn, pwBtn, delBtn));
  }

  function openExtendUser(u) {
    const errBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
    const days = h('input', { id: uid('f'), type: 'number', dir: 'ltr', min: '1', max: '3650', required: true, value: '30' });
    const form = h('form', { class: 'form', novalidate: true }, errBox, field('تعداد روز', days));
    form.id = uid('ex');
    const saveBtn = h('button', { type: 'submit', class: 'btn btn-primary', form: form.id }, 'تمدید');
    const m = openModal({
      title: `تمدید اشتراک «${u.username}»`,
      body: form,
      footer: [h('button', { type: 'button', class: 'btn', onclick: () => m.close() }, 'انصراف'), saveBtn],
    });
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const n = Number(days.value);
      if (!Number.isInteger(n) || n < 1) return showErr(errBox, 'تعداد روز باید عدد مثبت باشد.');
      act(saveBtn, async () => {
        await api('POST', `/api/users/${enc(u.id)}/extend`, { days: n });
        toast(`اشتراک «${u.username}» تمدید شد.`, 'success');
        m.close();
        await load('users');
      });
    });
  }

  function optLimit(el) {
    const v = el.value.trim();
    if (!v) return null;
    const n = Number(v);
    return Number.isInteger(n) && n >= 0 ? n : NaN;
  }

  async function onCreateUser(e) {
    e.preventDefault();
    const errBox = $('#uf-error');
    hideErr(errBox);
    const username = $('#uf-username').value.trim();
    if (!username) return showErr(errBox, 'نام کاربری را وارد کنید.');
    const daysRaw = $('#uf-days').value.trim();
    const days = daysRaw ? Number(daysRaw) : null;
    if (daysRaw && (!Number.isInteger(days) || days < 1)) return showErr(errBox, 'روز اشتراک باید عدد مثبت باشد.');
    const maxServers = optLimit($('#uf-max-servers'));
    const maxTunnels = optLimit($('#uf-max-tunnels'));
    const maxRelays = optLimit($('#uf-max-relays'));
    if (Number.isNaN(maxServers) || Number.isNaN(maxTunnels) || Number.isNaN(maxRelays)) {
      return showErr(errBox, 'سقف‌ها باید عدد صفر یا بزرگ‌تر باشند (خالی = نامحدود).');
    }
    const payload = {
      username,
      password: $('#uf-password').value || null,
      days,
      max_servers: maxServers,
      max_tunnels: maxTunnels,
      max_relays: maxRelays,
      allow_vpn: $('#uf-vpn').checked,
      allow_relay: $('#uf-relay').checked,
      allow_os_update: $('#uf-os').checked,
      allow_term: $('#uf-term') ? $('#uf-term').checked : true,
      note: $('#uf-note').value.trim() || null,
    };
    const btn = $('#uf-submit');
    act(btn, async () => {
      const r = await api('POST', '/api/users', payload);
      toast(`مشتری «${username}» ساخته شد.`, 'success');
      $('#user-form').reset();
      $('#uf-days').value = '30';
      $('#uf-vpn').checked = true;
      $('#uf-relay').checked = true;
      $('#uf-os').checked = true;
      if ($('#uf-term')) $('#uf-term').checked = true;
      if (r && r.password) showOnceSecret(`رمز «${username}»`, r.password);
      await load('users');
    });
  }

  /* ---------- jobs ---------- */

  function paintOpsClock() {
    const el = $('#jobs-ops-clock');
    if (!el) return;
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    el.textContent = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  }

  function paintOpsHud() {
    const el = $('#jobs-ops-live');
    if (el) {
      const live = (lists.jobs.data || []).some((j) => isActive(j.status));
      el.textContent = live ? 'LIVE' : 'STANDBY';
      el.classList.toggle('is-live', live);
    }
    paintOpsClock();
  }

  function jobBadge(status) {
    const [kind, label] = JOB_STATUS[status] || ['muted', status || 'نامشخص'];
    return badge(kind, label, isActive(status));
  }

  function renderJobs() {
    const box = $(lists.jobs.el);
    const data = lists.jobs.data;
    paintOpsHud();
    if (!data.length) {
      box.replaceChildren(emptyState('SYS.IDLE — هنوز عملیاتی ثبت نشده.', 'با تست اتصال، نصب یا ساخت تانل، لاگ اینجا می‌آید.'));
      return;
    }
    const rows = data.map((j) => {
      const open = () => openJobView(j.id);
      const label = JOB_STATUS[j.status] ? JOB_STATUS[j.status][1] : j.status;
      const code = JOB_CODE[j.status] || '???';
      return h('div', {
        class: 'job-row',
        role: 'button',
        tabindex: '0',
        'aria-label': `${j.title || j.kind} — ${label}`,
        onclick: open,
        onkeydown: (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            open();
          }
        },
      },
      h('span', { class: 'job-prompt', 'aria-hidden': 'true' }, '>'),
      h('span', { class: 'job-main' },
        h('span', { class: 'job-title' }, j.title || j.kind || `کار ${j.id}`, ownerChip(j)),
        h('span', { class: 'job-kind', dir: 'ltr' }, j.kind || '')),
      h('span', { class: `job-code job-code-${j.status || 'unknown'}`, dir: 'ltr' }, code),
      h('span', { class: 'job-time' }, fmtTime(j.created_at)),
      h('span', { class: 'job-dur' }, j.finished_at ? fmtDuration(j.created_at, j.finished_at) : '—'));
    });
    box.replaceChildren(h('div', { class: 'job-list' }, rows));
  }

  function closeJobView() {
    if (state.jobView) state.jobView.m.close();
  }

  function stopJobView(jv) {
    jv.closed = true;
    if (jv.es) jv.es.close();
    jv.es = null;
    if (jv.pollTimer) clearTimeout(jv.pollTimer);
    jv.pollTimer = null;
    if (state.jobView === jv) state.jobView = null;
    if (state.vpnMon === jv) state.vpnMon = null;
  }

  function jobStat(label, value) {
    return h('div', { class: 'job-stat' },
      h('span', { class: 'job-stat-k' }, label),
      h('span', { class: 'job-stat-v' }, value == null || value === '' ? '—' : value));
  }

  function openJobView(id) {
    closeJobView();
    const statusEl = h('div', { class: 'job-status' }, loadingState());
    const metaEl = h('div', { class: 'job-stats' });
    const stepsEl = h('ol', { class: 'steps' });
    const nowEl = h('p', { class: 'log-now', hidden: true }, 'در انتظار گزارش…');
    const feedEl = h('div', { class: 'log-feed', dir: 'rtl', tabindex: '0', 'aria-label': 'گزارش کار' });
    const rawEl = h('pre', { class: 'log log-raw', dir: 'ltr', hidden: true, 'aria-label': 'لاگ فنی' });
    const followBtn = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', hidden: true }, 'رفتن به انتهای گزارش');
    const rawBtn = h('button', { type: 'button', class: 'btn btn-sm btn-ghost' }, 'جزئیات فنی');
    const body = h('div', { class: 'job-view' },
      h('section', { class: 'job-sec' },
        h('h3', { class: 'job-sec-title' }, 'خلاصه'),
        h('div', { class: 'job-head' }, statusEl, metaEl)),
      h('section', { class: 'job-sec' },
        h('h3', { class: 'job-sec-title' }, 'مراحل'),
        stepsEl),
      h('section', { class: 'job-sec job-sec-log' },
        h('div', { class: 'log-head' },
          h('h3', { class: 'job-sec-title' }, 'گزارش'),
          h('div', { class: 'log-actions' }, rawBtn, followBtn)),
        nowEl,
        feedEl,
        rawEl));
    const closeBtn = h('button', { type: 'button', class: 'btn', onclick: () => jv.m.close() }, 'بستن');

    const jv = {
      id, closed: false, done: false, es: null, pollTimer: null, stick: true, showRaw: false,
      rawLog: '', lastHuman: '', job: null, statusEl, metaEl, stepsEl, nowEl, feedEl, rawEl,
      logEl: feedEl, followBtn, rawBtn,
    };
    jv.m = openModal({ title: 'گزارش عملیات', body, footer: closeBtn, wide: true, onClose: () => stopJobView(jv) });
    state.jobView = jv;
    rawBtn.addEventListener('click', () => toggleRawLog(jv));
    bindLogScroll(feedEl, jv);
    bindLogScroll(rawEl, jv);
    followBtn.addEventListener('click', () => {
      jv.stick = true;
      followBtn.hidden = true;
      scrollLog(jv);
    });

    (async () => {
      try {
        const job = await api('GET', `/api/jobs/${enc(id)}`);
        if (jv.closed) return;
        renderJob(jv, job);
        if (isActive(job.status)) {
          trackJob(id);
          startStream(jv);
        } else {
          jv.done = true;
        }
      } catch (err) {
        if (jv.closed || err.status === 401) return;
        statusEl.replaceChildren(errorState(err.message));
      }
    })();
  }

  function scrollLog(jv) {
    const el = jv.showRaw && jv.rawEl ? jv.rawEl : (jv.feedEl || jv.logEl);
    if (el) el.scrollTop = el.scrollHeight;
  }

  function renderJob(jv, job) {
    if (!job || typeof job !== 'object') return;
    jv.job = Object.assign({}, job, { steps: Array.isArray(job.steps) ? job.steps.slice() : [] });
    jv.m.titleEl.textContent = job.title || job.kind || 'گزارش عملیات';
    setJobStatus(jv, job.status);
    jv.metaEl.replaceChildren(
      jobStat('نوع', JOB_KIND_LABEL[job.kind] || job.kind || '—'),
      jobStat('شروع', fmtTime(job.created_at)),
      jobStat('پایان', job.finished_at ? fmtTime(job.finished_at) : '—'),
      jobStat('مدت', job.finished_at ? fmtDuration(job.created_at, job.finished_at) : '—'));
    renderSteps(jv);
    setLogText(jv, job.log || '');
    if (jv.stick) scrollLog(jv);
  }

  function setJobStatus(jv, status) {
    if (jv.job) jv.job.status = status;
    const text = {
      queued: 'این کار در صف اجرا است…',
      running: 'در حال اجرا… (بروزرسانی زنده)',
      ok: 'کار با موفقیت انجام شد.',
      failed: 'کار ناموفق بود. لاگ و مراحل را بررسی کنید.',
    }[status] || '';
    jv.statusEl.replaceChildren(jobBadge(status), h('span', { class: 'job-status-text' }, text));
    jv.statusEl.className = `job-status job-status-${status || 'unknown'}`;
    updateVpnProgress(jv);
  }

  function renderSteps(jv) {
    const steps = (jv.job && jv.job.steps) || [];
    if (!steps.length) {
      jv.stepsEl.replaceChildren(h('li', { class: 'step step-empty' }, 'هنوز مرحله‌ای ثبت نشده است.'));
      return;
    }
    jv.stepsEl.replaceChildren(...steps.map((s, i) => {
      const st = s && STEP_STATUS[s.status] ? s.status : 'pending';
      const [, label] = STEP_STATUS[st];
      return h('li', { class: `step step-${st}` },
        h('span', { class: 'step-num', 'aria-hidden': 'true' }, String(i + 1)),
        h('div', { class: 'step-body' },
          h('div', { class: 'step-name' }, (s && s.name) || '—'),
          s && s.detail ? h('div', { class: 'step-detail' }, infoText(s.detail)) : null),
        h('span', { class: 'step-status' }, label));
    }));
    updateVpnProgress(jv);
  }

  function updateVpnProgress(jv) {
    if (!jv || !jv.barEl) return;
    const steps = (jv.job && jv.job.steps) || [];
    const total = steps.length || 1;
    const done = steps.filter((s) => s && (s.status === 'ok' || s.status === 'skipped')).length;
    let pct = Math.round((done / total) * 100);
    if (jv.job && jv.job.status === 'running' && pct < 92) pct = Math.max(pct, 8);
    if (jv.job && jv.job.status === 'ok') pct = 100;
    jv.barEl.style.width = `${pct}%`;
    if (jv.pctEl) jv.pctEl.textContent = `${pct}٪`;
    const box = $('#vpn-monitor');
    if (!box) return;
    const st = (jv.job && jv.job.status) || '';
    box.classList.toggle('is-running', st === 'running' || st === 'queued');
    box.classList.toggle('is-ok', st === 'ok');
    box.classList.toggle('is-failed', st === 'failed');
  }

  function parseData(e) {
    try {
      return JSON.parse(e.data);
    } catch (err) {
      return null;
    }
  }

  function startStream(jv) {
    if (typeof EventSource === 'undefined') {
      startJobPoll(jv);
      return;
    }
    let es;
    try {
      es = new EventSource(withBase(`/api/jobs/${enc(jv.id)}/stream`));
    } catch (err) {
      startJobPoll(jv);
      return;
    }
    jv.es = es;

    es.addEventListener('snapshot', (e) => {
      const job = parseData(e);
      if (!job || jv.closed) return;
      renderJob(jv, job);
      if (job.status === 'ok' || job.status === 'failed') finishJob(jv, job.status, false);
    });
    es.addEventListener('log', (e) => {
      const d = parseData(e);
      if (!d || d.line == null || jv.closed) return;
      appendLiveLog(jv, d.line);
      if (jv.stick) scrollLog(jv);
    });
    es.addEventListener('step', (e) => {
      const d = parseData(e);
      if (!d || jv.closed || !jv.job) return;
      const steps = jv.job.steps;
      let idx = Number.isInteger(d.index) ? d.index : steps.findIndex((s) => s && s.name === d.name);
      if (idx < 0) idx = steps.length;
      while (steps.length < idx) steps.push({ name: '—', status: 'pending' });
      const cur = steps[idx] || {};
      steps[idx] = {
        name: d.name != null ? d.name : cur.name,
        status: d.status != null ? d.status : cur.status,
        detail: d.detail !== undefined ? d.detail : cur.detail,
      };
      renderSteps(jv);
    });
    es.addEventListener('done', (e) => {
      const d = parseData(e) || {};
      finishJob(jv, d.status, true);
    });
    es.onerror = () => {
      if (jv.es) jv.es.close();
      jv.es = null;
      if (!jv.done && !jv.closed) startJobPoll(jv);
    };
  }

  function startJobPoll(jv) {
    if (jv.pollTimer || jv.closed || jv.done) return;
    const tick = async () => {
      jv.pollTimer = null;
      if (jv.closed || jv.done) return;
      try {
        const job = await api('GET', `/api/jobs/${enc(jv.id)}`);
        if (jv.closed) return;
        renderJob(jv, job);
        if (!isActive(job.status)) {
          finishJob(jv, job.status, false);
          return;
        }
      } catch (err) {
        if (err.status === 401) return;
      }
      if (!jv.closed && !jv.done) jv.pollTimer = setTimeout(tick, JOB_POLL_MS);
    };
    jv.pollTimer = setTimeout(tick, 0);
  }

  async function finishJob(jv, status, refetch) {
    if (jv.done) return;
    jv.done = true;
    if (jv.es) jv.es.close();
    jv.es = null;
    if (jv.pollTimer) clearTimeout(jv.pollTimer);
    jv.pollTimer = null;
    let finalStatus = status;
    let title = jv.job && jv.job.title;
    if (refetch && !jv.closed) {
      try {
        const job = await api('GET', `/api/jobs/${enc(jv.id)}`);
        if (!jv.closed) renderJob(jv, job);
        finalStatus = job.status || finalStatus;
        title = job.title || title;
      } catch (err) {
        if (finalStatus && !jv.closed) setJobStatus(jv, finalStatus);
      }
    } else if (finalStatus && !jv.closed) {
      setJobStatus(jv, finalStatus);
    }
    if (finalStatus === 'ok' || finalStatus === 'failed') notifyDone(jv.id, finalStatus, title);
  }

  /* ---------- account ---------- */

  function setVersions(panelV) {
    const el = $('#hdr-versions');
    if (!el) return;
    el.textContent = panelV ? `نسخه ${panelV}` : '';
  }

  function openPasswordForm() {
    const formId = uid('pw');
    const errBox = h('div', { class: 'form-error', role: 'alert', hidden: true });
    const fOld = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'current-password', required: true });
    const fNew = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'new-password', minlength: '10', required: true });
    const fRep = h('input', { id: uid('f'), type: 'password', dir: 'ltr', autocomplete: 'new-password', required: true });
    const form = h('form', { id: formId, class: 'form', novalidate: true },
      errBox,
      h('input', { type: 'text', autocomplete: 'username', value: (state.me && state.me.username) || '', hidden: true, 'aria-hidden': 'true', tabindex: '-1' }),
      field('رمز عبور فعلی', fOld),
      field('رمز عبور جدید', fNew, 'حداقل 10 کاراکتر.'),
      field('تکرار رمز عبور جدید', fRep));
    const saveBtn = h('button', { type: 'submit', form: formId, class: 'btn btn-primary' }, 'تغییر رمز');
    const m = openModal({
      title: 'تغییر رمز عبور',
      body: form,
      footer: [h('button', { type: 'button', class: 'btn', onclick: () => m.close() }, 'انصراف'), saveBtn],
      sticky: true,
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      hideErr(errBox);
      if (!fOld.value) return showErr(errBox, 'رمز عبور فعلی را وارد کنید.');
      if (fNew.value.length < 10) return showErr(errBox, 'رمز عبور جدید باید حداقل 10 کاراکتر باشد.');
      if (fNew.value !== fRep.value) return showErr(errBox, 'تکرار رمز عبور جدید مطابقت ندارد.');
      if (fNew.value === fOld.value) return showErr(errBox, 'رمز عبور جدید باید با رمز فعلی متفاوت باشد.');
      saveBtn.disabled = true;
      try {
        await api('POST', '/api/password', { old_password: fOld.value, new_password: fNew.value });
        toast('رمز عبور با موفقیت تغییر کرد.', 'success');
        m.close();
      } catch (err) {
        if (err.status !== 401) showErr(errBox, err.message);
      } finally {
        saveBtn.disabled = false;
      }
      return undefined;
    });
  }

  async function logout() {
    const btn = $('#btn-logout');
    btn.disabled = true;
    try {
      await api('POST', '/api/logout');
    } catch (err) {
      /* ignore: session is dropped client-side anyway */
    } finally {
      btn.disabled = false;
    }
    if (hxTerms.left) hxTerms.left.disconnect();
    if (hxTerms.right) hxTerms.right.disconnect();
    showLogin();
    toast('از پنل خارج شدید.', 'info');
  }

  /* ---------- screens ---------- */

  function showLogin(msg) {
    state.loggedIn = false;
    state.csrf = '';
    state.me = null;
    state.info = null;
    stopPolling();
    closeAllModals();
    state.sessionJobs.clear();
    state.notified.clear();
    resetLists();
    $('#boot').hidden = true;
    $('#app-view').hidden = true;
    $('#login-view').hidden = false;
    $('#login-pass').value = '';
    const errBox = $('#login-error');
    if (msg) showErr(errBox, msg);
    else hideErr(errBox);
    $('#login-user').focus();
  }

  async function enterApp() {
    const me = await api('GET', '/api/me');
    state.me = me || {};
    if (state.me.csrf) state.csrf = state.me.csrf;
    state.loggedIn = true;
    $('#boot').hidden = true;
    $('#login-view').hidden = true;
    $('#app-view').hidden = false;
    applyRoleUI();
    setVersions(state.me.panel_version, state.me.jojonet_version);
    resetLists();
    updateTunnelForm();
    const hashTab = (location.hash || '').slice(1);
    const startTab = TABS.includes(hashTab) && !$(`#tabbtn-${hashTab}`).hidden ? hashTab : 'servers';
    switchTab(startTab);
    loadInfo();
    load('servers');
    load('tunnels');
    loadLiveTunnels();
    if (can('allow_relay')) load('relays');
    load('jobs');
    if (isOwner()) load('users');
    startPolling();
  }

  async function refreshMe() {
    try {
      const me = await api('GET', '/api/me');
      state.me = me || state.me;
      if (state.me && state.me.csrf) state.csrf = state.me.csrf;
      paintHeader();
    } catch (err) {
      /* keep last known profile */
    }
  }

  async function onLogin(e) {
    e.preventDefault();
    const errBox = $('#login-error');
    const btn = $('#login-btn');
    const user = $('#login-user');
    const pass = $('#login-pass');
    hideErr(errBox);
    if (!user.value.trim()) {
      showErr(errBox, 'نام کاربری را وارد کنید.');
      user.focus();
      return;
    }
    if (!pass.value) {
      showErr(errBox, 'رمز عبور را وارد کنید.');
      pass.focus();
      return;
    }
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    btn.textContent = 'در حال ورود…';
    try {
      const r = await api('POST', '/api/login', { username: user.value.trim(), password: pass.value });
      if (r && r.csrf) state.csrf = r.csrf;
      await enterApp();
    } catch (err) {
      showErr(errBox, err.status === 401 && !err.message ? 'نام کاربری یا رمز عبور اشتباه است.' : err.message);
      pass.select();
    } finally {
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      btn.textContent = 'ورود';
    }
  }

  function switchTab(name, focus) {
    state.tab = name;
    for (const b of document.querySelectorAll('.tab')) {
      const on = b.dataset.tab === name;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
      b.classList.toggle('is-active', on);
    }
    for (const t of TABS) $(`#tab-${t}`).hidden = t !== name;
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
    if (focus) $(`#tabbtn-${name}`).focus();
    if (state.loggedIn && name === 'jobs') load('jobs', true);
    if (state.loggedIn && name === 'relays') load('relays', true);
    if (state.loggedIn && name === 'panels') load('servers', true);
    if (state.loggedIn && name === 'tunnels') {
      load('tunnels', true);
      if (!liveState.data && !liveState.loading) loadLiveTunnels();
    }
    if (state.loggedIn && name === 'outbounds') load('tunnels', true);
    if (state.loggedIn && name === 'users' && isOwner()) load('users', true);
  }

  function readTheme() {
    try {
      const t = localStorage.getItem(THEME_KEY);
      if (THEMES.includes(t)) return t;
    } catch (_) {}
    return THEME_DEFAULT;
  }

  function applyTheme(theme) {
    const t = THEMES.includes(theme) ? theme : THEME_DEFAULT;
    document.documentElement.setAttribute('data-theme', t);
    document.documentElement.style.colorScheme = t === 'day' ? 'light' : 'dark';
    try { localStorage.setItem(THEME_KEY, t); } catch (_) {}
    for (const btn of document.querySelectorAll('[data-theme-set]')) {
      const on = btn.getAttribute('data-theme-set') === t;
      btn.setAttribute('aria-checked', on ? 'true' : 'false');
      btn.classList.toggle('is-on', on);
    }
  }

  function fillTermSelects() {
    const servers = lists.servers.data || [];
    for (const id of ['hx-left-server', 'hx-right-server']) {
      const sel = $(`#${id}`);
      if (!sel) continue;
      const cur = sel.value;
      const opts = [h('option', { value: '' }, '— انتخاب سرور —')];
      for (const s of servers) {
        const role = s.role === 'iran' ? 'ایران' : 'خارج';
        opts.push(h('option', { value: String(s.id) }, `${s.name} · ${role} · ${s.host}`));
      }
      sel.replaceChildren(...opts);
      if (cur && [...sel.options].some((o) => o.value === cur)) sel.value = cur;
    }
  }

  function hxFitClass() {
    const mod = window.FitAddon;
    if (!mod) return null;
    return mod.FitAddon || mod;
  }

  function createHxTerm(side) {
    const dock = $(`#hx-${side}`);
    const screen = $(`#hx-${side}-screen`);
    const boot = $(`#hx-${side}-boot`);
    const stateEl = $(`#hx-${side}-state`);
    const go = $(`#hx-${side}-go`);
    const kill = $(`#hx-${side}-kill`);
    const sel = $(`#hx-${side}-server`);
    if (!dock || !screen || typeof Terminal !== 'function') return null;
    const FitCls = hxFitClass();
    const term = new Terminal({
      convertEol: true,
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace',
      fontSize: 13,
      lineHeight: 1.25,
      theme: {
        background: '#020705',
        foreground: '#3dff9a',
        cursor: '#6ef0ff',
        cursorAccent: '#020705',
        selectionBackground: '#145c38',
        black: '#020705',
        red: '#ff5a6a',
        green: '#3dff9a',
        yellow: '#f5c15a',
        blue: '#4f8cff',
        magenta: '#c084fc',
        cyan: '#6ef0ff',
        white: '#d8ffe8',
        brightGreen: '#7dffb4',
        brightCyan: '#b4fff7',
      },
      scrollback: 4000,
    });
    const fit = FitCls ? new FitCls() : null;
    if (fit) term.loadAddon(fit);
    term.open(screen);
    const api = {
      term,
      ws: null,
      setState(name, live) {
        if (stateEl) stateEl.textContent = name;
        dock.classList.toggle('is-live', !!live);
        if (go) go.hidden = !!live;
        if (kill) kill.hidden = !live;
      },
      fit() {
        try { if (fit) fit.fit(); } catch (_) {}
      },
      async bootSeq() {
        if (!boot) return;
        boot.hidden = false;
        boot.textContent = '';
        const lines = [
          'JOJONET UPLINK 1.3.9',
          '>> initiating encrypted handshake...',
          '>> host key pinned / channel open',
          '>> allocating pty  xterm-256color',
          '>> shell online.',
        ];
        for (const line of lines) {
          boot.textContent += `${line}\n`;
          await new Promise((r) => setTimeout(r, 80));
        }
      },
      disconnect() {
        if (this.ws) {
          try { this.ws.send(JSON.stringify({ t: 'x' })); } catch (_) {}
          try { this.ws.close(); } catch (_) {}
        }
        this.ws = null;
        this.setState('قطع', false);
      },
      async connect() {
        if (!canTerm()) {
          toast('ترمینال برای این حساب غیرفعال است.', 'error');
          return;
        }
        const id = sel && sel.value;
        if (!id) {
          toast('اول سرور را برای ترمینال انتخاب کنید.', 'error');
          return;
        }
        this.disconnect();
        await this.bootSeq();
        this.fit();
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const url = `${proto}://${location.host}${withBase(`/ws/term?server_id=${enc(id)}&cols=${term.cols}&rows=${term.rows}`)}`;
        const ws = new WebSocket(url);
        this.ws = ws;
        this.setState('در حال اتصال', false);
        ws.addEventListener('open', () => this.setState('متصل', true));
        ws.addEventListener('message', (ev) => {
          let msg;
          try { msg = JSON.parse(ev.data); } catch (_) { return; }
          if (msg.t === 'o' && msg.d) term.write(msg.d);
          else if (msg.t === 'e' && msg.m) {
            term.writeln(`\r\n\x1b[31m${msg.m}\x1b[0m`);
            toast(msg.m, 'error');
          } else if (msg.t === 's' && msg.s === 'closed') this.disconnect();
        });
        ws.addEventListener('error', () => toast('اتصال ترمینال قطع شد.', 'error'));
        ws.addEventListener('close', () => {
          if (this.ws === ws) this.setState('قطع', false);
        });
      },
    };
    term.onData((data) => {
      if (api.ws && api.ws.readyState === 1) api.ws.send(JSON.stringify({ t: 'i', d: data }));
    });
    if (window.ResizeObserver) {
      new ResizeObserver(() => {
        api.fit();
        if (api.ws && api.ws.readyState === 1) {
          api.ws.send(JSON.stringify({ t: 'r', c: term.cols, r: term.rows }));
        }
      }).observe(screen);
    }
    if (go) go.addEventListener('click', () => api.connect());
    if (kill) kill.addEventListener('click', () => api.disconnect());
    setTimeout(() => api.fit(), 80);
    return api;
  }

  function syncHxOffset() {
    const topbar = document.querySelector('.topbar');
    const y = topbar ? Math.round(topbar.getBoundingClientRect().bottom) : 60;
    document.documentElement.style.setProperty('--hx-top', `${Math.max(y, 48)}px`);
  }

  function setHxOpen(side, open) {
    const dock = $(`#hx-${side}`);
    if (!dock) return;
    dock.classList.toggle('is-open', open);
    const fab = $(`#hx-toggle-${side}`);
    if (fab) fab.setAttribute('aria-pressed', open ? 'true' : 'false');
    syncHxOffset();
    const api = hxTerms[side];
    if (open && api) setTimeout(() => api.fit(), 280);
  }

  function bindHxTerms() {
    hxTerms.left = createHxTerm('left');
    hxTerms.right = createHxTerm('right');
    for (const side of ['left', 'right']) {
      const toggle = $(`#hx-toggle-${side}`);
      const close = $(`#hx-${side}-close`);
      if (toggle) {
        toggle.addEventListener('click', () => {
          const dock = $(`#hx-${side}`);
          setHxOpen(side, !(dock && dock.classList.contains('is-open')));
        });
      }
      if (close) close.addEventListener('click', () => setHxOpen(side, false));
    }
    window.addEventListener('resize', syncHxOffset);
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' || modalStack.length) return;
      setHxOpen('left', false);
      setHxOpen('right', false);
    });
    syncHxOffset();
  }

  function bindTheme() {
    applyTheme(readTheme());
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-theme-set]');
      if (!btn) return;
      applyTheme(btn.getAttribute('data-theme-set'));
    });
  }

  function listenAddress(path, port) {
    const clean = String(path || '').trim().replace(/^\/+|\/+$/g, '');
    const segment = clean ? '/' + clean : '';
    const number = Number(port) || 2053;
    const https = location.protocol === 'https:';
    const bare = (https && number === 443) || (!https && number === 80);
    const host = bare ? location.hostname : location.hostname + ':' + number;
    return location.protocol + '//' + host + segment + '/';
  }

  async function loadListen() {
    const pathEl = $('#listen-path');
    const portEl = $('#listen-port');
    if (!pathEl || !portEl || !isOwner()) return;
    try {
      const row = await api('GET', '/api/listen');
      pathEl.value = String(row.path || '').replace(/^\//, '');
      portEl.value = row.port || 2053;
      const url = $('#listen-url');
      if (url) url.textContent = row.url || listenAddress(pathEl.value, portEl.value);
    } catch (err) {
      if (err.status && err.status !== 401) {
        const box = $('#listen-error');
        if (box) { box.hidden = false; box.textContent = err.message || NET_ERR; }
      }
    }
  }

  function bindListen() {
    const form = $('#listen-form');
    const pathEl = $('#listen-path');
    const portEl = $('#listen-port');
    if (!form || !pathEl || !portEl) return;
    const preview = () => {
      const url = $('#listen-url');
      if (url && pathEl && portEl) url.textContent = listenAddress(pathEl.value, portEl.value);
    };
    pathEl.addEventListener('input', preview);
    portEl.addEventListener('input', preview);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!isOwner()) return;
      const box = $('#listen-error');
      if (box) box.hidden = true;
      const nextUrl = listenAddress(pathEl.value, portEl.value);
      const btn = $('#listen-submit');
      if (btn) btn.disabled = true;
      try {
        const row = await api('PUT', '/api/listen', { path: pathEl.value.trim(), port: Number(portEl.value) });
        const same = state.me && row.path === state.me.base_path && Number(row.port) === Number(state.me.panel_port);
        if (state.me) {
          state.me.base_path = row.path;
          state.me.panel_port = row.port;
        }
        paintHeader();
        if (same) {
          toast('همین آدرس الان فعال است.', 'success');
          if (btn) btn.disabled = false;
          return;
        }
        toast('آدرس ذخیره شد. چند ثانیه دیگر پنل روی آدرس جدید بالا می‌آید.', 'success');
        setTimeout(() => { location.href = row.url || nextUrl; }, 4000);
      } catch (err) {
        if (!err.status) {
          toast('پنل در حال بالا آمدن روی آدرس جدید است…', 'success');
          setTimeout(() => { location.href = nextUrl; }, 4000);
          return;
        }
        if (box) { box.hidden = false; box.textContent = err.message || NET_ERR; }
        else toast(err.message || NET_ERR, 'error');
        if (btn) btn.disabled = false;
      }
    });
  }

  function bindStatic() {
    bindTheme();
    bindHxTerms();
    bindListen();
    const termPolicy = $('#set-terms-enabled');
    if (termPolicy) {
      termPolicy.addEventListener('change', async () => {
        if (!isOwner()) return;
        try {
          const r = await api('PATCH', '/api/settings', { terms_enabled: termPolicy.checked });
          if (state.me) state.me.terms_enabled = !!r.terms_enabled;
          applyTermUI();
          toast(r.terms_enabled ? 'ترمینال برای کاربران مجاز روشن شد.' : 'ترمینال صفحه اصلی برای همه پنهان شد.', 'success');
        } catch (err) {
          termPolicy.checked = meTermsEnabled();
          if (err.status !== 401) toast(err.message || NET_ERR, 'error');
        }
      });
    }
    $('#login-form').addEventListener('submit', onLogin);
    $('#btn-logout').addEventListener('click', logout);
    $('#btn-password').addEventListener('click', openPasswordForm);
    $('#btn-add-server').addEventListener('click', () => openServerForm(null));
    $('#btn-refresh-servers').addEventListener('click', (e) => act(e.currentTarget, () => load('servers'), 'در حال بروزرسانی…'));
    $('#btn-refresh-tunnels').addEventListener('click', (e) => act(e.currentTarget, () => Promise.all([load('tunnels'), load('servers'), loadLiveTunnels(true)]), 'در حال بروزرسانی…'));
    const scanLive = $('#btn-scan-live');
    if (scanLive) scanLive.addEventListener('click', (e) => act(e.currentTarget, () => loadLiveTunnels(true), 'در حال اسکن…'));
    const bootAll = $('#btn-enable-boot-all');
    if (bootAll) {
      bootAll.addEventListener('click', async () => {
        const ok = await confirmDialog({
          title: 'ماندن بعد از ریبوت (همه سرورها)',
          message: 'برای همه سرورهای این حساب، ماندگاری تانل‌ها بعد از ریبوت فعال شود؟',
          okText: 'فعال‌سازی همه',
        });
        if (!ok) return;
        act(bootAll, async () => {
          const r = await api('POST', '/api/servers/enable-boot-all');
          const ids = r.job_ids || [];
          if (!ids.length) {
            toast('سروری برای فعال‌سازی پیدا نشد.', 'warn');
            return;
          }
          ids.forEach((id) => { if (id != null) state.sessionJobs.add(String(id)); });
          toast(`${ids.length} کار ماندگاری ریبوت شروع شد.`, 'info');
          load('jobs', true);
          if (ids[0] != null) openJobView(ids[0]);
        });
      });
    }
    $('#btn-refresh-relays').addEventListener('click', (e) => act(e.currentTarget, () => Promise.all([load('relays'), load('servers')]), 'در حال بروزرسانی…'));
    $('#btn-refresh-jobs').addEventListener('click', (e) => act(e.currentTarget, () => load('jobs'), 'در حال بروزرسانی…'));
    const refreshOut = $('#btn-refresh-outbounds');
    if (refreshOut) refreshOut.addEventListener('click', (e) => act(e.currentTarget, () => load('tunnels'), 'در حال بروزرسانی…'));
    const refreshUsers = $('#btn-refresh-users');
    if (refreshUsers) refreshUsers.addEventListener('click', (e) => act(e.currentTarget, () => load('users'), 'در حال بروزرسانی…'));
    const userForm = $('#user-form');
    if (userForm) userForm.addEventListener('submit', onCreateUser);
    $('#tunnel-form').addEventListener('submit', onCreateTunnel);
    $('#relay-form').addEventListener('submit', onCreateRelay);
    for (const btn of document.querySelectorAll('.vpn-panel-card')) {
      btn.addEventListener('click', onInstallVpnPanel);
    }
    const monLog = $('#vpn-mon-log');
    const monRaw = $('#vpn-mon-rawlog');
    const monFollow = $('#vpn-mon-follow');
    const monRawBtn = $('#vpn-mon-raw');
    if (monLog) {
      monLog.addEventListener('scroll', () => {
        const jv = state.vpnMon;
        if (!jv || jv.showRaw) return;
        jv.stick = monLog.scrollTop + monLog.clientHeight >= monLog.scrollHeight - 24;
        if (monFollow) monFollow.hidden = jv.stick;
      });
    }
    if (monRaw) {
      monRaw.addEventListener('scroll', () => {
        const jv = state.vpnMon;
        if (!jv || !jv.showRaw) return;
        jv.stick = monRaw.scrollTop + monRaw.clientHeight >= monRaw.scrollHeight - 24;
        if (monFollow) monFollow.hidden = jv.stick;
      });
    }
    if (monFollow) {
      monFollow.addEventListener('click', () => {
        const jv = state.vpnMon;
        if (!jv) return;
        jv.stick = true;
        monFollow.hidden = true;
        scrollLog(jv);
      });
    }
    if (monRawBtn) {
      monRawBtn.addEventListener('click', () => {
        if (state.vpnMon) toggleRawLog(state.vpnMon);
      });
    }
    $('#rf-engine').addEventListener('change', updateRelayEngine);
    $('#tf-sp-check').addEventListener('click', onSpoofCheck);
    $('#tf-mode').addEventListener('change', updateTunnelForm);
    $('#tf-direct').addEventListener('change', updateTunnelForm);

    const tabs = () => Array.from(document.querySelectorAll('.tab')).filter((b) => !b.hidden);
    for (const b of document.querySelectorAll('.tab')) {
      b.addEventListener('click', () => switchTab(b.dataset.tab));
      b.addEventListener('keydown', (e) => {
        const vis = tabs();
        const i = vis.indexOf(b);
        if (i < 0) return;
        let n = -1;
        if (e.key === 'ArrowLeft') n = (i + 1) % vis.length;
        else if (e.key === 'ArrowRight') n = (i - 1 + vis.length) % vis.length;
        else if (e.key === 'Home') n = 0;
        else if (e.key === 'End') n = vis.length - 1;
        if (n >= 0) {
          e.preventDefault();
          switchTab(vis[n].dataset.tab, true);
        }
      });
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && state.loggedIn) load('jobs', true);
    });
    paintOpsClock();
    setInterval(paintOpsClock, 1000);
  }

  async function init() {
    bindStatic();
    try {
      await enterApp();
    } catch (err) {
      showLogin(err.status === 401 ? '' : err.message);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
