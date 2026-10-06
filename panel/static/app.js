'use strict';

(function () {
  const NET_ERR = 'ارتباط با سرور برقرار نشد. اتصال شبکه را بررسی کنید.';
  const SESSION_EXPIRED = 'نشست شما منقضی شده است. لطفاً دوباره وارد شوید.';
  const POLL_MS = 5000;
  const JOB_POLL_MS = 2000;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  const TABS = ['servers', 'tunnels', 'relays', 'jobs'];

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
    pending: ['○', 'در انتظار'],
    running: ['◌', 'در حال اجرا'],
    ok: ['✓', 'انجام شد'],
    failed: ['✕', 'ناموفق'],
    skipped: ['–', 'رد شد'],
  };

  const state = {
    csrf: '',
    me: null,
    info: null,
    loggedIn: false,
    tab: 'servers',
    pollTimer: null,
    jobView: null,
    sessionJobs: new Set(),
    notified: new Set(),
  };

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
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    nf = new Intl.NumberFormat('fa-IR');
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
    return dtf ? dtf.format(d) : d.toLocaleString();
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
      res = await fetch(path, opts);
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
      class: `modal${opts.wide ? ' modal-wide' : ''}`,
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
  }

  /* ---------- list loaders ---------- */

  const lists = {
    servers: { path: '/api/servers', el: '#servers-list', render: renderServers, after: () => { updateTunnelForm(); updateRelayForm(); } },
    tunnels: { path: '/api/tunnels', el: '#tunnels-list', render: renderTunnels },
    relays: { path: '/api/relays', el: '#relays-list', render: renderRelays, after: updateRelayForm },
    jobs: { path: '/api/jobs?limit=50', el: '#jobs-list', render: renderJobs, after: checkSessionJobs },
  };

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
    box.replaceChildren(...groups);
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

    const updBtn = h('button', { type: 'button', class: 'btn btn-sm' }, 'آپدیت سیستم');
    updBtn.addEventListener('click', async () => {
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
          h('h4', { class: 'card-title' }, s.name),
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
        field('نام سرور', fName, 'بین ۱ تا ۴۰ کاراکتر.'),
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
      if (name.length < 1 || name.length > 40) return fail(fName, 'نام سرور باید بین ۱ تا ۴۰ کاراکتر باشد.');
      if (!IPV4_RE.test(fHost.value.trim())) return fail(fHost, 'آدرس IPv4 معتبر نیست (مثال: 203.0.113.10).');
      const port = Number(fPort.value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) return fail(fPort, 'پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد.');
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

  function updateModeDesc() {
    const desc = $('#tf-mode-desc');
    const m = modeInfo($('#tf-mode').value);
    $('#tf-spoof').hidden = $('#tf-mode').value !== 'spoof';
    $('#tf-xray').hidden = $('#tf-mode').value !== 'dokodemo' && $('#tf-mode').value !== 'xray_reverse';
    if (!m) {
      desc.textContent = 'یک نوع تانل انتخاب کنید تا توضیحات آن نمایش داده شود.';
      return;
    }
    const side = m.first === 'iran' ? 'ایران' : 'خارج';
    desc.replaceChildren(
      h('span', null, m.desc || ''),
      h('span', { class: 'hint-strong' }, ` ترتیب استقرار: ابتدا سمت ${side}.`));
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
    $('#tf-submit').disabled = !modes || !iran.length || !kharej.length;
    updateModeDesc();
  }

  /* Returns the spoof options object, or a Persian error message. */
  function readSpoofForm() {
    const val = (id) => $(id).value.trim();
    const port = (id, label) => {
      const v = val(id);
      const n = Number(v);
      return /^\d{1,5}$/.test(v) && n >= 1 && n <= 65535 ? n : `${label} باید عددی بین ۱ تا ۶۵۵۳۵ باشد.`;
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
      if (!/^\d{1,5}$/.test(ctrlRaw) || n < 1 || n > 65535) return 'پورت کنترل باید بین ۱ تا ۶۵۵۳۵ باشد.';
      ctrl_port = n;
    }
    const ports = $('#tf-xr-ports').value.replace(/\s+/g, '');
    if (!ports) return 'حداقل یک پورت فوروارد لازم است.';
    if (!PORTS_SPEC_RE.test(ports)) {
      return 'پورت‌ها باید به شکل 443 یا 8443:443 باشند.';
    }
    return { net, ctrl_port, ports };
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
    const iran = findSrv($('#tf-iran').value);
    const kharej = findSrv($('#tf-kharej').value);
    if (!mode) return showErr(errBox, 'نوع تانل را انتخاب کنید.');
    if (!iran) return showErr(errBox, 'سرور ایران را انتخاب کنید.');
    if (!kharej) return showErr(errBox, 'سرور خارج را انتخاب کنید.');
    const payload = { mode, iran_id: iran.id, kharej_id: kharej.id };
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

    const verifyBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'بررسی');
    verifyBtn.addEventListener('click', () => act(verifyBtn, async () => {
      startedJob(await api('POST', `/api/tunnels/${enc(t.id)}/verify`));
      load('tunnels', true);
    }));

    const redeployBtn = h('button', { type: 'button', class: 'btn btn-sm', disabled: transient }, 'استقرار مجدد');
    redeployBtn.addEventListener('click', async () => {
      const ok = await confirmDialog({
        title: 'استقرار مجدد تانل',
        message: `تانل ${mi ? mi.label : t.mode} بین «${t.iran_name}» و «${t.kharej_name}» دوباره روی هر دو سرور مستقر شود؟ ممکن است اتصال برای مدت کوتاهی قطع شود.`,
        okText: 'استقرار مجدد',
      });
      if (!ok) return;
      act(redeployBtn, async () => {
        startedJob(await api('POST', `/api/tunnels/${enc(t.id)}/redeploy`), 'استقرار مجدد آغاز شد.');
        load('tunnels', true);
      });
    });

    const logBtn = t.last_job_id != null
      ? h('button', { type: 'button', class: 'btn btn-sm btn-ghost', onclick: () => openJobView(t.last_job_id) }, 'آخرین کار')
      : null;

    const delBtn = h('button', { type: 'button', class: 'btn btn-sm btn-danger-ghost' }, 'حذف');
    delBtn.addEventListener('click', async () => {
      const res = await confirmDialog({
        title: 'حذف تانل',
        message: `تانل بین «${t.iran_name}» و «${t.kharej_name}» از روی هر دو سرور و از پنل حذف شود؟`,
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

    return h('article', { class: 'card tunnel-card' },
      h('div', { class: 'card-head' },
        h('div', null,
          h('h4', { class: 'card-title' }, mi ? mi.label : t.mode),
          h('span', { class: 'mode-chip', dir: 'ltr' }, t.mode)),
        badge(kind, label, transient)),
      h('div', { class: 'route' },
        h('span', { class: 'route-end role-iran' }, h('small', null, 'ایران'), t.iran_name || '—'),
        h('span', { class: 'route-link', 'aria-hidden': 'true' }),
        h('span', { class: 'route-end role-kharej' }, h('small', null, 'خارج'), t.kharej_name || '—')),
      h('dl', { class: 'kv' },
        ...(xr ? [
          kv('انتقال Xray', ltr(xr.net || 'tcp')),
          kv('پورت کنترل', xr.ctrl_port ? ltr(xr.ctrl_port) : 'خودکار'),
          kv('پورت‌های Xray', ltr(xr.ports || '')),
        ] : sp ? [
          kv('IP جعلی ایران / خارج', ltr(`${sp.iran_spoof_ip || '—'} / ${sp.kharej_spoof_ip || '—'}`)),
          kv('پروتکل رفت / برگشت', ltr(`${sp.up_transport || '—'}:${sp.up_port || '—'} / ${sp.down_transport || '—'}:${sp.down_port || '—'}`)),
        ] : [
          kv('IP تانل ایران', ltr(t.tun_iran_ip)),
          kv('IP تانل خارج', ltr(t.tun_kharej_ip)),
          kv('اینترفیس‌ها', ltr(`${t.iran_iface || '—'} / ${t.kharej_iface || '—'}`)),
        ]),
        kv('پورت‌های فوروارد', ltr(fmtPorts(t.forward_ports))),
        kv('آخرین بررسی', lc ? fmtTime(lc.at) : '—'),
        kv('زمان ساخت', fmtTime(t.created_at))),
      lc && lc.info ? h('p', { class: `check-info${lc.ok ? '' : ' is-err'}` }, infoText(lc.info)) : null,
      h('div', { class: 'card-actions' }, verifyBtn, redeployBtn, logBtn, delBtn));
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
    const iran = servers.filter((s) => s.role === 'iran').map((s) => ({ value: s.id, label: `${s.name} (${s.host})` }));
    const loaded = lists.servers.loaded;
    fillSelect(iranSel, iran, !loaded ? 'در حال بارگذاری…' : iran.length ? 'انتخاب سرور ایران…' : 'سرور ایرانی ثبت نشده است');
    iranSel.disabled = !iran.length;
    $('#rf-submit').disabled = !iran.length;
    updateRelayEngine();
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
    if (!iran) return showErr(errBox, 'سرور ایران را انتخاب کنید.');
    if (!validRelayTarget(target, engine === 'iptables')) {
      return showErr(errBox, engine === 'iptables' ? 'مقصد رله باید IPv4 معتبر باشد.' : 'مقصد رله باید IPv4 یا دامنه معتبر باشد.');
    }
    if (!ports || !PORTS_SPEC_RE.test(ports)) return showErr(errBox, 'پورت‌ها باید به شکل 443 یا 2096:443 باشند.');
    if (engine === 'haproxy' && proto !== 'tcp') return showErr(errBox, 'رله HAProxy فقط TCP است.');
    if (nameRaw && !RELAY_NAME_RE.test(nameRaw)) return showErr(errBox, 'نام رله: حروف کوچک انگلیسی، عدد و خط تیره (حداکثر ۲۴).');
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
          h('h4', { class: 'card-title' }, r.name || 'رله'),
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

  /* ---------- jobs ---------- */

  function jobBadge(status) {
    const [kind, label] = JOB_STATUS[status] || ['muted', status || 'نامشخص'];
    return badge(kind, label, isActive(status));
  }

  function renderJobs() {
    const box = $(lists.jobs.el);
    const data = lists.jobs.data;
    if (!data.length) {
      box.replaceChildren(emptyState('هنوز کاری اجرا نشده است.', 'با تست اتصال، نصب یا ساخت تانل، کارها اینجا نمایش داده می‌شوند.'));
      return;
    }
    const rows = data.map((j) => {
      const open = () => openJobView(j.id);
      const label = JOB_STATUS[j.status] ? JOB_STATUS[j.status][1] : j.status;
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
      h('span', { class: 'job-main' },
        h('span', { class: 'job-title' }, j.title || j.kind || `کار ${j.id}`),
        h('span', { class: 'job-kind', dir: 'ltr' }, j.kind || '')),
      jobBadge(j.status),
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
  }

  function openJobView(id) {
    closeJobView();
    const statusEl = h('span', { class: 'job-status' }, loadingState());
    const metaEl = h('dl', { class: 'kv kv-inline' });
    const stepsEl = h('ol', { class: 'steps' });
    const logEl = h('pre', { class: 'log', dir: 'ltr', tabindex: '0', 'aria-label': 'لاگ کار' });
    const followBtn = h('button', { type: 'button', class: 'btn btn-sm btn-ghost', hidden: true }, 'رفتن به انتهای لاگ');
    const body = h('div', { class: 'job-view' },
      h('div', { class: 'job-head' }, statusEl, metaEl),
      h('h3', { class: 'sub-head' }, 'مراحل'),
      stepsEl,
      h('div', { class: 'log-head' }, h('h3', { class: 'sub-head' }, 'لاگ'), followBtn),
      logEl);
    const closeBtn = h('button', { type: 'button', class: 'btn', onclick: () => jv.m.close() }, 'بستن');

    const jv = { id, closed: false, done: false, es: null, pollTimer: null, stick: true, job: null, statusEl, metaEl, stepsEl, logEl, followBtn };
    jv.m = openModal({ title: 'جزئیات کار', body, footer: closeBtn, wide: true, onClose: () => stopJobView(jv) });
    state.jobView = jv;

    logEl.addEventListener('scroll', () => {
      jv.stick = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 24;
      followBtn.hidden = jv.stick;
    });
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
    jv.logEl.scrollTop = jv.logEl.scrollHeight;
  }

  function renderJob(jv, job) {
    if (!job || typeof job !== 'object') return;
    jv.job = Object.assign({}, job, { steps: Array.isArray(job.steps) ? job.steps.slice() : [] });
    jv.m.titleEl.textContent = job.title || job.kind || 'جزئیات کار';
    setJobStatus(jv, job.status);
    jv.metaEl.replaceChildren(
      ...kv('نوع', ltr(job.kind)),
      ...kv('شروع', fmtTime(job.created_at)),
      ...kv('پایان', job.finished_at ? fmtTime(job.finished_at) : '—'),
      ...kv('مدت', job.finished_at ? fmtDuration(job.created_at, job.finished_at) : '—'));
    renderSteps(jv);
    jv.logEl.textContent = job.log || '';
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
  }

  function renderSteps(jv) {
    const steps = (jv.job && jv.job.steps) || [];
    if (!steps.length) {
      jv.stepsEl.replaceChildren(h('li', { class: 'step step-empty' }, 'هنوز مرحله‌ای ثبت نشده است.'));
      return;
    }
    jv.stepsEl.replaceChildren(...steps.map((s) => {
      const st = s && STEP_STATUS[s.status] ? s.status : 'pending';
      const [icon, label] = STEP_STATUS[st];
      return h('li', { class: `step step-${st}` },
        h('span', { class: 'step-icon', 'aria-hidden': 'true' }, icon),
        h('div', { class: 'step-body' },
          h('div', { class: 'step-name' }, (s && s.name) || '—'),
          s && s.detail ? h('div', { class: 'step-detail' }, infoText(s.detail)) : null),
        h('span', { class: 'step-status' }, label));
    }));
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
      es = new EventSource(`/api/jobs/${enc(jv.id)}/stream`);
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
      jv.logEl.append(document.createTextNode(`${d.line}\n`));
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

  function setVersions(panelV, jojoV) {
    const parts = [];
    if (panelV) parts.push(`پنل ${panelV}`);
    if (jojoV) parts.push(`جوجونت ${jojoV}`);
    $('#hdr-versions').textContent = parts.join(' · ');
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
      field('رمز عبور جدید', fNew, 'حداقل ۱۰ کاراکتر.'),
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
      if (fNew.value.length < 10) return showErr(errBox, 'رمز عبور جدید باید حداقل ۱۰ کاراکتر باشد.');
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
    $('#hdr-user').textContent = state.me.username || '';
    setVersions(state.me.panel_version, state.me.jojonet_version);
    resetLists();
    updateTunnelForm();
    const hashTab = (location.hash || '').slice(1);
    switchTab(TABS.includes(hashTab) ? hashTab : 'servers');
    loadInfo();
    load('servers');
    load('tunnels');
    load('relays');
    load('jobs');
    startPolling();
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
  }

  function bindStatic() {
    $('#login-form').addEventListener('submit', onLogin);
    $('#btn-logout').addEventListener('click', logout);
    $('#btn-password').addEventListener('click', openPasswordForm);
    $('#btn-add-server').addEventListener('click', () => openServerForm(null));
    $('#btn-refresh-servers').addEventListener('click', (e) => act(e.currentTarget, () => load('servers'), 'در حال بروزرسانی…'));
    $('#btn-refresh-tunnels').addEventListener('click', (e) => act(e.currentTarget, () => Promise.all([load('tunnels'), load('servers')]), 'در حال بروزرسانی…'));
    $('#btn-refresh-relays').addEventListener('click', (e) => act(e.currentTarget, () => Promise.all([load('relays'), load('servers')]), 'در حال بروزرسانی…'));
    $('#btn-refresh-jobs').addEventListener('click', (e) => act(e.currentTarget, () => load('jobs'), 'در حال بروزرسانی…'));
    $('#tunnel-form').addEventListener('submit', onCreateTunnel);
    $('#relay-form').addEventListener('submit', onCreateRelay);
    $('#rf-engine').addEventListener('change', updateRelayEngine);
    $('#tf-sp-check').addEventListener('click', onSpoofCheck);
    $('#tf-mode').addEventListener('change', updateModeDesc);

    const tabs = Array.from(document.querySelectorAll('.tab'));
    for (const b of tabs) {
      b.addEventListener('click', () => switchTab(b.dataset.tab));
      b.addEventListener('keydown', (e) => {
        const i = tabs.indexOf(b);
        let n = -1;
        if (e.key === 'ArrowLeft') n = (i + 1) % tabs.length;
        else if (e.key === 'ArrowRight') n = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') n = 0;
        else if (e.key === 'End') n = tabs.length - 1;
        if (n >= 0) {
          e.preventDefault();
          switchTab(tabs[n].dataset.tab, true);
        }
      });
    }

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && state.loggedIn) load('jobs', true);
    });
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
