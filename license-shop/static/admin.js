'use strict';
const $ = (s) => document.querySelector(s);

$('#login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await fetch('/api/admin/login', { method: 'POST', body: new FormData(e.target) });
  if (!r.ok) return alert('رمز اشتباه است');
  $('#login').classList.add('hidden');
  $('#desk').classList.remove('hidden');
  load();
});

$('#refresh').addEventListener('click', load);

async function load() {
  const r = await fetch('/api/admin/orders');
  if (r.status === 401) {
    $('#login').classList.remove('hidden');
    $('#desk').classList.add('hidden');
    return;
  }
  const rows = await r.json();
  const tb = $('#rows');
  tb.replaceChildren();
  for (const o of rows) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td dir="ltr">${o.id}</td><td dir="ltr">${o.email}</td><td>${o.coin}</td>
      <td dir="ltr">${o.amount}</td><td>${o.status}</td><td dir="ltr">${o.txid || ''}</td><td></td>`;
    if (o.status !== 'paid') {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = 'تأیید و صدور';
      b.addEventListener('click', async () => {
        const fd = new FormData();
        fd.set('months', '1');
        const res = await fetch(`/api/admin/orders/${encodeURIComponent(o.id)}/confirm`, { method: 'POST', body: fd });
        const d = await res.json();
        if (!res.ok) return alert(d.detail || 'خطا');
        alert(d.key);
        load();
      });
      tr.lastChild.append(b);
    }
    tb.append(tr);
  }
}

$('#issue').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await fetch('/api/admin/issue', { method: 'POST', body: new FormData(e.target) });
  const d = await r.json();
  if (!r.ok) return alert(d.detail || 'خطا');
  $('#issued').value = d.key;
});
