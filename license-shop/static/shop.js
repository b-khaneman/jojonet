'use strict';
const $ = (s) => document.querySelector(s);
let orderId = '';

async function info() {
  const r = await fetch('/api/info');
  const d = await r.json();
  $('#price').textContent = `اشتراک ماهانه: ${d.monthly_usd} دلار آمریکا`;
  $('#support').textContent = d.support || '';
  const sel = $('#coin');
  sel.replaceChildren();
  (d.coins || []).forEach((c) => {
    const o = document.createElement('option');
    o.value = c;
    o.textContent = c;
    sel.append(o);
  });
  if (!d.coins.length) {
    const o = document.createElement('option');
    o.textContent = 'هنوز کیف رمزارز تنظیم نشده — به مدیر بگویید';
    sel.append(o);
    sel.disabled = true;
  }
}

$('#buy').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/api/orders', { method: 'POST', body: fd });
  const d = await r.json();
  if (!r.ok) return alert(d.detail || 'خطا');
  orderId = d.order_id;
  $('#p-coin').textContent = d.coin;
  $('#p-amount').textContent = d.amount;
  $('#p-addr').textContent = d.address;
  $('#p-id').textContent = d.order_id;
  $('#pay').classList.remove('hidden');
});

$('#txid-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch(`/api/orders/${encodeURIComponent(orderId)}/txid`, { method: 'POST', body: fd });
  const d = await r.json();
  if (!r.ok) return alert(d.detail || 'خطا');
  $('#wait').classList.remove('hidden');
  poll();
});

async function poll() {
  if (!orderId) return;
  const r = await fetch(`/api/orders/${encodeURIComponent(orderId)}`);
  const d = await r.json();
  if (d.status === 'paid' && d.key) {
    $('#done').classList.remove('hidden');
    $('#key').value = d.key;
    $('#exp').textContent = d.exp ? `اعتبار تا ${new Date(d.exp * 1000).toLocaleString('fa-IR')}` : '';
    return;
  }
  setTimeout(poll, 8000);
}

info();
