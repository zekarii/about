/* Brankas cadangan — logika aplikasi
 *
 * Semua enkripsi berjalan di browser (Web Crypto API). Tidak ada permintaan jaringan.
 *
 * Cara kerja:
 *  - Saat membuat brankas, dibuat kunci data acak 256-bit (DEK).
 *  - Password Anda diubah menjadi kunci pembungkus (KEK) lewat PBKDF2-SHA256 (600.000 putaran + salt acak).
 *  - DEK dibungkus dengan AES-GCM memakai KEK. Hanya hasil bungkusan ini yang disimpan.
 *    Password tidak pernah disimpan; password yang salah membuat pembukaan bungkusan gagal.
 *  - Setiap file dipecah per 4 MB dan dienkripsi AES-256-GCM dengan IV acak per potongan.
 *    Nama, tipe, dan ukuran file ikut dienkripsi. Urutan potongan dikunci lewat data autentikasi
 *    tambahan (AAD), sehingga potongan tidak bisa ditukar, dibuang, atau dipindah antar file.
 *  - Data disimpan di IndexedDB browser. Ekspor menghasilkan satu file .brankas yang tetap terenkripsi.
 */
'use strict';

(() => {
  /* ---------- Konfigurasi ---------- */
  const DB_NAME = 'brankas-cadangan';
  const DB_VERSION = 1;
  const MAX_FILE_BYTES = 1024 * 1024 * 1024; // 1 GB per file
  const IDLE_LOCK_MS = 5 * 60 * 1000;        // kunci otomatis setelah 5 menit tanpa aktivitas
  const MIN_PASSWORD = 12;
  const MAGIC = 'BRANKAS1';

  const $ = (sel, root = document) => root.querySelector(sel);

  /* CRYPTO:BEGIN */
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITERATIONS = 600000;
  const CHUNK = 4 * 1024 * 1024;
  const DEK_AAD = enc.encode('brankas:v1:dek');

  // Status sesi: kunci hanya ada di memori selama brankas terbuka.
  const session = { key: null, items: [], metas: new Map(), idleTimer: null, busy: 0 };

  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

  const b64 = {
    enc(input) {
      const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(s);
    },
    dec(str) {
      const bin = atob(str);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    },
  };

  async function deriveKek(password, salt, iterations) {
    const base = await crypto.subtle.importKey(
      'raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // Bungkus kunci data mentah dengan password. Hasilnya aman disimpan.
  async function wrapDek(password, rawDek) {
    const salt = rand(16);
    const iv = rand(12);
    const kek = await deriveKek(password, salt, PBKDF2_ITERATIONS);
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: DEK_AAD }, kek, rawDek)
    );
    return { v: 1, iterations: PBKDF2_ITERATIONS, salt, iv, wrapped };
  }

  const importDek = (raw, extractable) =>
    crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, ['encrypt', 'decrypt']);

  // Buka bungkusan. Melempar error jika password salah.
  async function openVault(password, cfg, extractable) {
    const kek = await deriveKek(password, cfg.salt, cfg.iterations);
    const raw = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: cfg.iv, additionalData: DEK_AAD }, kek, cfg.wrapped
    );
    try {
      return await importDek(raw, extractable);
    } finally {
      new Uint8Array(raw).fill(0);
    }
  }

  // Data autentikasi tambahan per potongan: id file + nomor potongan + penanda potongan terakhir.
  function makeAad(id, index, last) {
    const idBytes = enc.encode(id);
    const out = new Uint8Array(idBytes.length + 5);
    out.set(idBytes, 0);
    new DataView(out.buffer).setUint32(idBytes.length, index);
    out[idBytes.length + 4] = last ? 1 : 0;
    return out;
  }

  async function encryptFile(file, onProgress) {
    const id = hex(rand(16));
    const total = Math.max(1, Math.ceil(file.size / CHUNK));
    const parts = [];
    for (let i = 0; i < total; i++) {
      const plain = await file.slice(i * CHUNK, (i + 1) * CHUNK).arrayBuffer();
      const iv = rand(12);
      const ct = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: makeAad(id, i, i === total - 1) },
        session.key,
        plain
      );
      parts.push(iv, ct);
      if (onProgress) onProgress((i + 1) / total);
    }
    const meta = {
      name: file.name,
      type: file.type || 'application/octet-stream',
      size: file.size,
      modified: file.lastModified,
      chunk: CHUNK,
    };
    const metaIv = rand(12);
    const metaCt = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: metaIv, additionalData: enc.encode('meta:' + id) },
      session.key,
      enc.encode(JSON.stringify(meta))
    );
    const data = new Blob(parts, { type: 'application/octet-stream' });
    const item = { id, created: Date.now(), metaIv, meta: new Uint8Array(metaCt), data, dataSize: data.size };
    return { item, meta };
  }

  async function decryptMeta(item) {
    const buf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: item.metaIv, additionalData: enc.encode('meta:' + item.id) },
      session.key,
      item.meta
    );
    return JSON.parse(dec.decode(buf));
  }

  async function decryptFile(item, meta) {
    const chunk = meta.chunk;
    const total = Math.max(1, Math.ceil(meta.size / chunk));
    const stride = 12 + chunk + 16;
    const out = [];
    for (let i = 0; i < total; i++) {
      const plainLen = i < total - 1 ? chunk : meta.size - (total - 1) * chunk;
      const start = i * stride;
      const end = start + 12 + plainLen + 16;
      const buf = new Uint8Array(await item.data.slice(start, end).arrayBuffer());
      out.push(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: buf.subarray(0, 12), additionalData: makeAad(item.id, i, i === total - 1) },
          session.key,
          buf.subarray(12)
        )
      );
    }
    return new Blob(out, { type: meta.type || 'application/octet-stream' });
  }
  /* CRYPTO:END */

  /* ---------- Penyimpanan (IndexedDB) ---------- */
  let db = null;

  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        req.result.createObjectStore('config');
        req.result.createObjectStore('items', { keyPath: 'id' });
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  const reqP = (req) =>
    new Promise((resolve, reject) => {
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

  const txDone = (tx) =>
    new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new DOMException('Transaksi dibatalkan', 'AbortError'));
    });

  const store = {
    getConfig: () => reqP(db.transaction('config').objectStore('config').get('main')),
    async setConfig(cfg) {
      const tx = db.transaction('config', 'readwrite');
      tx.objectStore('config').put(cfg, 'main');
      return txDone(tx);
    },
    allItems: () => reqP(db.transaction('items').objectStore('items').getAll()),
    async putItems(items) {
      const tx = db.transaction('items', 'readwrite');
      for (const item of items) tx.objectStore('items').put(item);
      return txDone(tx);
    },
    async deleteItem(id) {
      const tx = db.transaction('items', 'readwrite');
      tx.objectStore('items').delete(id);
      return txDone(tx);
    },
    async replaceAll(config, items) {
      const tx = db.transaction(['config', 'items'], 'readwrite');
      tx.objectStore('items').clear();
      for (const item of items) tx.objectStore('items').put(item);
      tx.objectStore('config').put(config, 'main');
      return txDone(tx);
    },
  };

  /* ---------- Operasi brankas ---------- */
  async function createVault(password) {
    const rawDek = rand(32);
    try {
      const cfg = await wrapDek(password, rawDek);
      await store.setConfig(cfg);
      session.key = await importDek(rawDek, false);
    } finally {
      rawDek.fill(0);
    }
  }

  async function unlock(password) {
    const cfg = await store.getConfig();
    try {
      session.key = await openVault(password, cfg, false);
      return true;
    } catch {
      return false;
    }
  }

  async function changePassword(oldPassword, newPassword) {
    const cfg = await store.getConfig();
    let dek;
    try {
      dek = await openVault(oldPassword, cfg, true);
    } catch {
      return false;
    }
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dek));
    try {
      await store.setConfig(await wrapDek(newPassword, raw));
    } finally {
      raw.fill(0);
    }
    return true;
  }

  /* ---------- Pembatasan percobaan (hanya di sisi klien) ---------- */
  const guard = {
    read() {
      try {
        return JSON.parse(localStorage.getItem('brankas-guard')) || { n: 0, until: 0 };
      } catch {
        return { n: 0, until: 0 };
      }
    },
    write(v) {
      try { localStorage.setItem('brankas-guard', JSON.stringify(v)); } catch { /* abaikan */ }
    },
    wait() { return Math.max(0, this.read().until - Date.now()); },
    fail() {
      const g = this.read();
      g.n += 1;
      if (g.n >= 3) g.until = Date.now() + Math.min(15 * 60 * 1000, 5000 * 2 ** (g.n - 3));
      this.write(g);
    },
    reset() { this.write({ n: 0, until: 0 }); },
  };

  /* ---------- Utilitas tampilan ---------- */
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const reduceMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

  function formatBytes(n) {
    if (!Number.isFinite(n)) return '–';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toLocaleString('id-ID', { maximumFractionDigits: i === 0 ? 0 : 1 })} ${units[i]}`;
  }

  const formatDate = (ms) =>
    new Date(ms).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'short' });

  function formatWait(seconds) {
    if (seconds < 60) return `${seconds} detik`;
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return s ? `${m} menit ${s} detik` : `${m} menit`;
  }

  function stamp() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
  }

  let toastTimer = null;
  function toast(message, kind) {
    const el = $('#toast');
    el.textContent = message;
    el.classList.toggle('is-error', kind === 'error');
    el.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('is-on'), kind === 'error' ? 7000 : 4500);
  }

  const setStatus = (text) => { $('#vault-status').textContent = text; };

  function setBusy(btn, busy, label) {
    if (busy) {
      btn.dataset.label = btn.textContent;
      btn.textContent = label;
      btn.disabled = true;
    } else {
      if (btn.dataset.label) btn.textContent = btn.dataset.label;
      btn.disabled = false;
    }
  }

  function saveBlob(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.rel = 'noopener';
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  function confirmDialog({ title, body, confirmLabel, danger }) {
    return new Promise((resolve) => {
      const dlg = $('#dlg-confirm');
      $('#dlg-confirm-title').textContent = title;
      $('#dlg-confirm-body').textContent = body;
      const ok = $('#dlg-confirm-ok');
      ok.textContent = confirmLabel;
      ok.classList.toggle('btn-danger', !!danger);
      ok.classList.toggle('btn-primary', !danger);
      dlg.returnValue = '';
      dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), { once: true });
      dlg.showModal();
    });
  }

  /* ---------- Kenop kombinasi ---------- */
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const DIAL = { cx: 200, cy: 212, outer: 176, numR: 130, ticks: 100 };
  let dialAngle = 0;

  function buildDial() {
    const rotor = $('#dial-rotor');
    for (let i = 0; i < DIAL.ticks; i++) {
      const deg = (360 / DIAL.ticks) * i;
      const rad = (deg * Math.PI) / 180;
      const sin = Math.sin(rad);
      const cos = Math.cos(rad);
      const major = i % 10 === 0;
      const mid = i % 5 === 0;
      const len = major ? 22 : mid ? 14 : 8;

      const line = document.createElementNS(SVG_NS, 'line');
      line.setAttribute('x1', (DIAL.cx + sin * DIAL.outer).toFixed(2));
      line.setAttribute('y1', (DIAL.cy - cos * DIAL.outer).toFixed(2));
      line.setAttribute('x2', (DIAL.cx + sin * (DIAL.outer - len)).toFixed(2));
      line.setAttribute('y2', (DIAL.cy - cos * (DIAL.outer - len)).toFixed(2));
      line.setAttribute('class', major ? 'tick major' : mid ? 'tick mid' : 'tick');
      rotor.append(line);

      if (major) {
        const x = (DIAL.cx + sin * DIAL.numR).toFixed(2);
        const y = (DIAL.cy - cos * DIAL.numR).toFixed(2);
        const text = document.createElementNS(SVG_NS, 'text');
        text.setAttribute('x', x);
        text.setAttribute('y', y);
        text.setAttribute('transform', `rotate(${deg} ${x} ${y})`);
        text.setAttribute('class', 'dial-num');
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('dominant-baseline', 'central');
        text.textContent = String(i);
        rotor.append(text);
      }
    }
  }

  function setDial(deg, duration) {
    const rotor = $('#dial-rotor');
    rotor.style.transition = duration ? `transform ${duration}ms cubic-bezier(.5, 0, .2, 1)` : '';
    dialAngle = deg;
    rotor.style.transform = `rotate(${deg}deg)`;
  }

  function resetDial() {
    const rotor = $('#dial-rotor');
    rotor.style.transition = 'none';
    rotor.style.transform = 'rotate(0deg)';
    dialAngle = 0;
    void rotor.getBoundingClientRect();
    rotor.style.transition = '';
  }

  // Setiap karakter memutar kenop 6 garis (21,6 derajat).
  const followTyping = (input) => setDial(input.value.length * 21.6);

  function shakeDial() {
    const el = $('#dial');
    el.classList.remove('is-error');
    void el.getBoundingClientRect();
    el.classList.add('is-error');
  }

  async function spinDial() {
    if (reduceMotion()) return;
    setDial(dialAngle + 360, 650);
    await sleep(700);
  }

  /* ---------- Kekuatan password (perkiraan kasar) ---------- */
  const COMMON = ['password', 'passw0rd', 'qwerty', '123456', 'admin', 'letmein', 'iloveyou',
    'welcome', 'abc123', 'katasandi', 'rahasia', 'sayang', 'indonesia'];
  const STRENGTH_NAMES = ['', 'lemah', 'cukup', 'kuat', 'sangat kuat'];

  function strength(pw) {
    if (!pw) return { level: 0, text: null };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    const unique = new Set(pw).size;
    let bits = Math.log2(pool) * Math.min(pw.length, unique * 2);
    const lower = pw.toLowerCase().replace(/\s+/g, '');
    if (COMMON.some((w) => lower.includes(w))) bits = Math.min(bits, 30);
    if (pw.length < MIN_PASSWORD) bits = Math.min(bits, 45);
    const level = bits < 45 ? 1 : bits < 70 ? 2 : bits < 95 ? 3 : 4;
    return { level, text: `Kekuatan: ${STRENGTH_NAMES[level]} (perkiraan kasar)` };
  }

  function bindMeter(input, meter, label) {
    const fallback = label.textContent;
    const update = () => {
      const s = strength(input.value);
      meter.dataset.level = String(s.level);
      label.textContent = s.text || fallback;
    };
    input.addEventListener('input', update);
    return update;
  }

  function randomPassword(length = 20) {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+?';
    const limit = Math.floor(256 / alphabet.length) * alphabet.length; // hindari bias modulo
    let out = '';
    while (out.length < length) {
      for (const b of rand(length * 2)) {
        if (b < limit && out.length < length) out += alphabet[b % alphabet.length];
      }
    }
    return out;
  }

  /* ---------- Tampilan ---------- */
  const views = { gate: $('#view-gate'), vault: $('#view-vault'), fatal: $('#view-fatal') };

  function showView(mode) {
    views.gate.hidden = !(mode === 'setup' || mode === 'unlock');
    views.vault.hidden = mode !== 'vault';
    views.fatal.hidden = mode !== 'fatal';
    $('#setup-form').hidden = mode !== 'setup';
    $('#unlock-form').hidden = mode !== 'unlock';
    if (mode === 'setup') $('#setup-pw').focus();
    if (mode === 'unlock') $('#unlock-pw').focus();
  }

  function fatal(message) {
    $('#fatal-message').textContent = message;
    showView('fatal');
  }

  function cell(className, text) {
    const td = document.createElement('td');
    if (className) td.className = className;
    td.textContent = text;
    return td;
  }

  function actionButton(label, ariaLabel, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'btn btn-sm';
    b.textContent = label;
    b.setAttribute('aria-label', ariaLabel);
    b.addEventListener('click', onClick);
    return b;
  }

  function renderList() {
    const body = $('#file-rows');
    body.replaceChildren();
    let total = 0;

    if (!session.items.length) {
      const tr = document.createElement('tr');
      tr.className = 'empty';
      const td = cell('', 'Brankas masih kosong. Tarik file ke slot di atas untuk mulai.');
      td.colSpan = 4;
      tr.append(td);
      body.append(tr);
    }

    for (const item of session.items) {
      const meta = session.metas.get(item.id);
      total += meta.size || 0;
      const tr = document.createElement('tr');
      tr.append(
        cell('name', meta.name),
        cell('col-size', meta.broken ? '–' : formatBytes(meta.size)),
        cell('col-date', formatDate(item.created))
      );
      const actions = document.createElement('td');
      actions.className = 'col-actions';
      if (!meta.broken) {
        actions.append(actionButton('Unduh', `Unduh ${meta.name}`, () => downloadItem(item.id)));
      }
      actions.append(actionButton('Hapus', `Hapus ${meta.name}`, () => deleteItem(item.id)));
      tr.append(actions);
      body.append(tr);
    }

    const n = session.items.length;
    $('#vault-summary').textContent = n ? `${n} file, ${formatBytes(total)}` : 'Kosong';
  }

  async function updateStorageNote() {
    const el = $('#storage-note');
    if (!navigator.storage || !navigator.storage.estimate) return;
    try {
      const { usage, quota } = await navigator.storage.estimate();
      el.textContent = `Ruang browser: ${formatBytes(usage)} terpakai dari perkiraan ${formatBytes(quota)}.`;
    } catch { /* abaikan */ }
  }

  let persistAsked = false;
  async function askPersistence() {
    if (persistAsked || !navigator.storage || !navigator.storage.persist) return;
    persistAsked = true;
    try { await navigator.storage.persist(); } catch { /* abaikan */ }
  }

  async function loadItems() {
    const rows = await store.allItems();
    rows.sort((a, b) => b.created - a.created);
    session.items = rows;
    session.metas = new Map();
    await Promise.all(rows.map(async (row) => {
      try {
        session.metas.set(row.id, await decryptMeta(row));
      } catch {
        session.metas.set(row.id, { name: '(tidak bisa dibaca)', size: 0, type: '', broken: true });
      }
    }));
  }

  async function enterVault() {
    await loadItems();
    renderList();
    setStatus('');
    showView('vault');
    bumpIdle();
    updateStorageNote();
  }

  function lock(message) {
    clearTimeout(session.idleTimer);
    session.key = null;
    session.items = [];
    session.metas = new Map();
    $('#file-rows').replaceChildren();
    $('#unlock-pw').value = '';
    setStatus('');
    resetDial();
    showView('unlock');
    startCountdown();
    if (message) toast(message);
  }

  function bumpIdle() {
    if (!session.key) return;
    clearTimeout(session.idleTimer);
    session.idleTimer = setTimeout(() => {
      if (session.busy) { bumpIdle(); return; }
      lock('Brankas dikunci otomatis karena tidak ada aktivitas.');
    }, IDLE_LOCK_MS);
  }

  /* ---------- Hitung mundur setelah salah password ---------- */
  let countdownTimer = null;
  function startCountdown() {
    clearInterval(countdownTimer);
    const err = $('#unlock-error');
    const btn = $('#unlock-submit');
    const tick = () => {
      const s = Math.ceil(guard.wait() / 1000);
      if (s <= 0) {
        clearInterval(countdownTimer);
        btn.disabled = false;
        if (err.dataset.locked) {
          err.textContent = '';
          delete err.dataset.locked;
        }
        return;
      }
      btn.disabled = true;
      err.dataset.locked = '1';
      err.textContent = `Terlalu banyak percobaan salah. Tunggu ${formatWait(s)} sebelum mencoba lagi.`;
    };
    tick();
    if (guard.wait() > 0) countdownTimer = setInterval(tick, 500);
  }

  /* ---------- File: tambah, unduh, hapus ---------- */
  async function addFiles(fileList) {
    const files = Array.from(fileList);
    if (!files.length || !session.key) return;
    session.busy++;
    let saved = 0;
    try {
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const prefix = `Mengenkripsi ${i + 1} dari ${files.length}: ${file.name}`;
        if (file.size > MAX_FILE_BYTES) {
          toast(`${file.name} dilewati karena lebih dari ${formatBytes(MAX_FILE_BYTES)}.`, 'error');
          continue;
        }
        setStatus(prefix);
        try {
          const { item, meta } = await encryptFile(file, (p) => setStatus(`${prefix} (${Math.round(p * 100)}%)`));
          await store.putItems([item]);
          session.items.unshift(item);
          session.metas.set(item.id, meta);
          saved++;
          renderList();
        } catch (err) {
          if (err && err.name === 'QuotaExceededError') {
            toast('Ruang penyimpanan browser penuh. Hapus file lama atau ekspor cadangan dulu.', 'error');
            break;
          }
          toast(`Gagal menyimpan ${file.name}. Jika ini folder, kompres jadi .zip dulu.`, 'error');
        }
      }
    } finally {
      session.busy--;
      setStatus(saved ? `${saved} file disimpan dan dienkripsi.` : '');
      updateStorageNote();
      if (saved) askPersistence();
    }
  }

  async function downloadItem(id) {
    const item = session.items.find((i) => i.id === id);
    const meta = session.metas.get(id);
    if (!item || !meta || meta.broken || !session.key) return;
    session.busy++;
    try {
      setStatus(`Mendekripsi ${meta.name}…`);
      const blob = await decryptFile(item, meta);
      saveBlob(blob, meta.name);
      setStatus(`${meta.name} diunduh.`);
    } catch {
      setStatus('');
      toast('Gagal mendekripsi file. Datanya mungkin rusak atau sudah diubah.', 'error');
    } finally {
      session.busy--;
    }
  }

  async function deleteItem(id) {
    const meta = session.metas.get(id);
    if (!meta) return;
    const ok = await confirmDialog({
      title: 'Hapus file ini?',
      body: `"${meta.name}" akan dihapus permanen dari brankas. Tindakan ini tidak bisa dibatalkan.`,
      confirmLabel: 'Hapus',
      danger: true,
    });
    if (!ok) return;
    try {
      await store.deleteItem(id);
      session.items = session.items.filter((i) => i.id !== id);
      session.metas.delete(id);
      renderList();
      updateStorageNote();
      toast('File dihapus.');
    } catch {
      toast('Gagal menghapus file.', 'error');
    }
  }

  /* ---------- Ekspor dan impor ---------- */
  async function exportVault() {
    session.busy++;
    try {
      setStatus('Menyiapkan file cadangan…');
      const cfg = await store.getConfig();
      const items = await store.allItems();
      const header = {
        v: 1,
        exported: Date.now(),
        config: {
          v: cfg.v,
          iterations: cfg.iterations,
          salt: b64.enc(cfg.salt),
          iv: b64.enc(cfg.iv),
          wrapped: b64.enc(cfg.wrapped),
        },
        items: items.map((i) => ({
          id: i.id,
          created: i.created,
          metaIv: b64.enc(i.metaIv),
          meta: b64.enc(i.meta),
          size: i.data.size,
        })),
      };
      const headerBytes = enc.encode(JSON.stringify(header));
      const lenBytes = new Uint8Array(4);
      new DataView(lenBytes.buffer).setUint32(0, headerBytes.length);
      const blob = new Blob(
        [enc.encode(MAGIC), lenBytes, headerBytes, ...items.map((i) => i.data)],
        { type: 'application/octet-stream' }
      );
      saveBlob(blob, `brankas-${stamp()}.brankas`);
      setStatus('Cadangan diekspor. Simpan salinannya di tempat lain.');
    } catch {
      setStatus('');
      toast('Gagal membuat file cadangan.', 'error');
    } finally {
      session.busy--;
    }
  }

  async function parseBackup(file) {
    const fixed = MAGIC.length + 4;
    const head = new Uint8Array(await file.slice(0, fixed).arrayBuffer());
    if (head.length < fixed || dec.decode(head.subarray(0, MAGIC.length)) !== MAGIC) {
      throw new Error('Ini bukan file cadangan brankas.');
    }
    const headerLen = new DataView(head.buffer, head.byteOffset + MAGIC.length, 4).getUint32(0);
    if (headerLen > 64 * 1024 * 1024 || fixed + headerLen > file.size) {
      throw new Error('File cadangan rusak atau terpotong.');
    }

    let header;
    try {
      header = JSON.parse(dec.decode(await file.slice(fixed, fixed + headerLen).arrayBuffer()));
    } catch {
      throw new Error('File cadangan rusak atau terpotong.');
    }
    if (!header || header.v !== 1 || !header.config || !Array.isArray(header.items)) {
      throw new Error('Format file cadangan tidak dikenali.');
    }

    let config;
    try {
      const c = header.config;
      config = {
        v: 1,
        iterations: Number(c.iterations),
        salt: b64.dec(c.salt),
        iv: b64.dec(c.iv),
        wrapped: b64.dec(c.wrapped),
      };
    } catch {
      throw new Error('File cadangan rusak.');
    }
    if (!(config.iterations >= 100000 && config.iterations <= 5000000) ||
        config.salt.length < 16 || config.iv.length !== 12 || config.wrapped.length < 32) {
      throw new Error('Pengaturan kunci di file cadangan tidak valid.');
    }

    let offset = fixed + headerLen;
    const items = [];
    for (const it of header.items) {
      const size = Number(it.size);
      if (typeof it.id !== 'string' || !/^[0-9a-f]{32}$/.test(it.id) ||
          !Number.isFinite(size) || size < 0 || offset + size > file.size) {
        throw new Error('File cadangan rusak atau terpotong.');
      }
      let metaIv, meta;
      try {
        metaIv = b64.dec(it.metaIv);
        meta = b64.dec(it.meta);
      } catch {
        throw new Error('File cadangan rusak.');
      }
      if (metaIv.length !== 12) throw new Error('File cadangan rusak.');
      items.push({
        id: it.id,
        created: Number(it.created) || Date.now(),
        metaIv,
        meta,
        data: file.slice(offset, offset + size),
        dataSize: size,
      });
      offset += size;
    }
    return { config, items };
  }

  const sameBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  async function importBackup(file, fromGate) {
    let parsed;
    try {
      parsed = await parseBackup(file);
    } catch (err) {
      toast(err.message, 'error');
      return;
    }

    try {
      if (fromGate) {
        await store.replaceAll(parsed.config, parsed.items);
        showView('unlock');
        toast(`Cadangan dimuat (${parsed.items.length} file). Masukkan password dari cadangan ini.`);
        return;
      }

      const current = await store.getConfig();
      const sameVault = sameBytes(current.salt, parsed.config.salt) &&
                        sameBytes(current.wrapped, parsed.config.wrapped);

      if (sameVault) {
        const existing = new Set(session.items.map((i) => i.id));
        const fresh = parsed.items.filter((i) => !existing.has(i.id));
        if (fresh.length) await store.putItems(fresh);
        await loadItems();
        renderList();
        updateStorageNote();
        toast(fresh.length ? `${fresh.length} file ditambahkan dari cadangan.` : 'Semua file di cadangan ini sudah ada.');
        return;
      }

      const ok = await confirmDialog({
        title: 'Ganti isi brankas?',
        body: 'Cadangan ini berasal dari brankas lain, atau dibuat dengan password yang berbeda. ' +
              'Melanjutkan akan menghapus seluruh isi brankas ini dan menggantinya dengan isi cadangan. ' +
              'Setelah itu Anda harus memakai password milik cadangan tersebut.',
        confirmLabel: 'Ganti isi brankas',
        danger: true,
      });
      if (!ok) return;
      await store.replaceAll(parsed.config, parsed.items);
      lock('Cadangan dimuat. Masukkan password dari cadangan tersebut.');
    } catch (err) {
      toast(err && err.name === 'QuotaExceededError'
        ? 'Ruang penyimpanan browser tidak cukup untuk cadangan ini.'
        : 'Gagal memuat cadangan.', 'error');
    }
  }

  /* ---------- Pasang event ---------- */
  function wireReveal() {
    for (const btn of document.querySelectorAll('[data-reveal]')) {
      btn.addEventListener('click', () => {
        setReveal(btn, btn.getAttribute('aria-pressed') !== 'true');
      });
    }
  }

  function setReveal(btn, show) {
    for (const id of btn.dataset.reveal.split(' ')) {
      $('#' + id).type = show ? 'text' : 'password';
    }
    btn.setAttribute('aria-pressed', String(show));
    btn.textContent = show ? 'Sembunyikan' : 'Tampilkan';
  }

  function wireSetup() {
    const pw = $('#setup-pw');
    const pw2 = $('#setup-pw2');
    const updateMeter = bindMeter(pw, $('#setup-meter'), $('#setup-meter-label'));
    pw.addEventListener('input', () => followTyping(pw));

    $('#btn-generate').addEventListener('click', () => {
      const generated = randomPassword(20);
      pw.value = generated;
      pw2.value = generated;
      setReveal($('[data-reveal="setup-pw setup-pw2"]'), true);
      updateMeter();
      followTyping(pw);
      toast('Password acak dibuat di browser ini. Catat atau simpan di password manager sebelum melanjutkan.');
    });

    $('#setup-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const err = $('#setup-error');
      const btn = $('#setup-submit');
      err.textContent = '';
      if (pw.value.length < MIN_PASSWORD) { err.textContent = `Password minimal ${MIN_PASSWORD} karakter.`; pw.focus(); return; }
      if (pw.value !== pw2.value) { err.textContent = 'Kedua password belum sama.'; pw2.focus(); return; }
      if (!$('#setup-ack').checked) { err.textContent = 'Centang pernyataan di atas untuk melanjutkan.'; return; }

      setBusy(btn, true, 'Membuat brankas…');
      try {
        await createVault(pw.value);
        pw.value = '';
        pw2.value = '';
        $('#setup-ack').checked = false;
        setReveal($('[data-reveal="setup-pw setup-pw2"]'), false);
        updateMeter();
        await spinDial();
        await enterVault();
        resetDial();
      } catch {
        err.textContent = 'Brankas gagal dibuat. Coba lagi, atau pakai browser lain.';
      } finally {
        setBusy(btn, false);
      }
    });

    $('#btn-import-gate').addEventListener('click', () => {
      importFromGate = true;
      $('#import-input').click();
    });
  }

  function wireUnlock() {
    const pw = $('#unlock-pw');
    pw.addEventListener('input', () => followTyping(pw));

    $('#unlock-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const err = $('#unlock-error');
      const btn = $('#unlock-submit');
      if (guard.wait() > 0) { startCountdown(); return; }
      err.textContent = '';
      if (!pw.value) { err.textContent = 'Masukkan password.'; pw.focus(); return; }

      setBusy(btn, true, 'Memeriksa…');
      try {
        if (await unlock(pw.value)) {
          guard.reset();
          pw.value = '';
          await spinDial();
          await enterVault();
          resetDial();
        } else {
          guard.fail();
          shakeDial();
          err.textContent = 'Password salah.';
          pw.select();
        }
      } catch {
        err.textContent = 'Brankas tidak bisa dibuka. Coba muat ulang halaman.';
      } finally {
        setBusy(btn, false);
        startCountdown();
      }
    });
  }

  let importFromGate = false;

  function wireVault() {
    const zone = $('#dropzone');
    const input = $('#file-input');

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    input.addEventListener('change', () => {
      const files = Array.from(input.files);
      input.value = '';
      addFiles(files);
    });

    for (const type of ['dragenter', 'dragover']) {
      zone.addEventListener(type, (e) => { e.preventDefault(); zone.classList.add('is-over'); });
    }
    zone.addEventListener('dragleave', (e) => {
      if (!zone.contains(e.relatedTarget)) zone.classList.remove('is-over');
    });
    zone.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('is-over');
      addFiles(e.dataTransfer.files);
    });
    // Cegah browser membuka file yang dijatuhkan di luar slot.
    window.addEventListener('dragover', (e) => e.preventDefault());
    window.addEventListener('drop', (e) => e.preventDefault());

    $('#btn-lock').addEventListener('click', () => lock('Brankas dikunci.'));
    $('#btn-export').addEventListener('click', exportVault);
    $('#btn-import').addEventListener('click', () => {
      importFromGate = false;
      $('#import-input').click();
    });

    $('#import-input').addEventListener('change', (e) => {
      const file = e.target.files[0];
      e.target.value = '';
      if (file) importBackup(file, importFromGate);
    });
  }

  function wireChangePassword() {
    const dlg = $('#dlg-password');
    const form = $('#pw-form');
    const updateMeter = bindMeter($('#pw-new'), $('#pw-meter'), $('#pw-meter-label'));

    $('#btn-change').addEventListener('click', () => {
      form.reset();
      $('#pw-error').textContent = '';
      updateMeter();
      dlg.showModal();
      $('#pw-old').focus();
    });
    $('#pw-cancel').addEventListener('click', () => dlg.close());

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const err = $('#pw-error');
      const btn = $('#pw-submit');
      const oldPw = $('#pw-old').value;
      const newPw = $('#pw-new').value;
      err.textContent = '';
      if (!oldPw) { err.textContent = 'Masukkan password sekarang.'; $('#pw-old').focus(); return; }
      if (newPw.length < MIN_PASSWORD) { err.textContent = `Password baru minimal ${MIN_PASSWORD} karakter.`; $('#pw-new').focus(); return; }
      if (newPw !== $('#pw-new2').value) { err.textContent = 'Kedua password baru belum sama.'; $('#pw-new2').focus(); return; }

      setBusy(btn, true, 'Menyimpan…');
      session.busy++;
      try {
        if (await changePassword(oldPw, newPw)) {
          form.reset();
          dlg.close();
          toast('Password diganti. Password lama tidak berlaku lagi.');
        } else {
          err.textContent = 'Password sekarang salah.';
          $('#pw-old').select();
        }
      } catch {
        err.textContent = 'Gagal mengganti password. Coba lagi.';
      } finally {
        session.busy--;
        setBusy(btn, false);
      }
    });
  }

  /* ---------- Mulai ---------- */
  async function init() {
    buildDial();
    wireReveal();
    wireSetup();
    wireUnlock();
    wireVault();
    wireChangePassword();

    for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
      document.addEventListener(ev, bumpIdle, { passive: true });
    }
    window.addEventListener('beforeunload', (e) => {
      if (session.busy) { e.preventDefault(); e.returnValue = ''; }
    });

    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
      fatal('Browser ini tidak menyediakan enkripsi (Web Crypto). Buka halaman lewat https:// atau http://localhost, atau langsung dari file di browser versi terbaru.');
      return;
    }
    if (!window.indexedDB) {
      fatal('Browser ini tidak mendukung penyimpanan IndexedDB.');
      return;
    }
    try {
      db = await openDb();
    } catch {
      fatal('Penyimpanan browser tidak bisa dibuka. Jika Anda memakai jendela privat, buka jendela biasa.');
      return;
    }

    let cfg;
    try {
      cfg = await store.getConfig();
    } catch {
      fatal('Data brankas tidak bisa dibaca dari penyimpanan browser.');
      return;
    }
    showView(cfg ? 'unlock' : 'setup');
    if (cfg) startCountdown();
  }

  init();
})();
