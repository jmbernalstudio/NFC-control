/* NFC Control · Sin red, sin dependencias, sin analíticas.
 * En iPhone ningún navegador (Safari, Chrome…) tiene Web NFC: esta web NO lee NFC físico en iOS.
 * La lectura real la hace una app de lectura (NFC Tools, NFC TagInfo) y aquí se importa su informe.
 * En navegadores con Web NFC (Chrome para Android) la lectura y escritura NDEF son directas.
 */
'use strict';

const STORE = 'nfc-control:vault:1';
const PREFS = 'nfc-control:prefs:1';
const ITERATIONS = 240000;
const IDLE_MS = 5 * 60 * 1000;
const MAX_VAULT_B64 = 8000000;
const MAX_RAW_STORED = 60000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = id => document.getElementById(id);
const $$ = sel => Array.from(document.querySelectorAll(sel));
const P = window.NFCParse;
const state = { cards: [], scans: [], key: null, salt: null, editing: null, idleTimeout: null, currentScan: null, hiddenAt: 0, pendingCardFromScan: null };
const HAS_WEB_NFC = 'NDEFReader' in window;
const IS_IOS = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
let toastTimeout;

/* ---------- Utilidades ---------- */
function notify(message) {
  const element = $('toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => element.classList.remove('show'), 3600);
}
function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}
function getPrefs() {
  try { return { lockDelay: 120000, ...JSON.parse(localStorage.getItem(PREFS) || '{}') }; } catch (e) { return { lockDelay: 120000 }; }
}
function setPrefs(p) { try { localStorage.setItem(PREFS, JSON.stringify(p)); } catch (e) { /* sin almacenamiento */ } }
function askConfirm(text, yes = 'Confirmar') {
  return new Promise(resolve => {
    const dialog = $('confirm-dialog');
    $('confirm-text').textContent = text;
    $('confirm-yes').textContent = yes;
    dialog.returnValue = '';
    dialog.addEventListener('close', () => resolve(dialog.returnValue === 'yes'), { once: true });
    dialog.showModal();
  });
}
function fmtDate(iso) {
  try { return new Date(iso).toLocaleString('es-ES', { dateStyle: 'medium', timeStyle: 'short' }); } catch (e) { return iso; }
}
async function copyText(text, ok) {
  try { await navigator.clipboard.writeText(text); notify(ok); }
  catch (e) { notify('No se pudo copiar. Mantén pulsado el texto para copiarlo.'); }
}
function bytesToB64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 4096) out += String.fromCharCode(...bytes.subarray(i, i + 4096));
  return btoa(out);
}
function b64ToBytes(base64) { return Uint8Array.from(atob(base64), c => c.charCodeAt(0)); }
function bytesToHex(bytes) { return Array.from(bytes, b => b.toString(16).padStart(2, '0').toUpperCase()).join(' '); }

/* ---------- Bóveda cifrada ---------- */
async function makeKey(password, salt) {
  const material = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
function getVault() {
  const raw = localStorage.getItem(STORE);
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  checkVault(parsed);
  return parsed;
}
function checkVault(obj) {
  if (!obj || typeof obj !== 'object' || obj.version !== 1 ||
      !['salt', 'iv', 'ciphertext'].every(key => typeof obj[key] === 'string' && /^[a-zA-Z0-9+/]*={0,2}$/.test(obj[key])) ||
      obj.salt.length > 64 || obj.iv.length > 64 || obj.ciphertext.length > MAX_VAULT_B64 ||
      b64ToBytes(obj.salt).length !== 16 || b64ToBytes(obj.iv).length !== 12 || b64ToBytes(obj.ciphertext).length < 16) {
    throw new Error('Formato de bóveda no válido');
  }
}
async function decryptVault(vault, password) {
  checkVault(vault);
  const salt = b64ToBytes(vault.salt);
  const key = await makeKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(vault.iv) }, key, b64ToBytes(vault.ciphertext));
  const payload = JSON.parse(dec.decode(plaintext));
  if (!payload || payload.version !== 1 || !Array.isArray(payload.cards) || payload.cards.length > 10000) throw new Error('Datos incompatibles');
  const scans = Array.isArray(payload.scans) ? payload.scans.filter(s => s && typeof s === 'object' && typeof s.id === 'string').slice(0, 5000) : [];
  return { key, salt, cards: payload.cards, scans };
}
async function encryptVault() {
  if (!state.key || !state.salt) throw new Error('La bóveda está bloqueada');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ version: 1, cards: state.cards, scans: state.scans }));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, plain);
  const vault = { version: 1, salt: bytesToB64(state.salt), iv: bytesToB64(iv), ciphertext: bytesToB64(new Uint8Array(cipher)) };
  if (vault.ciphertext.length > MAX_VAULT_B64) throw new Error('La bóveda es demasiado grande');
  localStorage.setItem(STORE, JSON.stringify(vault));
}

/* ---------- Pantallas y pestañas ---------- */
function show(screen) {
  $('setup-view').classList.toggle('hidden', screen !== 'setup');
  $('unlock-view').classList.toggle('hidden', screen !== 'unlock');
  $('dashboard-view').classList.toggle('hidden', screen !== 'dashboard');
  document.body.classList.toggle('with-tabs', screen === 'dashboard');
}
function showPanel(name) {
  ['scan', 'history', 'cards', 'settings'].forEach(p => {
    $(`panel-${p}`).classList.toggle('hidden', p !== name);
    const tab = $(`tab-${p}`);
    tab.classList.toggle('active', p === name);
    tab.setAttribute('aria-selected', String(p === name));
  });
  if (name === 'settings') renderSettings();
  window.scrollTo({ top: 0 });
}
function resetIdle() {
  if (!state.key) return;
  clearTimeout(state.idleTimeout);
  state.idleTimeout = setTimeout(lockVault, IDLE_MS);
}
function lockVault() {
  clearTimeout(state.idleTimeout);
  Object.assign(state, { key: null, salt: null, cards: [], scans: [], editing: null, currentScan: null });
  $$('dialog[open]').forEach(d => d.close());
  $('unlock-password').value = '';
  show('unlock');
}
function unlockIntoState(data) {
  Object.assign(state, { key: data.key, salt: data.salt, cards: data.cards, scans: data.scans || [] });
  $('unlock-password').value = '';
  show('dashboard');
  showPanel('scan');
  render();
  resetIdle();
}
async function persist(before, okMessage) {
  try { await encryptVault(); if (okMessage) notify(okMessage); return true; }
  catch (err) { before(); notify('No se pudo guardar: el almacenamiento del navegador está lleno o no disponible.'); return false; }
}

/* ---------- Inventario de tarjetas (fichas) ---------- */
function normalize(value) { return String(value || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase(); }
function render() {
  renderCards();
  renderScans();
}
function renderCards() {
  $('metric-total').textContent = state.cards.length;
  $('metric-active').textContent = state.cards.filter(c => c.status === 'activa').length;
  $('metric-scans').textContent = state.scans.length;
  const query = normalize($('search-input').value);
  const status = $('filter-status').value;
  const filtered = state.cards
    .filter(c => (status === 'todos' || c.status === status) && [c.name, c.owner, c.uid, c.zone, c.tech, c.notes].some(v => normalize(v).includes(query)))
    .sort((a, b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  const list = $('cards-list');
  list.replaceChildren();
  $('empty-state').classList.toggle('hidden', state.cards.length > 0 || query !== '' || status !== 'todos');
  if (!filtered.length && state.cards.length) list.append(el('p', 'muted pad', 'No se encontraron tarjetas con estos filtros.'));
  filtered.forEach(card => {
    const item = el('article', 'access-card');
    const badge = el('div', 'card-badge', '▤'); badge.setAttribute('aria-hidden', 'true');
    const body = el('div', 'card-main');
    body.append(el('div', 'card-name', card.name || 'Sin nombre'),
      el('div', 'card-detail', [card.owner || 'Sin titular', card.zone || 'Sin zona'].join(' · ')),
      el('div', 'card-uid', card.uid ? `UID/REF: ${card.uid}` : `TECNOLOGÍA: ${card.tech || 'Desconocida'}`));
    const side = el('div', 'card-side');
    const statusNode = el('span', `status ${['activa', 'inactiva', 'perdida'].includes(card.status) ? card.status : 'inactiva'}`,
      ({ activa: 'ACTIVA', inactiva: 'INACTIVA', perdida: 'PERDIDA' })[card.status] || 'SIN ESTADO');
    const edit = el('button', 'edit-card', '✎'); edit.type = 'button';
    edit.setAttribute('aria-label', `Editar ${card.name}`); edit.addEventListener('click', () => openEditor(card.id));
    side.append(statusNode, edit); item.append(badge, body, side); list.append(item);
  });
}
function openEditor(id = null, prefill = null) {
  resetIdle();
  const existing = state.cards.find(c => c.id === id);
  const src = existing || prefill || {};
  state.editing = existing ? existing.id : null;
  $('card-dialog-title').textContent = existing ? 'Editar tarjeta' : 'Nueva tarjeta';
  $('field-name').value = src.name || '';
  $('field-owner').value = src.owner || '';
  $('field-uid').value = src.uid || '';
  $('field-tech').value = src.tech && [...$('field-tech').options].some(o => o.value === src.tech) ? src.tech : 'Desconocida';
  $('field-zone').value = src.zone || '';
  $('field-status').value = src.status || 'activa';
  $('field-notes').value = src.notes || '';
  $('delete-card').classList.toggle('hidden', !existing);
  $('card-dialog').showModal();
}
async function saveCard(event) {
  event.preventDefault();
  const name = $('field-name').value.trim();
  if (!name) return notify('Introduce un nombre para la tarjeta.');
  const now = new Date().toISOString();
  const card = {
    id: state.editing || crypto.randomUUID(),
    name, owner: $('field-owner').value.trim(), uid: $('field-uid').value.trim(),
    tech: $('field-tech').value, zone: $('field-zone').value.trim(),
    status: $('field-status').value, notes: $('field-notes').value.trim(), updatedAt: now
  };
  const before = state.cards.slice();
  if (state.editing) state.cards = state.cards.map(c => c.id === state.editing ? { ...c, ...card } : c);
  else state.cards.unshift({ ...card, createdAt: now });
  if (await persist(() => { state.cards = before; }, 'Tarjeta guardada de forma cifrada.')) {
    $('card-dialog').close(); render(); resetIdle();
  }
}
async function deleteCard() {
  const card = state.cards.find(c => c.id === state.editing);
  if (!card || !(await askConfirm(`¿Eliminar «${card.name}» del inventario? Esto NO revoca su acceso en la cerradura.`, 'Eliminar'))) return;
  const before = state.cards.slice();
  state.cards = state.cards.filter(c => c.id !== card.id);
  if (await persist(() => { state.cards = before; }, 'Ficha eliminada del inventario.')) { $('card-dialog').close(); render(); resetIdle(); }
}

/* ---------- Lector: estado y escaneo ---------- */
function renderReader() {
  const status = $('reader-status');
  if (HAS_WEB_NFC) {
    status.dataset.state = 'ok';
    $('reader-text').textContent = 'Web NFC disponible: lectura NDEF directa.';
    $('reader-eyebrow').textContent = 'WEB NFC ACTIVO';
    $('scan-label').textContent = 'Escanear NFC';
    $('webnfc-steps').classList.remove('hidden');
  } else {
    status.dataset.state = 'off';
    $('reader-text').textContent = IS_IOS
      ? 'El navegador del iPhone no tiene acceso al lector NFC (limitación de iOS).'
      : 'Este navegador no ofrece Web NFC.';
    $('reader-eyebrow').textContent = IS_IOS ? "iOS · VÍA APP" : "SIN WEB NFC";
    $('scan-label').textContent = 'Escanear NFC';
    $('ios-steps').classList.remove('hidden');
  }
}
function decodeWebRecord(r) {
  try {
    if (r.recordType === 'empty') return null;
    if (r.recordType === 'text') return { type: 'text', value: new TextDecoder(r.encoding || 'utf-8').decode(r.data), lang: r.lang || '' };
    if (r.recordType === 'url' || r.recordType === 'absolute-url') return { type: 'url', value: dec.decode(r.data) };
    if (r.recordType === 'mime' && /^(text\/|application\/json)/.test(r.mediaType || '')) return { type: `mime ${r.mediaType}`, value: dec.decode(r.data) };
    return { type: r.recordType + (r.mediaType ? ` ${r.mediaType}` : ''), value: r.data ? bytesToHex(new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength)) : '' };
  } catch (e) { return { type: r.recordType, value: '(no decodificable)' }; }
}
function webNfcReadOnce(timeoutMs = 30000) {
  return new Promise(async (resolve, reject) => {
    const ctrl = new AbortController();
    const reader = new NDEFReader();
    const timer = setTimeout(() => { ctrl.abort(); reject(new Error('Tiempo agotado: no se detectó ninguna tarjeta.')); }, timeoutMs);
    reader.onreading = ev => { clearTimeout(timer); ctrl.abort(); resolve(ev); };
    reader.onreadingerror = () => { clearTimeout(timer); ctrl.abort(); reject(new Error('La tarjeta se detectó, pero no tiene NDEF legible (puede estar cifrada o no ser compatible).')); };
    try { await reader.scan({ signal: ctrl.signal }); }
    catch (err) { clearTimeout(timer); reject(err); }
  });
}
function setScanning(on, label) {
  $('scan-button').classList.toggle('scanning', on);
  $('scan-label').textContent = on ? (label || 'Acerca la tarjeta…') : 'Escanear NFC';
}
async function onScanButton() {
  resetIdle();
  if (!HAS_WEB_NFC) { openImport(); return; }
  setScanning(true);
  try {
    const ev = await webNfcReadOnce();
    const records = Array.from(ev.message?.records || []).map(decodeWebRecord).filter(Boolean);
    const scan = P.fromWebNfc(ev.serialNumber, records);
    await addScan(scan);
  } catch (err) {
    notify(err.name === 'NotAllowedError' ? 'Permiso NFC denegado en el navegador.' : (err.message || 'No se pudo leer la tarjeta.'));
  } finally { setScanning(false); }
}

/* ---------- Importar informes ---------- */
function openImport() {
  resetIdle();
  $('import-text').value = '';
  $('import-label').value = '';
  $('import-dialog').showModal();
}
async function readReportFile(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > 8000000) return notify('El archivo es demasiado grande.');
  try {
    if (/\.(bin|mfd|dump)$/i.test(file.name)) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const lines = [];
      for (let i = 0; i < bytes.length && i < 4096; i += 4) lines.push(`[${(i / 4).toString(16).padStart(2, '0').toUpperCase()}] ${bytesToHex(bytes.subarray(i, i + 4))}`);
      $('import-text').value = `Volcado binario: ${file.name} (${bytes.length} bytes)\n${lines.join('\n')}`;
    } else {
      $('import-text').value = (await file.text()).slice(0, 200000);
    }
    if (!$('import-label').value) $('import-label').value = file.name.replace(/\.[a-z0-9]+$/i, '').slice(0, 80);
    notify('Archivo cargado. Revisa y pulsa «Analizar y guardar».');
  } catch (err) { notify('No se pudo leer el archivo.'); }
}
async function submitImport(event) {
  event.preventDefault();
  const text = $('import-text').value;
  if (text.trim().length < 6) return notify('Pega el informe de lectura o elige un archivo.');
  const scan = P.parseReport(text, { source: $('import-source').value, label: $('import-label').value.trim() || undefined });
  if (!scan.uid && scan.family === 'unknown' && !scan.ndef.length && !scan.memory.length) {
    const go = await askConfirm('No se ha reconocido ningún dato NFC (UID, chip, NDEF o memoria). ¿Guardarlo igualmente como informe sin analizar?', 'Guardar');
    if (!go) return;
  }
  $('import-dialog').close();
  await addScan(scan);
}
function previousScanFor(scan) {
  if (!scan.uid) return null;
  return state.scans.find(s => s.id !== scan.id && s.uid === scan.uid) || null;
}
async function addScan(scan) {
  if (scan.raw && scan.raw.length > MAX_RAW_STORED) scan.raw = scan.raw.slice(0, MAX_RAW_STORED) + '\n… (recortado)';
  const prev = previousScanFor(scan);
  if (prev) {
    const diff = P.compareNdef(prev.ndef, scan.ndef);
    scan.compare = { withId: prev.id, withDate: prev.createdAt, added: diff.added.length, removed: diff.removed.length, same: diff.same };
    if (prev.pendingEdit) {
      const v = P.compareNdef(prev.pendingEdit.records, scan.ndef);
      scan.compare.verified = v.same;
      scan.compare.expected = prev.pendingEdit.records.length;
    }
  }
  const before = state.scans.slice();
  state.scans.unshift(scan);
  if (await persist(() => { state.scans = before; }, 'Lectura guardada cifrada en el historial.')) {
    render(); openScan(scan.id);
  }
}

/* ---------- Historial ---------- */
const STATE_LABEL = { ok: 'Disponible', partial: 'Parcial / según la tarjeta', no: 'No disponible' };
function renderScans() {
  const query = normalize($('scan-search').value);
  const list = $('scans-list');
  list.replaceChildren();
  const filtered = state.scans.filter(s => [s.label, s.uid, s.chip, s.tech, s.source, ...(s.ndef || []).map(r => r.value)].some(v => normalize(v).includes(query)));
  $('scans-empty').classList.toggle('hidden', state.scans.length > 0);
  if (!filtered.length && state.scans.length) list.append(el('p', 'muted pad', 'No hay lecturas que coincidan.'));
  filtered.forEach(scan => {
    const item = el('button', 'access-card scan-item'); item.type = 'button';
    const fam = P.FAMILIES[scan.family] || P.FAMILIES.unknown;
    const badge = el('div', 'card-badge', '◎'); badge.setAttribute('aria-hidden', 'true');
    const body = el('div', 'card-main');
    body.append(el('div', 'card-name', scan.label || fam.name),
      el('div', 'card-detail', `${fmtDate(scan.createdAt)} · ${scan.source || ''}`),
      el('div', 'card-uid', scan.uid ? `UID: ${scan.uid}` : (scan.chip || fam.name)));
    const write = (scan.operations || []).find(o => o.id === 'ndefWrite');
    const side = el('div', 'card-side');
    side.append(el('span', `status ${write?.state === 'ok' ? 'activa' : write?.state === 'partial' ? 'inactiva' : 'perdida'}`,
      write?.state === 'ok' ? 'EDITABLE' : write?.state === 'partial' ? 'LIMITADA' : 'SOLO LECTURA'));
    item.append(badge, body, side);
    item.addEventListener('click', () => openScan(scan.id));
    list.append(item);
  });
}
function kv(list, k, v, mono) {
  if (!v) return;
  const dt = el('dt', '', k); const dd = el('dd', mono ? 'mono' : '', v);
  list.append(dt, dd);
}
function openScan(id) {
  resetIdle();
  const scan = state.scans.find(s => s.id === id);
  if (!scan) return;
  state.currentScan = scan.id;
  const fam = P.FAMILIES[scan.family] || P.FAMILIES.unknown;
  $('scan-title').textContent = scan.label || fam.name;
  $('scan-eyebrow').textContent = `RESULTADO · ${fmtDate(scan.createdAt).toUpperCase()}`;
  const info = $('scan-info'); info.replaceChildren();
  kv(info, 'Tecnología', fam.name);
  kv(info, 'Chip (según el informe)', scan.chip);
  kv(info, 'Fabricante', scan.manufacturer);
  kv(info, 'UID', scan.uid || 'No disponible en el informe', !!scan.uid);
  kv(info, 'Estándar', scan.tech && scan.tech !== fam.standard ? `${scan.tech} · ${fam.standard}` : fam.standard);
  kv(info, 'Tipo NFC Forum', fam.forum);
  kv(info, 'Memoria', scan.size);
  kv(info, 'Qué se puede leer', fam.read);
  kv(info, 'Escritura', fam.write);
  kv(info, 'Origen', scan.source);

  const cmp = $('scan-compare');
  cmp.classList.toggle('hidden', !scan.compare);
  cmp.className = 'compare' + (scan.compare ? '' : ' hidden');
  if (scan.compare) {
    const c = scan.compare;
    let msg = c.same ? `Sin cambios en el NDEF respecto a la lectura del ${fmtDate(c.withDate)}.`
      : `Cambios respecto a la lectura del ${fmtDate(c.withDate)}: ${c.added} registro(s) nuevo(s), ${c.removed} eliminado(s).`;
    if (c.verified === true) { msg = `✓ Escritura verificada: la tarjeta contiene exactamente los ${c.expected} registro(s) editados. ` + msg; cmp.classList.add('ok'); }
    else if (c.verified === false) { msg = '✗ La nueva lectura NO coincide con la edición pendiente. ' + msg; cmp.classList.add('bad'); }
    cmp.textContent = msg;
  }

  const ops = $('scan-ops'); ops.replaceChildren();
  (scan.operations || []).forEach(o => {
    const li = el('li', `op ${o.state}`);
    li.append(el('span', 'op-dot'), el('span', 'op-label', o.label), el('span', 'op-state', STATE_LABEL[o.state] || o.state));
    ops.append(li);
  });
  $('scan-note').textContent = fam.note;

  const nd = $('scan-ndef'); nd.replaceChildren();
  if (!scan.ndef?.length) nd.append(el('p', 'muted', 'No se ha encontrado contenido NDEF en el informe.'));
  (scan.ndef || []).forEach((r, i) => {
    const box = el('div', 'ndef-record');
    box.append(el('div', 'ndef-type', `#${i + 1} · ${r.type === 'url' ? 'Enlace (URI)' : r.type === 'text' ? 'Texto' : r.type}`), el('div', 'ndef-value', r.value));
    nd.append(box);
  });
  const mem = (scan.memory || []).map(p => `${p.index.toString(16).padStart(3, '0').toUpperCase()}  ${p.hex}`).join('\n');
  $('scan-memory-box').classList.toggle('hidden', !mem);
  $('scan-memory').textContent = mem;
  const det = $('scan-details'); det.replaceChildren();
  (scan.details || []).forEach(d => kv(det, d.k, d.v));
  $('scan-raw').textContent = scan.raw || '';
  const writable = (scan.operations || []).find(o => o.id === 'ndefWrite')?.state !== 'no';
  $('scan-edit').classList.toggle('hidden', !writable);
  if (!$('scan-dialog').open) $('scan-dialog').showModal();
}
function familyToTech(f) {
  return ({ ntag: 'NTAG', ultralight: 'MIFARE Ultralight', ultralight_c: 'MIFARE Ultralight', classic: 'MIFARE Classic', plus: 'MIFARE Plus', desfire: 'MIFARE DESFire', type4: 'ISO 14443-4', iso15693: 'ISO 15693', felica: 'FeliCa' })[f] || 'Otra';
}
function scanToCard() {
  const scan = state.scans.find(s => s.id === state.currentScan);
  if (!scan) return;
  $('scan-dialog').close();
  openEditor(null, { name: scan.label, uid: scan.uid, tech: familyToTech(scan.family), notes: `Creada desde la lectura del ${fmtDate(scan.createdAt)} (${scan.source}).` });
}
async function deleteScan() {
  const scan = state.scans.find(s => s.id === state.currentScan);
  if (!scan || !(await askConfirm('¿Eliminar esta lectura del historial?', 'Eliminar'))) return;
  const before = state.scans.slice();
  state.scans = state.scans.filter(s => s.id !== scan.id);
  if (await persist(() => { state.scans = before; }, 'Lectura eliminada.')) { $('scan-dialog').close(); render(); }
}
function scanReport(scan) {
  const fam = P.FAMILIES[scan.family] || P.FAMILIES.unknown;
  return [
    `NFC Control · ${scan.label || fam.name}`, `Fecha: ${fmtDate(scan.createdAt)}`, `Origen: ${scan.source}`,
    `Tecnología: ${fam.name}`, `Chip: ${scan.chip || '-'}`, `UID: ${scan.uid || '-'}`, `Estándar: ${fam.standard}`,
    '', 'Operaciones:', ...(scan.operations || []).map(o => `- ${o.label}: ${STATE_LABEL[o.state]}`),
    '', 'NDEF:', ...((scan.ndef || []).length ? scan.ndef.map((r, i) => `#${i + 1} ${r.type}: ${r.value}`) : ['(vacío)'])
  ].join('\n');
}

/* ---------- Editor NDEF ---------- */
function editorRow(record) {
  const row = el('div', 'editor-record');
  const sel = el('select'); sel.setAttribute('aria-label', 'Tipo de registro');
  [['text', 'Texto'], ['url', 'Enlace']].forEach(([v, l]) => { const o = el('option', '', l); o.value = v; sel.append(o); });
  sel.value = record.type === 'url' ? 'url' : 'text';
  const input = el('textarea'); input.rows = 2; input.maxLength = 900; input.value = record.value || '';
  input.setAttribute('aria-label', 'Contenido del registro');
  const del = el('button', 'icon-button', '×'); del.type = 'button'; del.setAttribute('aria-label', 'Quitar registro');
  del.addEventListener('click', () => { row.remove(); validateEditor(); });
  sel.addEventListener('change', validateEditor); input.addEventListener('input', validateEditor);
  row.append(sel, input, del);
  return row;
}
function editorRecords() {
  return $$('#editor-records .editor-record').map(row => ({ type: row.querySelector('select').value, value: row.querySelector('textarea').value.trim() }));
}
function validateEditor() {
  const records = editorRecords();
  const errors = records.map((r, i) => { const e = P.validateRecord(r); return e ? `Registro ${i + 1}: ${e}` : ''; }).filter(Boolean);
  if (!records.length) errors.push('Añade al menos un registro.');
  const size = P.ndefSize(records);
  $('editor-size').textContent = `≈ ${size} bytes`;
  $('editor-errors').textContent = errors.join(' ');
  $('editor-write').disabled = errors.length > 0;
  $('editor-copy').disabled = errors.length > 0;
  return errors.length === 0;
}
function openNdefEditor() {
  const scan = state.scans.find(s => s.id === state.currentScan);
  if (!scan) return;
  $('scan-dialog').close();
  const box = $('editor-records'); box.replaceChildren();
  const editable = (scan.ndef || []).filter(r => r.type === 'text' || r.type === 'url');
  const lost = (scan.ndef || []).length - editable.length;
  (editable.length ? editable : [{ type: 'text', value: '' }]).forEach(r => box.append(editorRow(r)));
  const op = (scan.operations || []).find(o => o.id === 'ndefWrite');
  $('editor-warning').textContent = [
    op?.state === 'partial' ? 'Esta tecnología solo admite escritura en algunos casos: puede que la tarjeta la rechace.' : '',
    lost > 0 ? `${lost} registro(s) de otro tipo no se pueden editar aquí y se perderán al escribir.` : '',
    'Solo se escribe el mensaje NDEF. Nunca se tocan sectores protegidos ni datos cifrados.'
  ].filter(Boolean).join(' ');
  $('editor-write').classList.toggle('hidden', !HAS_WEB_NFC);
  $('editor-ios').classList.toggle('hidden', HAS_WEB_NFC);
  validateEditor();
  $('editor-dialog').showModal();
}
async function savePendingEdit(records) {
  const scan = state.scans.find(s => s.id === state.currentScan);
  if (!scan) return;
  const before = JSON.stringify(scan.pendingEdit || null);
  scan.pendingEdit = { records, at: new Date().toISOString() };
  await persist(() => { scan.pendingEdit = JSON.parse(before); });
}
async function copyEditor() {
  if (!validateEditor()) return;
  const records = editorRecords();
  await savePendingEdit(records);
  await copyText(records.map(r => r.value).join('\n'), 'Registros copiados. Pégalos en NFC Tools → Escribir.');
}
async function writeEditor(event) {
  event.preventDefault();
  if (!HAS_WEB_NFC || !validateEditor()) return;
  const scan = state.scans.find(s => s.id === state.currentScan);
  const records = editorRecords();
  $('editor-dialog').close();
  setScanning(true, 'Acerca la tarjeta original…');
  try {
    const first = await webNfcReadOnce();
    if (scan?.uid && P.cleanHex(first.serialNumber) !== scan.uid) throw new Error('Es otra tarjeta: el UID no coincide con la lectura original. No se ha escrito nada.');
    await new NDEFReader().write({ records: records.map(r => ({ recordType: r.type, data: r.value })) }, { overwrite: true });
    await savePendingEdit(records);
    setScanning(true, 'Escrito. Acércala otra vez para comprobar…');
    const check = await webNfcReadOnce();
    const readBack = Array.from(check.message?.records || []).map(decodeWebRecord).filter(Boolean);
    const verify = P.fromWebNfc(check.serialNumber, readBack);
    verify.source = 'Web NFC (verificación tras escribir)';
    verify.label = scan?.label || verify.label;
    await addScan(verify);
  } catch (err) {
    notify(err.name === 'NotAllowedError' ? 'La tarjeta es de solo lectura o el permiso NFC fue denegado.' : (err.message || 'No se pudo escribir.'));
  } finally { setScanning(false); }
}

/* ---------- Ajustes ---------- */
async function renderSettings() {
  const dl = $('diagnostics'); dl.replaceChildren();
  const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  kv(dl, 'Web NFC', HAS_WEB_NFC ? 'Disponible (lectura y escritura NDEF)' : (IS_IOS ? 'No disponible: iOS no lo permite en ningún navegador' : 'No disponible en este navegador'));
  kv(dl, 'Plataforma', IS_IOS ? 'iOS / iPadOS (WebKit)' : (navigator.userAgentData?.platform || navigator.platform || 'Desconocida'));
  kv(dl, 'Contexto seguro (HTTPS)', window.isSecureContext ? 'Sí' : 'No');
  kv(dl, 'Abierta como app (PWA)', standalone ? 'Sí' : 'No (Safari → Compartir → Añadir a pantalla de inicio)');
  kv(dl, 'Lecturas / fichas', `${state.scans.length} / ${state.cards.length}`);
  kv(dl, 'Tamaño de la bóveda', `${Math.round(((localStorage.getItem(STORE) || '').length) / 1024)} KB`);
  try {
    if (navigator.storage?.persisted) {
      const p = await navigator.storage.persisted();
      kv(dl, 'Almacenamiento protegido', p ? 'Sí' : 'No (el navegador podría borrarlo)');
      $('persist-state').textContent = p ? 'Ya está protegido' : 'Pide al navegador que no borre los datos';
    }
    if (navigator.storage?.estimate) {
      const e = await navigator.storage.estimate();
      if (e.quota) kv(dl, 'Espacio usado del navegador', `${Math.round((e.usage || 0) / 1024)} KB de ${Math.round(e.quota / 1048576)} MB`);
    }
  } catch (e) { /* sin API de almacenamiento */ }
  const prefs = getPrefs();
  $('lock-delay-state').textContent = prefs.lockDelay === 0 ? 'Inmediato al salir de la web' : 'Tras 2 minutos fuera (para copiar desde la app lectora)';

  const table = $('compat-table'); table.replaceChildren();
  Object.entries(P.FAMILIES).filter(([k]) => k !== 'unknown').forEach(([, f]) => {
    const row = el('div', 'compat-row');
    row.append(el('strong', '', f.name), el('span', 'muted small', `${f.forum} · ${f.standard}`), el('p', '', `Lectura: ${f.read}`), el('p', '', `Escritura: ${f.write}`));
    table.append(row);
  });
}
async function requestPersist() {
  try {
    const ok = await navigator.storage?.persist?.();
    notify(ok ? 'El navegador protegerá los datos de esta web.' : 'El navegador no lo ha concedido. Haz copias de seguridad con regularidad.');
  } catch (e) { notify('Este navegador no permite proteger el almacenamiento.'); }
  renderSettings();
}
async function clearScans() {
  if (!state.scans.length) return notify('El historial ya está vacío.');
  if (!(await askConfirm(`¿Eliminar las ${state.scans.length} lecturas del historial? No se puede deshacer.`, 'Borrar todo'))) return;
  const before = state.scans.slice();
  state.scans = [];
  if (await persist(() => { state.scans = before; }, 'Historial borrado.')) { render(); renderSettings(); }
}
function toggleLockDelay() {
  const p = getPrefs();
  p.lockDelay = p.lockDelay === 0 ? 120000 : 0;
  setPrefs(p);
  renderSettings();
}

/* ---------- Copias de seguridad ---------- */
function downloadBackup() {
  try {
    const vault = getVault();
    if (!vault) return notify('Aún no hay datos para exportar.');
    const blob = new Blob([JSON.stringify(vault, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `nfc-control-copia-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    notify('Copia cifrada creada. Guárdala en un lugar seguro.');
  } catch (err) { notify('No se pudo exportar la copia.'); }
}
async function readBackup(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > MAX_VAULT_B64 + 10000) return notify('La copia es demasiado grande.');
  try {
    const payload = JSON.parse(await file.text()); checkVault(payload);
    if (!(await askConfirm('¿Restaurar esta copia? Sustituirá TODAS las tarjetas y lecturas actuales de este navegador. Necesitarás la contraseña original de la copia.', 'Restaurar'))) return;
    localStorage.setItem(STORE, JSON.stringify(payload));
    lockVault();
    notify('Copia restaurada. Introduce la contraseña de esa copia.');
  } catch (err) { notify('Archivo inválido o no se pudo guardar.'); }
}

/* ---------- Arranque ---------- */
async function main() {
  if (!crypto?.subtle || !window.isSecureContext) {
    show('setup');
    $('setup-form').replaceChildren(el('p', 'notice', 'Esta web necesita HTTPS para proteger tu información. Publícala en GitHub Pages o usa localhost.'));
    return;
  }
  try { show(getVault() ? 'unlock' : 'setup'); }
  catch (err) { show('setup'); notify('Bóveda dañada. Restaura una copia desde otro navegador seguro.'); }
  renderReader();
  $('setup-form').addEventListener('submit', async event => {
    event.preventDefault();
    const password = $('setup-password').value;
    if (password.length < 10) return notify('Usa una contraseña de al menos 10 caracteres.');
    if (password !== $('setup-confirm').value) return notify('Las contraseñas no coinciden.');
    if (localStorage.getItem(STORE)) return notify('Ya existe una bóveda. No se puede sobrescribir.');
    try {
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await makeKey(password, state.salt);
      state.cards = []; state.scans = [];
      await encryptVault();
      $('setup-password').value = ''; $('setup-confirm').value = '';
      show('dashboard'); showPanel('scan'); render(); resetIdle(); notify('Bóveda creada. Recuerda exportar una copia.');
    } catch (err) { state.key = null; state.salt = null; notify('No fue posible crear la bóveda en este navegador.'); }
  });
  $('unlock-form').addEventListener('submit', async event => {
    event.preventDefault();
    try { unlockIntoState(await decryptVault(getVault(), $('unlock-password').value)); }
    catch (err) { notify('Contraseña incorrecta o copia dañada.'); }
  });
  $$('.lock-button').forEach(b => b.addEventListener('click', lockVault));
  $$('.tab').forEach(t => t.addEventListener('click', () => showPanel(t.dataset.panel)));
  $$('.go-scan').forEach(b => b.addEventListener('click', () => showPanel('scan')));
  $$('.import-alt').forEach(b => b.addEventListener('click', openImport));
  $$('.close-dialog').forEach(b => b.addEventListener('click', () => b.closest('dialog').close()));
  $('scan-button').addEventListener('click', onScanButton);
  $('import-scan-button').addEventListener('click', openImport);
  $('import-form').addEventListener('submit', submitImport);
  $('import-file-button').addEventListener('click', () => $('report-input').click());
  $('report-input').addEventListener('change', readReportFile);
  $('scan-search').addEventListener('input', renderScans);
  $('scan-delete').addEventListener('click', deleteScan);
  $('scan-to-card').addEventListener('click', scanToCard);
  $('scan-copy').addEventListener('click', () => { const s = state.scans.find(x => x.id === state.currentScan); if (s) copyText(scanReport(s), 'Informe copiado.'); });
  $('scan-edit').addEventListener('click', openNdefEditor);
  $('editor-add-text').addEventListener('click', () => { $('editor-records').append(editorRow({ type: 'text', value: '' })); validateEditor(); });
  $('editor-add-url').addEventListener('click', () => { $('editor-records').append(editorRow({ type: 'url', value: 'https://' })); validateEditor(); });
  $('editor-copy').addEventListener('click', copyEditor);
  $('editor-form').addEventListener('submit', writeEditor);
  $('add-button').addEventListener('click', () => openEditor());
  $('empty-add').addEventListener('click', () => openEditor());
  $('close-dialog').addEventListener('click', () => $('card-dialog').close());
  $('cancel-card').addEventListener('click', () => $('card-dialog').close());
  $('delete-card').addEventListener('click', deleteCard);
  $('card-form').addEventListener('submit', saveCard);
  $('search-input').addEventListener('input', renderCards);
  $('filter-status').addEventListener('change', renderCards);
  $('export-button').addEventListener('click', downloadBackup);
  $('import-button').addEventListener('click', () => $('backup-input').click());
  $('import-locked').addEventListener('click', () => $('backup-input').click());
  $('import-first').addEventListener('click', () => $('backup-input').click());
  $('backup-input').addEventListener('change', readBackup);
  $('persist-button').addEventListener('click', requestPersist);
  $('clear-scans').addEventListener('click', clearScans);
  $('lock-delay-button').addEventListener('click', toggleLockDelay);
  ['click', 'keydown', 'touchstart'].forEach(name => document.addEventListener(name, resetIdle, { passive: true }));
  // Al salir de la web (por ejemplo para copiar el informe en la app lectora) se bloquea según la preferencia.
  document.addEventListener('visibilitychange', () => {
    if (!state.key) return;
    const delay = getPrefs().lockDelay;
    if (document.hidden) { state.hiddenAt = Date.now(); if (delay === 0) lockVault(); }
    else if (state.hiddenAt && Date.now() - state.hiddenAt > delay) lockVault();
  });
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    window.addEventListener('load', () => navigator.serviceWorker.register('./sw.js').catch(() => {}));
  }
}
main();
