/* NFC Control · Sin red, sin dependencias, sin analíticas.
 * Importante: Safari no soporta Web NFC. Esta aplicación NO lee NFC físico.
 */
'use strict';

const STORE = 'nfc-control:vault:1';
const ITERATIONS = 240000;
const IDLE_MS = 5 * 60 * 1000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = id => document.getElementById(id);
const state = { cards: [], key: null, salt: null, editing: null, idleTimeout: null };
let toastTimeout;

function notify(message) {
  const element = $('toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => element.classList.remove('show'), 3600);
}
function bytesToB64(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 4096) {
    out += String.fromCharCode(...bytes.subarray(i, i + 4096));
  }
  return btoa(out);
}
function b64ToBytes(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
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
      obj.salt.length > 64 || obj.iv.length > 64 || obj.ciphertext.length > 2000000 ||
      b64ToBytes(obj.salt).length !== 16 || b64ToBytes(obj.iv).length !== 12 || b64ToBytes(obj.ciphertext).length < 16) {
    throw new Error('Formato de bóveda no válido');
  }
}
async function decryptVault(vault, password) {
  checkVault(vault);
  const salt = b64ToBytes(vault.salt);
  const key = await makeKey(password, salt);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(vault.iv) },
    key, b64ToBytes(vault.ciphertext)
  );
  const payload = JSON.parse(dec.decode(plaintext));
  if (!payload || payload.version !== 1 || !Array.isArray(payload.cards) || payload.cards.length > 10000) {
    throw new Error('Datos incompatibles');
  }
  return { key, salt, cards: payload.cards };
}
async function encryptVault() {
  if (!state.key || !state.salt) throw new Error('La bóveda está bloqueada');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ version: 1, cards: state.cards }));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, plain);
  const vault = {
    version: 1,
    salt: bytesToB64(state.salt),
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(new Uint8Array(cipher))
  };
  localStorage.setItem(STORE, JSON.stringify(vault));
}
function show(screen) {
  $('setup-view').classList.toggle('hidden', screen !== 'setup');
  $('unlock-view').classList.toggle('hidden', screen !== 'unlock');
  $('dashboard-view').classList.toggle('hidden', screen !== 'dashboard');
}
function resetIdle() {
  if (!state.key) return;
  clearTimeout(state.idleTimeout);
  state.idleTimeout = setTimeout(lockVault, IDLE_MS);
}
function lockVault() {
  clearTimeout(state.idleTimeout);
  state.key = null;
  state.salt = null;
  state.cards = [];
  state.editing = null;
  if ($('card-dialog').open) $('card-dialog').close();
  $('unlock-password').value = '';
  show('unlock');
}
function unlockIntoState(data) {
  state.key = data.key;
  state.salt = data.salt;
  state.cards = data.cards;
  $('unlock-password').value = '';
  show('dashboard');
  render();
  resetIdle();
}
function normalize(value) { return String(value || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase(); }
function render() {
  $('metric-total').textContent = state.cards.length;
  $('metric-active').textContent = state.cards.filter(c => c.status === 'activa').length;
  $('metric-zones').textContent = new Set(state.cards.map(c => normalize(c.zone).trim()).filter(Boolean)).size;
  const query = normalize($('search-input').value);
  const status = $('filter-status').value;
  const filtered = state.cards
    .filter(c => (status === 'todos' || c.status === status) &&
      [c.name,c.owner,c.uid,c.zone,c.tech,c.notes].some(v => normalize(v).includes(query)))
    .sort((a,b) => (b.updatedAt || '').localeCompare(a.updatedAt || ''));
  const list = $('cards-list');
  list.replaceChildren();
  $('empty-state').classList.toggle('hidden', state.cards.length > 0 || query !== '' || status !== 'todos');
  if (!filtered.length && state.cards.length) {
    const nothing = document.createElement('p');
    nothing.className = 'muted';
    nothing.style.padding = '20px 5px';
    nothing.textContent = 'No se encontraron tarjetas con estos filtros.';
    list.append(nothing);
  }
  filtered.forEach(card => {
    const item = document.createElement('article'); item.className = 'access-card';
    const badge = document.createElement('div'); badge.className = 'card-badge'; badge.textContent = '▤'; badge.setAttribute('aria-hidden', 'true');
    const body = document.createElement('div'); body.className = 'card-main';
    const title = document.createElement('div'); title.className = 'card-name'; title.textContent = card.name || 'Sin nombre';
    const detail = document.createElement('div'); detail.className = 'card-detail';
    detail.textContent = [card.owner || 'Sin titular',card.zone || 'Sin zona'].join(' · ');
    const uid = document.createElement('div'); uid.className = 'card-uid'; uid.textContent = card.uid ? `REF: ${card.uid}` : `TECNOLOGÍA: ${card.tech || 'Desconocida'}`;
    body.append(title,detail,uid);
    const side = document.createElement('div'); side.className = 'card-side';
    const statusNode = document.createElement('span'); statusNode.className = `status ${['activa','inactiva','perdida'].includes(card.status) ? card.status : 'inactiva'}`;
    statusNode.textContent = ({activa:'ACTIVA',inactiva:'INACTIVA',perdida:'PERDIDA'})[card.status] || 'SIN ESTADO';
    const edit = document.createElement('button'); edit.className = 'edit-card'; edit.type = 'button'; edit.textContent = '✎';
    edit.setAttribute('aria-label',`Editar ${card.name}`); edit.addEventListener('click', () => openEditor(card.id));
    side.append(statusNode,edit); item.append(badge,body,side); list.append(item);
  });
}
function openEditor(id = null) {
  resetIdle();
  const existing = state.cards.find(c => c.id === id);
  state.editing = existing ? existing.id : null;
  $('card-dialog-title').textContent = existing ? 'Editar tarjeta' : 'Nueva tarjeta';
  $('field-name').value = existing?.name || '';
  $('field-owner').value = existing?.owner || '';
  $('field-uid').value = existing?.uid || '';
  $('field-tech').value = existing?.tech || 'Desconocida';
  $('field-zone').value = existing?.zone || '';
  $('field-status').value = existing?.status || 'activa';
  $('field-notes').value = existing?.notes || '';
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
    status: $('field-status').value, notes: $('field-notes').value.trim(),
    updatedAt: now
  };
  const before = state.cards.slice();
  if (state.editing) state.cards = state.cards.map(c => c.id === state.editing ? { ...c, ...card } : c);
  else state.cards.unshift({ ...card, createdAt: now });
  try {
    await encryptVault();
    $('card-dialog').close(); render(); resetIdle(); notify('Tarjeta guardada de forma cifrada.');
  } catch (err) {
    state.cards = before;
    notify('No se pudo guardar. Comprueba el espacio del navegador.');
  }
}
async function deleteCard() {
  const card = state.cards.find(c => c.id === state.editing);
  if (!card || !confirm(`¿Eliminar «${card.name}» del inventario? Esto NO revoca su acceso en la cerradura.`)) return;
  const before = state.cards.slice();
  state.cards = state.cards.filter(c => c.id !== card.id);
  try { await encryptVault(); $('card-dialog').close(); render(); resetIdle(); notify('Ficha eliminada del inventario.'); }
  catch (err) { state.cards = before; notify('No se pudo eliminar la ficha.'); }
}
function downloadBackup() {
  try {
    const vault = getVault();
    if (!vault) return notify('Aún no hay datos para exportar.');
    const blob = new Blob([JSON.stringify(vault,null,2)],{type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `nfc-control-copia-${new Date().toISOString().slice(0,10)}.json`;
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    notify('Copia cifrada creada. Guárdala en un lugar seguro.');
  } catch (err) { notify('No se pudo exportar la copia.'); }
}
async function readBackup(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > 2000000) return notify('La copia es demasiado grande.');
  try {
    const payload = JSON.parse(await file.text()); checkVault(payload);
    if (!confirm('¿Restaurar esta copia? Sustituirá TODAS las tarjetas actuales de este navegador. Necesitarás la contraseña original de la copia.')) return;
    localStorage.setItem(STORE,JSON.stringify(payload));
    lockVault();
    notify('Copia restaurada. Introduce la contraseña de esa copia.');
  } catch (err) { notify('Archivo inválido o no se pudo guardar.'); }
}
async function main() {
  if (!crypto?.subtle || !window.isSecureContext) {
    show('setup');
    $('setup-form').innerHTML = '<p class="notice">Esta web necesita HTTPS para proteger tu información. Publícala en GitHub Pages o usa localhost.</p>';
    return;
  }
  try { show(getVault() ? 'unlock' : 'setup'); }
  catch (err) { show('setup'); notify('Bóveda dañada. Restaura una copia desde otro navegador seguro.'); }
  $('setup-form').addEventListener('submit', async event => {
    event.preventDefault();
    const password = $('setup-password').value;
    if (password.length < 10) return notify('Usa una contraseña de al menos 10 caracteres.');
    if (password !== $('setup-confirm').value) return notify('Las contraseñas no coinciden.');
    if (localStorage.getItem(STORE)) return notify('Ya existe una bóveda. No se puede sobrescribir.');
    try {
      state.salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await makeKey(password,state.salt);
      state.cards = [];
      await encryptVault();
      $('setup-password').value='';$('setup-confirm').value='';
      show('dashboard'); render(); resetIdle(); notify('Bóveda creada. Recuerda exportar una copia.');
    } catch (err) { state.key=null; state.salt=null; notify('No fue posible crear la bóveda en este navegador.'); }
  });
  $('unlock-form').addEventListener('submit', async event => {
    event.preventDefault();
    try { const data = await decryptVault(getVault(), $('unlock-password').value); unlockIntoState(data); }
    catch (err) { notify('Contraseña incorrecta o copia dañada.'); }
  });
  $('lock-button').addEventListener('click',lockVault);
  $('add-button').addEventListener('click',()=>openEditor());
  $('empty-add').addEventListener('click',()=>openEditor());
  $('close-dialog').addEventListener('click',()=> $('card-dialog').close());
  $('cancel-card').addEventListener('click',()=> $('card-dialog').close());
  $('delete-card').addEventListener('click',deleteCard);
  $('card-form').addEventListener('submit',saveCard);
  $('search-input').addEventListener('input',render);
  $('filter-status').addEventListener('change',render);
  $('export-button').addEventListener('click',downloadBackup);
  $('import-button').addEventListener('click',()=> $('backup-input').click());
  $('import-locked').addEventListener('click',()=> $('backup-input').click());
  $('import-first').addEventListener('click',()=> $('backup-input').click());
  $('backup-input').addEventListener('change',readBackup);
  ['click','keydown','touchstart'].forEach(name => document.addEventListener(name, resetIdle, { passive:true }));
  document.addEventListener('visibilitychange',()=>{ if (document.hidden && state.key) lockVault(); });
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    window.addEventListener('load',()=> navigator.serviceWorker.register('./sw.js').catch(()=>{}));
  }
}
main();
