/* NFC Control · Análisis de informes de lectura NFC.
 * Convierte el informe que exporta una app de lectura real (NFC Tools, NFC TagInfo by NXP…)
 * o una lectura Web NFC en un registro estructurado, y calcula qué operaciones son posibles.
 * Sin red. Funciona en el navegador (window.NFCParse) y en Node (para las pruebas).
 */
'use strict';
(function (root) {
  const MAX_RAW = 200000;

  /* Base de conocimiento: qué permite cada familia de chip con un iPhone. */
  const FAMILIES = {
    ntag: {
      name: 'NXP NTAG 21x', forum: 'NFC Forum Type 2', standard: 'ISO/IEC 14443-A',
      read: 'UID, versión del chip, memoria de usuario y mensaje NDEF.',
      write: 'Sí, el mensaje NDEF si la etiqueta no está bloqueada ni protegida con contraseña.',
      ops: { uid: 'ok', ndefRead: 'ok', ndefWrite: 'ok', memory: 'ok', protected: 'partial' },
      note: 'Si la etiqueta tiene contraseña (PWD_AUTH), las páginas protegidas no se leen ni se escriben sin ella.'
    },
    ultralight: {
      name: 'MIFARE Ultralight / Ultralight EV1', forum: 'NFC Forum Type 2', standard: 'ISO/IEC 14443-A',
      read: 'UID, páginas de memoria no protegidas y NDEF si está formateada.',
      write: 'Sí, el NDEF o las páginas de usuario si no están bloqueadas.',
      ops: { uid: 'ok', ndefRead: 'ok', ndefWrite: 'ok', memory: 'ok', protected: 'partial' },
      note: 'Muchas tarjetas de transporte desechables usan Ultralight con páginas bloqueadas: se leen, pero no se pueden modificar.'
    },
    ultralight_c: {
      name: 'MIFARE Ultralight C', forum: 'NFC Forum Type 2', standard: 'ISO/IEC 14443-A',
      read: 'UID y páginas no protegidas por la autenticación 3DES.',
      write: 'Solo en páginas no protegidas y si la tarjeta lo permite.',
      ops: { uid: 'ok', ndefRead: 'ok', ndefWrite: 'partial', memory: 'partial', protected: 'no' },
      note: 'Las páginas protegidas requieren la clave 3DES del emisor.'
    },
    classic: {
      name: 'MIFARE Classic', forum: 'Sin tipo NFC Forum (propietario NXP)', standard: 'ISO/IEC 14443-A (cifrado Crypto-1)',
      read: 'En iPhone, como mucho el UID. iOS no da acceso a los sectores de MIFARE Classic.',
      write: 'No desde iPhone.',
      ops: { uid: 'partial', ndefRead: 'no', ndefWrite: 'no', memory: 'no', protected: 'no' },
      note: 'Es la tecnología más habitual en llaves de hotel, gimnasio y edificio. Su contenido está en sectores protegidos con claves del emisor: NFC Control no intenta obtenerlas ni eludirlas.'
    },
    plus: {
      name: 'MIFARE Plus', forum: 'Sin tipo NFC Forum', standard: 'ISO/IEC 14443-A (AES)',
      read: 'UID y datos de identificación del chip.',
      write: 'No sin las claves AES del emisor.',
      ops: { uid: 'ok', ndefRead: 'no', ndefWrite: 'no', memory: 'no', protected: 'no' },
      note: 'Los datos de control de acceso están cifrados con AES.'
    },
    desfire: {
      name: 'MIFARE DESFire', forum: 'NFC Forum Type 4 (si tiene aplicación NDEF)', standard: 'ISO/IEC 14443-4 / ISO 7816-4',
      read: 'UID, versión, y a veces la lista de aplicaciones y el NDEF público.',
      write: 'Solo el NDEF si existe una aplicación NDEF con escritura libre.',
      ops: { uid: 'ok', ndefRead: 'partial', ndefWrite: 'partial', memory: 'no', protected: 'no' },
      note: 'Las aplicaciones de acceso y transporte están protegidas con claves AES/3DES del emisor y no son accesibles.'
    },
    type4: {
      name: 'Tarjeta ISO-DEP / NFC Forum Type 4', forum: 'NFC Forum Type 4', standard: 'ISO/IEC 14443-4 / ISO 7816-4',
      read: 'UID (a menudo aleatorio) y el NDEF si la tarjeta lo expone.',
      write: 'Solo el NDEF si la tarjeta lo permite.',
      ops: { uid: 'partial', ndefRead: 'partial', ndefWrite: 'partial', memory: 'no', protected: 'no' },
      note: 'Bancarias, DNI, pasaportes y muchas tarjetas de transporte modernas son de este tipo; sus datos internos no son editables.'
    },
    iso15693: {
      name: 'ISO 15693 / NFC Forum Type 5 (ICODE, ST25, Tag-it)', forum: 'NFC Forum Type 5', standard: 'ISO/IEC 15693',
      read: 'UID, información del sistema, bloques no protegidos y NDEF.',
      write: 'Sí, bloques y NDEF si no están bloqueados ni protegidos.',
      ops: { uid: 'ok', ndefRead: 'ok', ndefWrite: 'ok', memory: 'ok', protected: 'partial' },
      note: 'Habitual en bibliotecas, esquís y algunas instalaciones. Las zonas con contraseña no son accesibles.'
    },
    felica: {
      name: 'Sony FeliCa', forum: 'NFC Forum Type 3', standard: 'JIS X 6319-4 / ISO 18092',
      read: 'IDm, PMm, códigos de sistema y servicios sin cifrar.',
      write: 'Solo FeliCa Lite-S / NDEF. Los servicios cifrados (monederos de transporte) no.',
      ops: { uid: 'ok', ndefRead: 'partial', ndefWrite: 'partial', memory: 'partial', protected: 'no' },
      note: 'Tarjetas como Suica u Octopus muestran parte del historial sin cifrar; el saldo y la escritura están protegidos.'
    },
    topaz: {
      name: 'Innovision Topaz / Broadcom', forum: 'NFC Forum Type 1', standard: 'ISO/IEC 14443-A',
      read: 'No compatible con iPhone.',
      write: 'No compatible con iPhone.',
      ops: { uid: 'no', ndefRead: 'no', ndefWrite: 'no', memory: 'no', protected: 'no' },
      note: 'Core NFC no admite NFC Forum Type 1.'
    },
    unknown: {
      name: 'Tecnología no identificada', forum: 'Desconocido', standard: 'Desconocido',
      read: 'Depende del chip. Revisa el informe original.',
      write: 'Desconocido.',
      ops: { uid: 'partial', ndefRead: 'partial', ndefWrite: 'partial', memory: 'partial', protected: 'no' },
      note: 'Si la tarjeta es de acceso o transporte, lo normal es que su contenido esté cifrado.'
    }
  };

  const OPS = [
    ['uid', 'Leer UID / identificador'],
    ['ndefRead', 'Leer mensaje NDEF'],
    ['ndefWrite', 'Escribir mensaje NDEF'],
    ['memory', 'Volcado de memoria no protegida'],
    ['protected', 'Sectores o aplicaciones cifradas']
  ];

  function detectFamily(text) {
    const t = String(text || '').toLowerCase();
    const has = re => re.test(t);
    if (has(/mifare\s*classic|classic\s*(1k|4k|ev1)|mini\s*0\.3k|\bmf1s|\bmf1ics/)) return 'classic';
    if (has(/desfire/)) return 'desfire';
    if (has(/mifare\s*plus/)) return 'plus';
    if (has(/ultralight\s*c\b|mf0icu2/)) return 'ultralight_c';
    if (has(/ntag\s*-?\s*(2\d\d|4\d\d|i2c)|\bntag\b/)) return 'ntag';
    if (has(/ultralight|mf0ul/)) return 'ultralight';
    if (has(/felica|\bidm\b/)) return 'felica';
    if (has(/icode|iso\s*\/?\s*(iec)?\s*15693|nfcv|type\s*5|st25t?v|tag-?it/)) return 'iso15693';
    if (has(/topaz|type\s*1\b/)) return 'topaz';
    if (has(/iso\s*\/?\s*(iec)?\s*14443-4|isodep|iso-dep|iso\s*7816|type\s*4/)) return 'type4';
    if (has(/type\s*2\b/)) return 'ntag';
    return 'unknown';
  }

  const KEY_PATTERNS = {
    uid: /^(uid|serial\s*number|n[uú]mero\s*de\s*serie|identifier|identificador|tag\s*id|id\s*de\s*etiqueta|idm)$/i,
    chip: /^(ic\s*type|tag\s*type|tipo\s*de\s*etiqueta|tipo\s*de\s*chip|chip|ic|product|producto|type|tipo)$/i,
    manufacturer: /^(ic\s*manufacturer|manufacturer|fabricante|vendor|tag\s*maker)$/i,
    tech: /^(technologies?\s*(available)?|tecnolog[ií]as?(\s*disponibles)?|protocol|protocolo|norma|nfc\s*forum|standard|est[aá]ndar)$/i,
    size: /^(memory\s*size|size|tamaño|memoria|capacity|capacidad|tamaño\s*de\s*memoria)$/i,
    writable: /^(writable|escribible|editable|writeable)$/i,
    locked: /^(locked|bloqueada|read[-\s]?only|solo\s*lectura)$/i,
    atqa: /^atqa$/i, sak: /^sak$/i, ats: /^ats$/i
  };

  const HEX_UID = /\b((?:[0-9a-f]{2}[:\s-]){3,9}[0-9a-f]{2}|[0-9a-f]{8,20})\b/i;

  function cleanHex(value) {
    const m = String(value || '').match(HEX_UID);
    if (!m) return '';
    const bytes = m[1].replace(/[^0-9a-f]/gi, '').toUpperCase();
    if (bytes.length % 2) return '';
    return bytes.match(/../g).join(':');
  }

  function parseKeyValues(lines) {
    const out = [];
    for (const raw of lines) {
      const line = raw.replace(/^[\s*•\-–#>]+/, '').trim();
      const m = line.match(/^([^:=]{1,40}?)\s*[:=]\s*(.+)$/);
      if (m && !/^https?$/i.test(m[1].trim())) out.push([m[1].trim(), m[2].trim()]);
    }
    return out;
  }

  function parseMemory(lines) {
    const pages = [];
    // Formatos habituales: "[00] * 04:A2:3B:C1", "p0 04 A2 3B C1", "0x00: 04 A2 3B C1", "Block 00: …"
    const re = /^\s*(?:\[\s*([0-9a-f]{1,3})\s*\]|(?:p(?:age|ágina|agina)?|b(?:lock|loque)?|sector)\s*\.?\s*([0-9a-f]{1,3})|0x([0-9a-f]{1,3})|([0-9a-f]{2,3}))\s*[:|*.\s]\s*[*!+.\s]*((?:[0-9a-f]{2}[\s:]?){4,16})/i;
    for (const line of lines) {
      const m = line.match(re);
      if (!m) continue;
      const idx = m[1] || m[2] || m[3] || m[4];
      const bytes = m[5].replace(/[^0-9a-f]/gi, '').toUpperCase().match(/../g) || [];
      if (bytes.length >= 4) pages.push({ index: parseInt(idx, 16), hex: bytes.join(' '), protected: /\?\?|xx|--/i.test(line) });
    }
    return pages.length >= 2 ? pages.slice(0, 1024) : [];
  }

  function parseNdef(text, lines) {
    const records = [];
    const seen = new Set();
    const add = r => { const k = r.type + '|' + r.value; if (!seen.has(k) && r.value) { seen.add(k); records.push(r); } };
    for (const url of String(text).match(/\b(?:https?:\/\/|mailto:|tel:|sms:|geo:)[^\s"'<>]+/gi) || []) add({ type: 'url', value: url.replace(/[),.;]+$/, '') });
    for (const [k, v] of parseKeyValues(lines)) {
      if (/^(text|texto|ndef\s*text|registro\s*de\s*texto|record\s*\d+\s*-?\s*text)/i.test(k)) add({ type: 'text', value: v });
      else if (/^(uri|url|link|enlace)$/i.test(k) && !/^https?:|mailto:|tel:/i.test(v)) add({ type: 'url', value: v });
    }
    return records.slice(0, 50);
  }

  function flattenJson(obj, prefix = '', out = []) {
    if (out.length > 4000) return out;
    if (Array.isArray(obj)) obj.forEach((v, i) => flattenJson(v, `${prefix}[${i}]`, out));
    else if (obj && typeof obj === 'object') Object.entries(obj).forEach(([k, v]) => flattenJson(v, prefix ? `${prefix}.${k}` : k, out));
    else if (obj !== null && obj !== undefined) out.push(`${prefix.split('.').pop().replace(/\[\d+\]$/, '')}: ${obj}`);
    return out;
  }

  function buildOperations(familyId, fields) {
    const fam = FAMILIES[familyId] || FAMILIES.unknown;
    const ops = OPS.map(([id, label]) => ({ id, label, state: fam.ops[id] }));
    const lockedFlag = /s[ií]|yes|true|bloquead|locked/i.test(fields.locked || '') || /^(no|false)$/i.test(fields.writable || '');
    if (lockedFlag) ops.find(o => o.id === 'ndefWrite').state = 'no';
    if (fields.uid && ops[0].state !== 'no') ops[0].state = 'ok';
    return ops;
  }

  /** Analiza un informe de texto o JSON exportado por una app de lectura NFC. */
  function parseReport(input, meta = {}) {
    let text = String(input || '').slice(0, MAX_RAW).replace(/\r\n?/g, '\n');
    let json = null;
    const trimmed = text.trim();
    if (/^[\[{]/.test(trimmed)) { try { json = JSON.parse(trimmed); } catch (e) { json = null; } }
    const lines = json ? flattenJson(json) : text.split('\n');
    const kv = parseKeyValues(lines);
    const fields = {};
    for (const [k, v] of kv) {
      for (const [field, re] of Object.entries(KEY_PATTERNS)) {
        if (!fields[field] && re.test(k.replace(/[_.]/g, ' ').trim())) fields[field] = v.slice(0, 200);
      }
    }
    if (fields.uid) fields.uid = cleanHex(fields.uid) || fields.uid;
    const family = detectFamily([fields.chip, fields.tech, text.slice(0, 20000)].join(' '));
    const memory = parseMemory(lines);
    const ndef = parseNdef(json ? lines.join('\n') : text, lines);
    const fam = FAMILIES[family];
    return {
      id: meta.id || (root.crypto && root.crypto.randomUUID ? root.crypto.randomUUID() : String(Date.now()) + Math.random().toString(16).slice(2)),
      createdAt: meta.createdAt || new Date().toISOString(),
      source: meta.source || 'Informe importado',
      label: meta.label || fam.name,
      family,
      uid: fields.uid || '',
      chip: fields.chip || '',
      manufacturer: fields.manufacturer || (/(^|:)04(:|$)/.test((fields.uid || '').slice(0, 3)) && family !== 'unknown' ? 'NXP Semiconductors (por el UID)' : ''),
      tech: fields.tech || fam.standard,
      size: fields.size || '',
      details: kv.slice(0, 80).map(([k, v]) => ({ k: k.slice(0, 60), v: v.slice(0, 300) })),
      ndef,
      memory,
      operations: buildOperations(family, fields),
      raw: text
    };
  }

  /** Convierte una lectura Web NFC (Android Chrome) en un registro. */
  function fromWebNfc(serialNumber, records) {
    const ndef = (records || []).map(r => ({ type: r.type, value: String(r.value || '').slice(0, 2000) }));
    const raw = [`UID: ${serialNumber || 'no disponible'}`, 'Fuente: Web NFC', ...ndef.map(r => `${r.type === 'url' ? 'URI' : r.type === 'text' ? 'Text' : r.type}: ${r.value}`)].join('\n');
    const rec = parseReport(raw, { source: 'Web NFC (lectura directa)' });
    rec.ndef = ndef;
    rec.operations.find(o => o.id === 'ndefRead').state = 'ok';
    return rec;
  }

  function compareNdef(before, after) {
    const key = r => `${r.type}|${r.value}`;
    const a = new Set((before || []).map(key)), b = new Set((after || []).map(key));
    return {
      added: (after || []).filter(r => !a.has(key(r))),
      removed: (before || []).filter(r => !b.has(key(r))),
      same: a.size === b.size && [...a].every(k => b.has(k))
    };
  }

  /** Comprueba un registro NDEF editado antes de escribirlo. */
  function validateRecord(r) {
    if (!r || !['text', 'url'].includes(r.type)) return 'Tipo de registro no admitido.';
    const v = String(r.value || '');
    if (!v.trim()) return 'El registro está vacío.';
    if (r.type === 'url' && !/^(https?:\/\/[^\s]+|mailto:[^\s]+|tel:\+?[0-9 ()-]+|sms:\+?[0-9]+|geo:-?[0-9.]+,-?[0-9.]+)$/i.test(v.trim())) return 'URL no válida (usa https://, mailto:, tel:, sms: o geo:).';
    if (new TextEncoder().encode(v).length > 860) return 'Demasiado largo: supera la capacidad de un NTAG216.';
    return '';
  }

  function ndefSize(records) {
    // Estimación del tamaño del mensaje NDEF (registros cortos) para comprobar la capacidad.
    let total = 0;
    for (const r of records) {
      const len = new TextEncoder().encode(r.value).length + (r.type === 'text' ? 3 : 1);
      total += 3 + (len > 255 ? 3 : 0) + len;
    }
    return total;
  }

  const api = { FAMILIES, OPS, parseReport, fromWebNfc, detectFamily, compareNdef, validateRecord, ndefSize, cleanHex };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.NFCParse = api;
})(typeof window !== 'undefined' ? window : globalThis);
