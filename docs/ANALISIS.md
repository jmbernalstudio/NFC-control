# NFC Control · Análisis técnico para iPhone 17

Fecha del análisis: 22 de noviembre de 2026.

Este documento responde a una pregunta concreta: **qué se puede hacer de verdad con el lector NFC de un iPhone 17, gratis, sin servidores y sin aparentar funciones que no existen.**

## 1. Resumen

| Pregunta | Respuesta |
|---|---|
| ¿Puede una web (Safari o Chrome) usar el NFC del iPhone? | **No.** iOS no implementa Web NFC y obliga a todos los navegadores a usar WebKit. Chrome en iPhone tiene las mismas limitaciones que Safari. |
| ¿Puede una app nativa propia (Core NFC) leer y escribir tarjetas? | **Sí**, pero necesita la capacidad «NFC Tag Reading», que **no está disponible con un Apple ID gratuito** (equipo personal de Xcode). Hace falta el Apple Developer Program de pago (99 €/año) y un Mac con Xcode. |
| ¿AltStore, SideStore u otras vías de instalación lateral lo evitan? | **No.** Firman con el mismo certificado gratuito de Apple ID, que no puede incluir el permiso NFC. TrollStore y el jailbreak no existen para iOS 26 en un iPhone 17. |
| ¿Hay alguna forma gratuita y legal de leer NFC con el iPhone? | **Sí**: con apps gratuitas que ya tienen ese permiso, como **NFC Tools** (wakdev) y **NFC TagInfo by NXP** (de NXP, el fabricante de MIFARE y NTAG). Ambas declaran en la App Store «Datos no recopilados». |
| ¿Se pueden leer o copiar llaves de hotel, gimnasio o transporte? | Se puede ver la **tecnología y el UID**. El contenido de acceso está **cifrado con claves del emisor** (MIFARE Classic, DESFire, Plus, FeliCa con cifrado). iOS no da acceso a MIFARE Classic en absoluto. NFC Control no intenta eludir ninguna protección. |

**Arquitectura elegida (gratuita):** la lectura física la hace una app gratuita que sí tiene permiso NFC, y **NFC Control (esta web/PWA)** importa ese informe, identifica el chip, calcula qué operaciones son posibles, lo guarda **cifrado y en local**, prepara las ediciones NDEF y **verifica** el cambio al comparar una nueva lectura con la edición pendiente. En navegadores que sí tienen Web NFC (Chrome para Android) la misma web lee y escribe NDEF directamente.

## 2. Limitaciones por plataforma

### Safari y Chrome en iOS
- No existe `NDEFReader` (Web NFC) en WebKit. Apple no lo ha implementado y no hay ajuste ni bandera para activarlo.
- En iOS todos los navegadores usan el motor WebKit, así que Chrome, Edge o Firefox en iPhone tampoco lo tienen.
- Una PWA instalada en la pantalla de inicio sigue siendo WebKit: tampoco accede al NFC.
- Sí funcionan Web Crypto (cifrado AES-GCM), `localStorage`, Service Worker (funcionamiento sin conexión) y el portapapeles, que es lo que usa NFC Control.

### Core NFC (app nativa)
- Permite `NFCTagReaderSession` (ISO 14443, ISO 15693, FeliCa) y `NFCNDEFReaderSession`.
- Requiere el *entitlement* `com.apple.developer.nfc.readersession.formats`. Xcode muestra para equipos gratuitos: *«Personal development teams … do not support the Near Field Communication Tag Reading capability»*. Un ingeniero de Apple lo confirma en el [foro de desarrolladores](https://developer.apple.com/forums/thread/730036).
- Con cuenta gratuita, además, la firma dura 7 días y hay un máximo de 3 apps.
- Conclusión: una app propia con NFC real exige pagar a Apple. Si en el futuro decides pagar, la app nativa es la mejora natural de este proyecto.

### Chrome en Android (referencia)
- Tiene Web NFC: lee el número de serie y el mensaje NDEF y escribe NDEF. No da acceso a comandos de bajo nivel, a MIFARE Classic ni a datos cifrados. NFC Control lo aprovecha automáticamente si se abre ahí.

## 3. Compatibilidad por tecnología (iPhone)

| Tecnología | Tipo NFC Forum | Lectura posible en iPhone | Escritura posible | Notas |
|---|---|---|---|---|
| NTAG 213/215/216 | Type 2 | UID, versión, memoria y NDEF | Sí (NDEF), si no está bloqueada ni con contraseña | Las etiquetas «en blanco» más habituales. Ideal para probar. |
| MIFARE Ultralight / EV1 | Type 2 | UID, páginas no protegidas, NDEF | Sí, en páginas no bloqueadas | Billetes de transporte desechables: suelen estar bloqueados. |
| MIFARE Ultralight C | Type 2 | UID y páginas no protegidas | Parcial | Zona protegida con 3DES. |
| MIFARE Classic 1K/4K | Ninguno | Como mucho el UID | No | iOS no soporta Crypto-1. Es la tecnología de muchas llaves de hotel, gimnasio y edificio. |
| MIFARE Plus | Ninguno | UID e identificación | No | Datos protegidos con AES. |
| MIFARE DESFire EV1/EV2/EV3 | Type 4 (si tiene NDEF) | UID, versión, a veces lista de aplicaciones y NDEF público | Solo NDEF libre | Acceso y transporte protegidos con AES/3DES. |
| ISO 14443-4 genérica | Type 4 | UID (a menudo aleatorio) y NDEF | Solo NDEF libre | Bancarias, DNI y pasaportes: no editables. |
| ISO 15693 (ICODE, ST25, Tag-it) | Type 5 | UID, información del sistema, bloques y NDEF | Sí, si no está bloqueada | Bibliotecas, forfaits de esquí. |
| FeliCa | Type 3 | IDm, PMm, servicios sin cifrar | Solo Lite-S / NDEF | Suica u Octopus muestran parte del historial; el saldo está protegido. |
| Topaz | Type 1 | No | No | Core NFC no lo admite. |

## 4. Qué hace NFC Control y qué no

**Hace**
1. Importa el informe real de NFC Tools o NFC TagInfo (texto pegado o archivo `.txt`, `.json`, `.xml`, `.hex`, `.nfc`, `.bin`), o lee directamente con Web NFC donde existe.
2. Identifica la familia del chip, el UID, el fabricante, el estándar y el tipo NFC Forum.
3. Muestra el NDEF, la memoria en hexadecimal, los datos técnicos y el informe original.
4. Marca cada operación como disponible, parcial o no disponible según la tecnología y el estado de bloqueo.
5. Edita registros NDEF de texto y enlace con validación y una estimación del tamaño.
6. Escribe: en Android con Web NFC directamente (comprobando antes que es la misma tarjeta por el UID); en iPhone copia los registros para escribirlos con NFC Tools o NFC TagWriter.
7. Verifica: al importar una nueva lectura de la misma tarjeta, compara el NDEF con la edición pendiente y con la lectura anterior.
8. Guarda todo cifrado (AES-GCM 256, PBKDF2-SHA256 240 000 iteraciones) en el navegador, con copias de seguridad cifradas y sin peticiones de red (CSP `connect-src 'none'`).

**No hace**
- No lee el NFC desde el navegador del iPhone (imposible en iOS).
- No descifra, rompe ni prueba claves de MIFARE Classic, DESFire, Plus o FeliCa.
- No clona ni emula tarjetas de acceso o transporte.
- No cambia permisos en cerraduras: eso depende del sistema de control de accesos del edificio.

## 5. Privacidad

- Sin cuentas, sin analíticas, sin servidores propios. La web no puede hacer peticiones de red por su política de seguridad de contenidos.
- GitHub Pages sirve los archivos estáticos y puede registrar la IP al cargar la página. Después de la primera visita funciona sin conexión.
- iCloud: el almacenamiento de Safari no se sincroniza entre dispositivos. Las copias de seguridad son archivos cifrados que tú decides dónde guardar.
- Las apps lectoras se instalan desde la App Store (no hay alternativa en iOS para apps con NFC) y declaran «Datos no recopilados»; esa declaración la hace el desarrollador y Apple no la verifica.

## 6. Opciones descartadas

| Opción | Motivo |
|---|---|
| PWA con Web NFC en iPhone | No existe en iOS. |
| App propia firmada con Apple ID gratuito | Xcode no permite NFC en equipos personales. |
| AltStore / SideStore | Mismo certificado gratuito, sin permiso NFC. |
| TrollStore / jailbreak | No disponible para iOS 26 en iPhone 17. |
| Atajos de iOS (automatización NFC) | Solo dispara una acción al detectar una etiqueta; no entrega su contenido. |
| Lector NFC externo | Descartado: requiere comprar hardware. |
| App propia con cuenta de pago | Viable técnicamente (99 €/año + Mac). Descartada por ahora por coste. |
