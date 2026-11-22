# NFC Control

**Historial cifrado de lecturas NFC y gestor privado de tarjetas de acceso, pensado para iPhone.** Web estática (PWA), gratuita, sin servidores, sin cuentas y sin analíticas.

> **Lo primero que debes saber:** en iPhone ningún navegador (ni Safari ni Chrome) puede usar el lector NFC, porque iOS no implementa Web NFC. Y una app propia con Core NFC no se puede instalar con un Apple ID gratuito. Por eso NFC Control funciona así: **la lectura física la hace una app gratuita que sí tiene permiso NFC** (NFC Tools o NFC TagInfo by NXP) y **NFC Control importa, analiza, guarda cifrado y verifica** esa lectura. En Chrome para Android, la misma web lee y escribe NDEF directamente.
>
> El análisis completo está en [docs/ANALISIS.md](docs/ANALISIS.md).

## Funciones

- **Escanear**: botón «Escanear NFC», estado real del lector del navegador e instrucciones. En iPhone abre la importación del informe; con Web NFC (Android) lee la tarjeta directamente.
- **Resultado de lectura**: tecnología, chip, fabricante, UID, estándar, tipo NFC Forum, contenido NDEF, memoria en hexadecimal, datos técnicos e informe original.
- **Operaciones disponibles**: para cada tarjeta indica qué se puede hacer (leer UID, leer y escribir NDEF, volcado de memoria, zonas cifradas) según su tecnología y su estado de bloqueo.
- **Editor NDEF**: registros de texto y enlace, con validación y estimación de tamaño. En Android escribe en la tarjeta (comprobando antes que es la misma por su UID) y la vuelve a leer para verificar. En iPhone copia los registros para escribirlos con NFC Tools y verifica el cambio cuando importas la nueva lectura.
- **Historial**: lecturas guardadas, búsqueda, comparación automática con lecturas anteriores de la misma tarjeta y creación de fichas desde una lectura.
- **Tarjetas**: inventario de fichas (nombre, titular, UID, tecnología, zona, estado, notas).
- **Ajustes**: copias de seguridad cifradas, protección del almacenamiento, bloqueo al salir, borrado del historial, diagnóstico del dispositivo y tabla de compatibilidad.

## Qué NO hace (a propósito)

- No lee NFC desde el navegador del iPhone (iOS no lo permite).
- No descifra ni prueba claves de MIFARE Classic, DESFire, Plus o FeliCa, ni accede a sectores protegidos.
- No clona ni emula tarjetas de acceso o de transporte.
- No activa ni revoca accesos en cerraduras: el estado de una ficha es solo administrativo.

La mayoría de llaves de hotel, gimnasio y edificio son MIFARE Classic o DESFire: con un iPhone verás su tecnología y su UID, pero su contenido está cifrado con claves del emisor. Las etiquetas que sí puedes leer y reescribir por completo son, por ejemplo, NTAG213/215/216.

## Uso desde el iPhone

### 1. Instalar las apps lectoras (gratis, una vez)
- [NFC Tools](https://apps.apple.com/app/id1252962749) (wakdev): leer, escribir NDEF y exportar volcados de memoria.
- [NFC TagInfo by NXP](https://apps.apple.com/app/id1246143596): identificación detallada de chips NXP (NTAG, MIFARE, ICODE) y comprobación de originalidad.
- Opcional: [NFC TagWriter by NXP](https://apps.apple.com/app/id1246143221) para escribir NDEF.

Las tres declaran «Datos no recopilados» en la App Store.

### 2. Abrir NFC Control
Abre `https://jmbernalstudio.github.io/NFC-control/` en Safari (o Chrome), crea tu contraseña de cifrado (mínimo 10 caracteres) y, si quieres, Compartir → **Añadir a pantalla de inicio**.

### 3. Leer una tarjeta
1. Abre NFC Tools → **Leer** (o TagInfo → **Scan**) y acerca la tarjeta a la parte superior trasera del iPhone.
2. Copia el informe:
   - **TagInfo**: activa *Full Scan* en ajustes, pestaña *Full Scan* → botón Compartir → *Guardar en Archivos* (o Copiar).
   - **NFC Tools**: mantén pulsados los datos para copiarlos, o exporta el volcado de memoria (`.txt`, `.hex`, `.bin`, `.nfc`).
3. Vuelve a NFC Control → **Escanear NFC** → pega el texto o pulsa *Elegir archivo…* → **Analizar y guardar**.

Si sales de la web menos de 2 minutos para copiar el informe, la bóveda sigue desbloqueada. Puedes cambiarlo a bloqueo inmediato en Ajustes.

### 4. Editar y escribir (solo tarjetas que lo admiten)
1. En el resultado pulsa **Editar NDEF**, modifica los registros y pulsa **Copiar registros**.
2. En NFC Tools → **Escribir** → *Añadir un registro* (Texto o URL) → pega → **Escribir** y acerca la tarjeta.
3. Vuelve a leer la tarjeta e impórtala: NFC Control mostrará **«✓ Escritura verificada»** si coincide con lo que editaste.

## Publicar en GitHub Pages

El repositorio ya tiene Pages activado. Tras fusionar los cambios en `main`:
1. Ve a **Settings → Pages** y comprueba *Deploy from a branch*, rama `main`, carpeta `/ (root)`.
2. Espera 1-2 minutos y abre `https://jmbernalstudio.github.io/NFC-control/`.
3. Si ya tenías la web instalada, ciérrala y ábrela dos veces para que el Service Worker cargue la versión nueva.

**Nunca subas a GitHub tus copias de seguridad ni informes de lectura**: el repositorio es público.

## Privacidad y seguridad

- Cifrado AES-GCM de 256 bits; clave derivada de tu contraseña con PBKDF2-SHA256 (240 000 iteraciones). Las tarjetas y lecturas solo se guardan cifradas en el almacenamiento local del navegador.
- Política de seguridad de contenidos con `connect-src 'none'`: la web no puede enviar datos a ningún servidor.
- Sin dependencias externas, sin CDN, sin trackers.
- Bloqueo automático tras 5 minutos de inactividad.
- No se puede recuperar la contraseña. Exporta copias cifradas desde Ajustes; Safari puede borrar los datos de webs que no visitas en semanas (usa «Proteger almacenamiento» y añade la web a la pantalla de inicio para reducir ese riesgo).
- GitHub Pages sirve los archivos y puede registrar tu IP al cargar la página. Apple ve la descarga de las apps lectoras desde la App Store.

## Desarrollo local

```bash
python3 -m http.server 8000
# abre http://localhost:8000/
```

Archivos: `index.html` (interfaz), `app.js` (bóveda, historial, editor, Web NFC), `nfc-parse.js` (análisis de informes y base de compatibilidad), `styles.css`, `sw.js` (funcionamiento sin conexión), `manifest.webmanifest`.

## Ampliación futura: app nativa

Si algún día decides pagar el Apple Developer Program (99 €/año) y tienes un Mac, una app SwiftUI con Core NFC podría leer directamente (UID, GET_VERSION, páginas de NTAG/Ultralight, versión de DESFire, bloques ISO 15693, IDm de FeliCa) y escribir NDEF sin pasar por otras apps, con los mismos límites de seguridad descritos arriba.
