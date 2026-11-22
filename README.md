# NFC Control · Gestor privado de tarjetas de acceso

**Web estática y gratuita, diseñada para iPhone.** Permite administrar un inventario de tarjetas de acceso sin publicar las fichas en ningún servidor.

## Funcionalidades

- Crear una bóveda cifrada con contraseña (AES-GCM 256 bits, clave derivada con PBKDF2-SHA256).
- Añadir, editar y borrar fichas: nombre, titular, referencia/UID introducida manualmente, tecnología, instalación/zona, estado y notas.
- Búsqueda, filtro de estado y estadísticas.
- Exportar e importar copias de seguridad cifradas en JSON.
- PWA opcional: añadir a pantalla de inicio y caché offline de los archivos estáticos tras la primera visita.
- Sin dependencias, sin trackers, sin CDN, sin analítica y sin llamadas de red voluntarias desde JavaScript.
- Auto-bloqueo tras 5 minutos de inactividad o al enviar la página a segundo plano.

## Qué NO puede hacer

- **Safari del iPhone NO admite Web NFC. Esta web no puede escanear, modificar, duplicar ni emular tarjetas NFC.**
- Cambiar el estado de una ficha **NO activa ni revoca** la autorización real en una puerta.
- No conecta con la electrónica de las cerraduras. Para abrir puertas de verdad hace falta una integración con un sistema autorizado compatible.
- No puede garantizar invisibilidad absoluta frente a Apple, GitHub o el proveedor de internet. El hosting puede registrar visitas; iOS controla el navegador.
- No se pueden recuperar contraseñas perdidas. El navegador puede eliminar su almacenamiento; crea y conserva copias cifradas.

## Publicación gratuita en GitHub Pages

1. En https://github.com/new crea un repositorio **público** llamado `nfc-control` (GitHub Pages gratuito requiere repositorio público).
2. Sube **los archivos de esta carpeta al nivel raíz del repositorio** (`index.html`, `app.js`, `styles.css`, `sw.js`, etc.), sin subir esta carpeta como subcarpeta.
3. En el repositorio abre **Settings > Pages**. En **Build and deployment** selecciona **Deploy from a branch**, `main` y `/ (root)`; guarda.
4. Visita `https://TU-USUARIO.github.io/nfc-control/` desde Safari.
5. Opcional: Safari > Compartir > **Añadir a pantalla de inicio** para abrirla con icono. Entra al sitio una vez con internet antes de desconectarte.

## Privacidad

El repositorio de GitHub Pages será **público**: solo contiene el código y estilos. **Nunca subas tus fichas, contraseñas ni copias JSON a GitHub.**

Las fichas se cifran en el navegador antes de almacenarse en `localStorage` de ese origen. Los datos no se incluyen en la URL ni se transfieren por el JavaScript de la web. GitHub sí sirve los archivos y puede registrar peticiones de red e IP; Apple/iOS tampoco es invisible desde un iPhone. El almacenamiento web puede estar sujeto a políticas de eliminación, copias del dispositivo y comportamiento de Safari. Guarda respaldos cifrados y no registres secretos de cerraduras ni claves maestras en las notas.

## Uso local en Mac

`python3 -m http.server 8000` dentro de esta carpeta y abre `http://localhost:8000/` en el Mac. Para utilizar Web Crypto en el iPhone es mejor publicarlo bajo HTTPS con GitHub Pages.

## Tecnología

HTML, CSS, JavaScript, Web Crypto API, Service Worker. Sin compilación, servidor de datos ni paquetes npm.
