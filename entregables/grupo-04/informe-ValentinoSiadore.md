# Informe individual — Grupo 04

**Integrante:** Valentino Siadore (valentinosiadore) · **Fecha:** 01/11/2026
**Destinatario:** gerencia de operaciones / comité de crisis

**Caso:** la organización del laboratorio. No tenemos una organización asignada por
la cátedra, así que uso la misma que el resto del grupo: un portal de legajos del
personal hecho en PHP y publicado en Internet, una API en Node.js que usan las
aplicaciones de los clientes, un servicio interno en Python y una base de datos
(db01) que apareció en los registros pero no estaba inventariada.

> No ejecuté el laboratorio. Las pruebas son de Lorenzo Bellomo (29/10) y Naim Guarino
> (01/11). Mi aporte fue revisar la entrega y la detección contra el contexto
> actualizado de la cátedra. Lo que digo acá se apoya en esa evidencia.

**Qué le pido a la gerencia:** autorizar hoy el aislamiento de los tres servicios y
una ventana de emergencia de menos de 24 horas para actualizarlos.

---

## 1. Situación y riesgo

**Riesgo: alto.** Hay dos fallas graves, las dos ya se usan para atacar, y en los
registros del ejercicio hay señales de que alguien ejecutó comandos en nuestros
servidores.

- **PHP2Shell** afecta al portal. Permite que cualquiera desde Internet ejecute
  comandos en el servidor sin usuario ni contraseña, y no depende de cómo esté hecha
  nuestra aplicación: alcanza con usar una versión vieja de PHP. Se está explotando y
  CISA, la agencia de ciberseguridad de EE. UU., la tiene en su lista de fallas
  explotadas (KEV) desde el 26/10.
- **Node2Shell** está en el componente que descomprime datos (Brotli), que viene
  dentro de Node.js y de Python. Afecta a la API y al servicio interno, aunque
  nuestro código no lo use de forma directa. Está en KEV desde el 27/10. El exploit
  que circula públicamente falla, pero eso no nos tranquiliza: otros investigadores
  sí lograron tomar control, y cada intento fallido **tira la API**. O sea que, en el
  peor caso, nos toman el servidor, y en el "mejor", nos lo apagan.

Lo que más pesa en mi evaluación no son las fallas sino los registros. El 27/10, en
tres minutos, el portal, la API y el servicio interno ejecutaron comandos que su
código nunca ejecuta: consultar el usuario, consultar el sistema, intentar bajar
archivos de afuera. Además hubo sesiones de administración en db01 en ese mismo rato.
No sabemos si las descargas funcionaron ni quién entró a db01, pero alcanza para
tratarlo como un incidente y no como un parche pendiente.

Una aclaración importante para el comité: **parchear no echa a alguien que ya
entró**. Por eso el plan aísla primero y parchea después.

---

## 2. Plan de acción priorizado

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Aislar de la red, copiar logs y memoria **antes** de reiniciar nada | Portal, API, servicio interno | Inmediato | Seguridad (SOC) | Reconectar solo con la investigación cerrada y desde imagen limpia |
| 2 | Averiguar quién abrió las 3 sesiones SSH en db01 (usuario, origen, método) | db01 | Hoy, primeras 2 h | Infraestructura | No aplica: es una consulta |
| 3 | Mitigación del portal: desactivar `upload_progress` en PHP | Portal | Primeras 2 h | Responsable del portal | Volver el valor a `1` (segundos), solo con autorización |
| 4 | Actualizar PHP a 8.3.36, reconstruyendo desde imagen limpia | Portal | < 24 h | Responsable del portal | Volver a la imagen anterior **solo** aislada y con el riesgo firmado; ensayado en el lab: unos 5 s |
| 5 | Rechazar Brotli en la API hasta parchear | API | Primeras 2 h | Equipo de la API | Volver a aceptar `br` en la configuración; probado en el lab como propuesta |
| 6 | Actualizar Node a 22.23.4 y brotli de Python a 1.0.10 | API y servicio interno | < 24 h (techo KEV: 10/11) | Equipo de la API / plataforma | Igual que la fila 4 |
| 7 | Rotar contraseñas y claves que esos servicios pudieran leer | Los tres | Antes de reconectar | Seguridad + dueños | No se revierte: las claves viejas se dan por perdidas |
| 8 | Relevar el kernel de los servidores (falla Fragnesia, que permite llegar a administrador) | Hosts | Primera jornada (techo KEV: 31/10, vencido) | Infraestructura | No aplica hasta definir si corresponde parche |
| 9 | Evaluar con Legales si hay que notificar por datos personales (Ley 25.326) | Portal | Cuando haya alcance mínimo | Legales + Comunicación | No aplica |

**Por qué este orden.** Lo primero no es parchear sino contener, porque hay señales
de que alguien ya ejecutó comandos. Entre los parches, el portal va primero: tiene
datos personales, está publicado en Internet y la falla se explota hace días. La API
y el servicio interno van en la misma ventana corta y no en la semana siguiente,
porque también están en KEV, comparten el componente afectado y aparecen en los
registros. El plazo de CISA (10/11 para Node2Shell) lo tomamos como límite máximo,
no como objetivo. El puntaje CVSS es el mismo en los tres (9.2), así que **no sirve
para ordenar**: lo que ordena es exposición, datos y evidencia.

---

## 3. Indicadores de compromiso

**Confirmarían el compromiso:**

- Un servicio web que lanza un intérprete de comandos o un programa de descarga
  (`apache2` → `sh`, `node` → `curl`). Ya lo vemos en el log del ejercicio.
- Una conexión saliente que **funcionó** hacia las direcciones de los registros, o
  archivos nuevos en `/tmp` o en la carpeta de la aplicación.
- Una sesión en db01 que nadie del equipo reconozca.
- Contraseñas o claves de esos servicios usadas desde otro lado.

**Lo descartarían (o bajarían la gravedad):**

- Que las sesiones de db01 sean de un administrador que lo pueda explicar con su
  registro de cambios.
- Registros de red que muestren que las descargas no salieron.
- Que la revisión de los servidores no encuentre archivos, usuarios ni tareas
  programadas nuevas.

**Lo que hoy no podemos saber:**

- Quién ejecutó cada comando y desde qué dirección: el registro no guarda usuario ni
  IP de origen.
- Qué pasó entre el 17/10 (primeros intentos en el mundo) y el 27/10: no hay
  registros de esos días.
- Si los relojes de los cuatro servidores estaban sincronizados. La secuencia
  "portal → API → servicio interno" la armamos comparando horas de máquinas
  distintas, así que es una hipótesis, no un hecho.
- Los registros de acceso del portal se pierden cada vez que el servicio se
  reinicia. Si alguien lo reinició para mitigar, esa evidencia ya no está.

Si después de buscar no aparece nada, el resultado es **indeterminado**, no "limpio":
la falta de registros no prueba que no haya pasado nada.

---

## 4. Transferencia: CVE-2024-3094 (puerta trasera en xz-utils)

Elegí una falla de otra clase para ver qué partes del marco siguen sirviendo. En
marzo de 2024 se descubrió que las versiones **5.6.0 y 5.6.1** de xz-utils, una
librería de compresión que viene en casi todos los Linux, traían una **puerta
trasera puesta a propósito** por alguien que había ganado la confianza del proyecto
durante años. En algunas distribuciones esa librería termina cargada dentro del
servidor SSH, y la puerta trasera le permitía al dueño de una clave secreta ejecutar
comandos en el servidor. CVSS 10. La descubrió un ingeniero que notó que el login
por SSH tardaba medio segundo más de lo normal.

**Qué se mantiene del marco:**

- **Inventario por dependencias, no por producto.** Igual que Brotli dentro de Node,
  nadie "instala xz" a propósito: viene con el sistema. La pregunta no es "¿usamos
  xz?" sino "¿qué versión hay en cada servidor y el SSH la carga?" (`xz --version` y
  revisar si `sshd` tiene enlazada `liblzma`).
- **Priorizar por exposición.** Primero los servidores con SSH abierto a Internet,
  después los internos.
- **Contener mientras se corrige:** limitar SSH a la VPN o a un servidor de salto.

**Qué cambia:**

- **El "parche" es volver atrás.** La corrección fue bajar a una versión anterior
  sana (5.4.6), no subir. En nuestro plan, la reversión pasa a ser la solución, y
  hay que asegurarse de que la versión vieja venga de una fuente confiable.
- **El atacante no es un desconocido explotando un error:** es alguien que metió el
  código en el proveedor. No alcanza con confiar en el número de versión; hay que
  verificar de dónde salió el paquete.
- **La detección por procesos sirve menos.** Lo que la delató fue una demora, no un
  proceso raro. Pero hay un punto en común con nuestro caso: un `sshd` que ejecuta
  comandos **sin que haya una sesión de usuario** es la misma idea que `node` → `sh`.
  Y nos recuerda que las sesiones de db01 (`sshd` → `bash`) no se pueden dar por
  buenas solo porque "SSH es de administradores".
- **Plazo:** aunque solo el dueño de la clave podía usarla, una puerta trasera
  confirmada en un proveedor es motivo de emergencia aunque no haya ataques
  conocidos. Acá la evidencia de explotación pesa menos que la de intención.

---

## 5. Qué cambiaría en los procesos

1. **Inventario con dependencias y proxies desde antes.** Tardamos en ver que Brotli
   estaba en tres lugares. Tener una lista de componentes por servicio (SBOM) habría
   respondido "¿estamos afectados?" en minutos.
2. **Logs fuera del servidor.** Los registros del portal se borran al reiniciar y el
   de procesos no trae usuario ni IP. Hay que mandarlos a un colector externo, con
   relojes sincronizados, antes del próximo incidente.
3. **Alertar por reinicios, no solo por caídas.** Un servicio que se reinicia solo
   puede estar escondiendo intentos de ataque. Además, la configuración actual deja
   de reiniciar después de 3 fallas: conviene saberlo antes de que pase.
4. **Responsables nombrados de antemano.** Cada fila del plan tiene un rol, pero no
   una persona. En la emergencia, ese "¿quién se encarga?" cuesta horas.
5. **Probar el armado de los servicios antes de necesitarlo.** En el taller, un
   antivirus que intercepta conexiones frenó la actualización de la API. En una
   emergencia real, eso es tiempo con el servidor expuesto.

---

**Fuentes:** evidencia del grupo en [`entrega.md`](entrega.md) y
[`deteccion.md`](deteccion.md); contexto de la cátedra (`recursos/contexto.md`,
revisión del 29/10). xz-utils:
[NVD — CVE-2024-3094](https://nvd.nist.gov/vuln/detail/CVE-2024-3094) ·
[CISA — Reported Supply Chain Compromise Affecting XZ Utils](https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094) ·
[Help Net Security](https://www.helpnetsecurity.com/2024/03/29/cve-2024-3094-linux-backdoor/).
