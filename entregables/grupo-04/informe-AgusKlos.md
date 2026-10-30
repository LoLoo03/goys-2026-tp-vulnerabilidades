# Informe individual — Grupo 04

**Integrante:** Agustín Kloster (AgusKlos) · **Fecha:** 30/10/2026
**Destinatario:** gerencia de operaciones

**Caso:** la organización del laboratorio. Tiene un portal publicado en Internet donde
se cargan los legajos del personal (hecho en PHP), una API que usan las aplicaciones
de los clientes (Node.js), un servicio interno (Python) y un servidor de base de datos
que apareció en los registros pero no estaba en nuestro inventario.

> No participé en la ejecución del laboratorio. Este informe se basa en la evidencia
> que dejó el grupo (versiones, cambios aplicados, registros) y en la revisión que
> hice de esa evidencia.

---

## 1. Situación y riesgo

**En una frase:** el riesgo es **alto**, y no tanto por las fallas en sí, sino porque
hay señales de que alguien ya entró.

El 21 de octubre se publicaron dos fallas graves:

- **PHP2Shell**, en el lenguaje con el que está hecho el portal. Permite que cualquiera
  desde Internet tome control del servidor sin usuario ni contraseña. Ya se usa en
  ataques reales y la agencia de ciberseguridad de Estados Unidos (CISA) la incluyó
  en su lista de fallas explotadas.
- **Node2Shell**, en un componente que descomprime datos y viene incluido dentro de
  Node.js y de Python. Afecta a la API y al servicio interno. Se demostró que puede
  aprovecharse, pero no hay ataques reales confirmados.

En papel las dos tienen la misma gravedad (9,2 sobre 10). Lo que las diferencia es
que una ya se está usando y la otra todavía no.

Lo que cambia el panorama son los registros del 27/10. En apenas tres minutos, el
portal, la API y el servicio interno ejecutaron comandos que nunca ejecutan: uno
para averiguar con qué permisos corría, dos descargas desde direcciones de Internet
y uno para reconocer el sistema. Es la secuencia típica de alguien que acaba de
entrar y mira dónde está. En ese mismo lapso hubo tres accesos remotos al servidor
de base de datos que todavía nadie explicó.

| Sistema | Qué tiene | Riesgo | Por qué |
|---|---|---|---|
| Portal de legajos | Datos personales, expuesto a Internet | **Crítico** | Falla explotada en el mundo real + actividad sospechosa |
| API de clientes | Recibe datos de clientes | **Alto** | Actividad sospechosa, aunque su falla no se explote todavía |
| Servicio interno | Procesa datos de otros sistemas | **Alto** | Actividad sospechosa: alguien llegó a un sistema que no da a Internet |
| Base de datos | Sin relevar | **Desconocido** | Accesos sin explicar en la ventana del ataque |

Lo que juega a favor: los servidores no tienen salida a Internet, así que esas
descargas muy probablemente fallaron. Corren sin permisos de administrador y no
pueden modificar sus propios archivos. Eso limita el daño, pero no lo descarta.

---

## 2. Plan de acción priorizado

El orden responde a una idea: **primero cortar el acceso, después cerrar la puerta**.
Actualizar un servidor donde alguien ya entró cierra la falla, pero no saca al
intruso.

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Aislar de la red los tres servidores con actividad sospechosa y guardar una copia de su estado | Portal, API, servicio interno | Hoy, primera hora | Líder del incidente (Seguridad) | Reconectar una vez confirmados limpios. Aislar no borra nada |
| 2 | Identificar quién abrió las sesiones en la base de datos | Base de datos | Hoy | Infraestructura | No aplica: es una consulta |
| 3 | Cambiar las contraseñas y claves que usan esos sistemas | Los cuatro | Hoy | Infraestructura | No se revierte: las claves viejas quedan anuladas a propósito |
| 4 | Desactivar la opción de PHP que usa el ataque (medida temporal, ya probada en el laboratorio) | Portal | Hoy | Responsable del portal | Volver a activar la opción |
| 5 | Rechazar en la API los datos comprimidos con Brotli hasta actualizar | API | Hoy | Responsable de la API | Quitar el filtro |
| 6 | Actualizar PHP, reconstruyendo el servidor desde cero | Portal | < 24 h | Responsable del portal | Volver a la versión anterior, manteniendo la medida del punto 4 |
| 7 | Actualizar Node.js, reconstruyendo desde cero | API | < 72 h | Responsable de la API | Volver a la versión anterior |
| 8 | Actualizar el componente de Python | Servicio interno | < 72 h | Responsable del servicio | Volver a la versión anterior |
| 9 | Evaluar con Legales la obligación de avisar y preparar el mensaje a clientes | Organización | Objetivo: 48 h | Comunicación + Legales | No aplica |

**Por qué este orden.**

- Los pasos 1 a 3 no dependen de qué falla usó el atacante: si alguien está adentro,
  hay que sacarlo igual.
- Entre las actualizaciones, el portal va primero porque combina las tres cosas que
  pesan: falla explotada, exposición a Internet y datos personales.
- La API va después porque su falla todavía no se explota y el filtro del punto 5 la
  protege mientras tanto.
- El servicio interno, que en un escenario sin incidente quedaría para la semana,
  lo subí a 72 h: si alguien ejecutó comandos ahí, ya no podemos suponer que "solo
  se llega desde adentro".

**Qué cambiaría el plan:** si Node2Shell pasa a explotarse en ataques reales, la API
se iguala al portal (< 24 h). Si las sesiones de la base de datos no tienen
explicación, la base entra en el punto 1.

---

## 3. Indicadores de compromiso

| Indicador | Qué indicaría | Dónde se mira | ¿Lo tenemos hoy? |
|---|---|---|---|
| Servicios que ejecutan comandos (`sh`, `curl`, `wget`) | Alguien controla el servicio | Registro de procesos | **Sí, ya apareció** (27/10) |
| Conexiones salientes que **lograron** salir | Las descargas o el robo de datos funcionaron | Firewall, registros de red | **No**: no hay registro de red |
| Archivos, usuarios o tareas programadas nuevos | El intruso intentó quedarse | Copia forense de cada servidor | Se puede ver con la copia del paso 1 |
| Accesos a la base de datos sin dueño | El intruso pasó a la base | Registro de SSH con usuario y origen | **Parcial**: hay accesos, no quién |
| Reinicios por fallas de los servicios | Intentos de ataque fallidos | Estado de los procesos, registros del sistema | **No**: el registro no dice por qué reinician |

**Qué permitiría descartar el compromiso** (o reducirlo a "intento sin éxito"): que
las descargas hayan fallado por la falta de salida a Internet, que la copia forense
no muestre archivos ni procesos nuevos y que las sesiones de la base de datos sean de
alguien del equipo.

**Qué no vamos a poder saber** con la telemetría actual: quién ejecutó cada comando,
desde qué dirección, si las descargas funcionaron y qué pasó entre el 17/10 (primeros
intentos conocidos en el mundo) y el 27/10, porque el registro cubre solo nueve
minutos. Con lo que hay, **no se puede declarar que el sistema está limpio**.

---

## 4. Transferencia: CVE-2026-115560

Apliqué el mismo marco a otra falla, publicada el 23/10, dos días después de
PHP2Shell.

**Qué es.** Una falla en PHP que también permite ejecutar código, pero solo con una
combinación de configuración poco común: la aplicación tiene que cambiar el formato
con que guarda las sesiones antes de abrirlas, y además tener activa la misma opción
que desactivamos por PHP2Shell. PHP la considera de explotación improbable. No hay
versión corregida todavía (la incluirá en una actualización normal), no publicó
puntaje de gravedad y no se reportan ataques. Una fuente le atribuye un alcance mucho
mayor y enlaza repositorios con supuestos "exploits". Esa versión contradice al
aviso oficial, así que la tomo como no verificada, y por las reglas del trabajo no
abrí esos repositorios.

**Las mismas cuatro preguntas:**

1. **¿Lo tenemos?** El portal usa PHP con sesiones, así que el producto sí. La
   condición puntual (cambiar el formato de sesión) no aparece en el código del
   portal del laboratorio. Habría que confirmarlo también en las librerías que use la
   aplicación real.
2. **¿Se explota?** No hay reportes.
3. **¿Está expuesto?** Sí, el portal da a Internet.
4. **¿Hay medida temporal?** Sí, y **ya está aplicada**: es la misma opción que
   desactivamos por PHP2Shell.

**Decisión:** no amerita una ventana de emergencia. Va a la ventana normal cuando PHP
publique la corrección, más una revisión del código para confirmar que no usamos esa
combinación.

**Lo que cambia en el plan.** En el punto 6 dije que, si había que volver atrás la
actualización de PHP, se mantenía la medida temporal. Con esta falla, la medida
tampoco se puede retirar *después* de actualizar por PHP2Shell: sigue protegiéndonos
de CVE-2026-115560 hasta que salga su propia corrección. La lección es que una medida
temporal puede terminar cubriendo más de una falla, así que cada una necesita
registrado **qué cubre y cuándo se puede quitar**.

**Qué me haría cambiar la decisión:** que se confirme explotación, que aparezca en el
catálogo de CISA o que encontremos en nuestro código el cambio de formato de sesión.

---

## 5. Qué cambiaría en los procesos

1. **Inventario completo, incluido lo que viene adentro.** El componente vulnerable
   de Node2Shell estaba dentro de Node.js y de Python sin que nadie lo instalara a
   propósito. Y apareció un servidor de base de datos que no estaba inventariado.
2. **Registros que sirvan para investigar.** Usuario, dirección de origen y
   resultado de cada comando, con al menos 90 días de retención. Hoy podemos ver que
   algo pasó, pero no quién ni desde dónde.
3. **Registro de medidas temporales.** Cada medida con dueño, qué falla cubre y bajo
   qué condición se retira (ver sección 4).
4. **Pruebas que comprueben la aplicación, no solo el servidor.** En el laboratorio,
   el chequeo del portal solo verificaba que el servidor web respondiera, no que
   PHP funcionara.
5. **Ensayar la actualización antes de necesitarla.** El antivirus del equipo
   bloqueó la descarga de componentes y frenó el parche. En una emergencia, eso es
   tiempo perdido.
6. **Roles definidos de antemano:** líder del incidente, técnico, comunicación y
   alguien que registre todo. En el laboratorio una sola persona hizo los cuatro
   roles. En un incidente real eso no alcanza.

---

**Fuentes de la sección 4:**
[The Hacker News](https://thehackernews.com/2026/10/urgent-php-warns-of-another-unpatched.html) ·
[IT-Connect](https://www.it-connect.tech/php-flags-a-new-rce-flaw-cve-2026-115560-keep-the-same-setting-used-against-php2shell/) ·
[Astra Security](https://www.getastra.com/blog/security-advisory/cve-2026-115560/) ·
[Brandefense](https://brandefense.io/knowledge-hub/vulnerabilities/cve-2026-115560/) ·
[Vulners](https://vulners.com/cve/CVE-2026-115560) (fuente contradictoria, ver arriba).
Resto del contexto: [`recursos/contexto.md`](../../recursos/contexto.md) y los
entregables del grupo ([`entrega.md`](entrega.md), [`deteccion.md`](deteccion.md)).
