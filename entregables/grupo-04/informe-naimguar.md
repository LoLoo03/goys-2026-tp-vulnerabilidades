# Informe individual — Grupo 04

**Integrante:** Naim Guarino (naimguar) · **Fecha:** 01/11/2026
**Destinatario:** gerente de operaciones / comité de crisis

**Caso.** La consigna no asigna una organización ficticia por grupo, así que tomo la
del laboratorio: un portal de legajos del personal publicado en Internet (PHP), una
API que usan los clientes (Node.js), un servicio interno (Python) y un servidor de
base de datos que aparece en los registros pero no en el inventario.

> No participé del taller del 29/10. El 01/11 volví a levantar el laboratorio y probé
> cómo se *comportan* las defensas, no solo cómo están configuradas. Lo que digo
> "medido" o "probado" sale de esas pruebas ([`entrega.md`](entrega.md) §3 y §5,
> capturas [`08`](capturas/08-contencion-pruebas-antes.txt) a
> [`16`](capturas/16-kernel-y-arquitectura.txt)).

---

## 1. Situación y riesgo

**Riesgo alto**, con un agravante: si hubo una intrusión, hoy podríamos no tener
cómo probarla ni descartarla.

Entre el 21 y el 28 de octubre se conocieron tres fallas que nos afectan, las tres
en la lista de fallas explotadas de CISA (la agencia de ciberseguridad de EE. UU.):

- **PHP2Shell (portal):** cualquiera desde Internet toma control del servidor sin
  usuario ni contraseña.
- **Node2Shell (API y servicio interno):** está en un componente que descomprime
  datos y que viene dentro de Node.js y Python aunque nadie lo haya instalado.
- **Fragnesia (sistema operativo):** convierte a un usuario común en administrador.
  Ya se usó encadenada con PHP2Shell para tomar control total en menos de 15 minutos.

Además, el registro del 27/10 muestra al portal, la API y el servicio interno
ejecutando comandos que nunca ejecutan, en menos de tres minutos, mientras alguien
entraba a la base de datos sin que sepamos quién. Es un ejercicio, pero lo trato como
si fuera real.

Al probar las defensas encontré tres problemas que cambian lo que podemos afirmar:

1. **La evidencia del portal se borra sola.** Sus registros de acceso se guardan en
   memoria y desaparecen al reiniciar, y la medida urgente del portal exige reiniciar.
   Medido: el registro quedó vacío después del reinicio.
2. **Una defensa no hacía lo que decía.** El límite de memoria del servicio interno
   era, en la práctica, el doble del configurado.
3. **La API le confirma al atacante que es vulnerable.** Ante datos mal formados
   responde con un error técnico que nombra el componente afectado.

Lo que sí funciona, también medido: los servidores no salen a Internet, no pueden
modificar su propio programa, no corren como administrador y no pueden lanzar
procesos sin límite. Lo que no frena: un servidor comprometido puede hablar con los
otros dos dentro de la red interna.

| Sistema | Riesgo | Por qué |
|---|---|---|
| Portal de legajos | **Crítico** | Falla explotada, en Internet, datos personales, actividad sospechosa y registros que se pierden |
| API de clientes | **Alto** | Falla explotada desde el 27/10, actividad sospechosa y un error que delata el componente |
| Servicio interno | **Alto** | Actividad sospechosa en un sistema sin acceso desde Internet: alguien llegó desde adentro |
| Sistema operativo | **Alto, sin confirmar** | Fragnesia afecta versiones anteriores a mayo de 2026; la del laboratorio es de mayo de 2025 |
| Base de datos | **Desconocido** | Accesos sin explicar y fuera del inventario |

---

## 2. Plan de acción priorizado

Regla del orden: **guardar evidencia, cortar el acceso y recién después cerrar las
fallas.** Actualizar un servidor donde alguien entró no saca al intruso, y
reiniciarlo sin copiar sus registros nos deja sin pruebas.

| # | Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|---|
| 1 | Copiar los registros de cada servidor **antes de tocar nada**, con el método probado (la copia "obvia" devuelve archivos vacíos sin avisar) | Portal, API, servicio | Hoy, 1.ª hora | Seguridad (líder del incidente) | No aplica: solo lee |
| 2 | Aislar de la red los tres servidores | Portal, API, servicio | Hoy, 1.ª hora | Infraestructura | Reconectar al confirmarlos limpios |
| 3 | Identificar quién entró a la base el 27/10 | Base de datos | Hoy | Infraestructura | No aplica |
| 4 | Cambiar contraseñas y claves de esos sistemas | Los cuatro | Hoy | Infraestructura | No se revierte a propósito |
| 5 | Medida temporal del portal (apagar una opción de PHP) y comprobarla en el portal funcionando | Portal | Hoy, después del 1 | Responsable del portal | Volver a activarla |
| 6 | Rechazar datos comprimidos en la API y ocultar sus errores técnicos | API | Hoy | Responsable de la API | Quitar el filtro |
| 7 | Actualizar PHP, Node.js y el componente de Python desde imágenes limpias | Los tres servicios | < 24 h | Responsable de cada servicio | Versión anterior: **ensayado, ~5 s**; solo aislado y con aprobación |
| 8 | Relevar el sistema operativo de cada servidor y corregir Fragnesia | Servidores | < 24 h | Infraestructura | Arrancar con la versión anterior |
| 9 | Corregir el límite de memoria y separar la red interna | Todos | ≤ 7 días | Infraestructura | Configuración anterior |
| 10 | Evaluar con Legales el aviso por datos personales (Ley 25.326) y preparar el mensaje a clientes | Organización | 48 h | Comunicación + Legales | No aplica |

**Por qué este orden.** El paso 1 va primero porque es lo único que no se puede
recuperar si se hace tarde. Los tres servicios comparten 24 h porque las fallas ya
se explotan y los tres muestran actividad; dentro de ese plazo el portal va primero
por exposición y datos personales. Fragnesia entra el mismo día porque es la
diferencia entre un intruso limitado y uno con control total del equipo. Las medidas
5 y 6 no reemplazan la actualización: compran horas. El filtro del punto 6 lo probé:
corta el camino al componente vulnerable.

**Qué cambiaría el orden:** si se confirma salida de datos o acceso a la base, todo
pasa a respuesta de incidente, con apagado si aislar no alcanza. Si el proveedor
confirma que nuestro sistema operativo ya está corregido, el punto 8 sale del plan.

---

## 3. Indicadores de compromiso

| Indicador | Qué indicaría | ¿Tenemos dónde mirarlo? |
|---|---|---|
| Un servicio que lanza comandos (`sh`, `curl`, `wget`) | Alguien lo controla | **Sí**: ya apareció el 27/10 |
| Errores repetidos de descompresión en la API | Alguien prueba el ataque de Node2Shell | **Sí, medido**, pero sin decir desde dónde |
| Conexiones entre servicios internos fuera de lo habitual | Un intruso pasó de un servidor a otro | **Parcial**: el servicio interno registra quién le habla; la API no |
| Pedidos anómalos al portal antes de los comandos | Por dónde entró | **Solo si se copian antes de reiniciar** |
| Archivos de sistema alterados para entrar como administrador sin contraseña | Se usó Fragnesia | **Solo con la copia del paso 1**: la falla modifica la copia en memoria, que puede no llegar al disco |
| Conexiones salientes exitosas | Descarga o robo de datos | **No** hay registro de red; sí sabemos que la salida está bloqueada |

**Qué lo descartaría:** que las sesiones de la base sean de alguien del equipo, que
la copia de cada servidor no muestre archivos, usuarios ni tareas nuevas, y que los
registros del portal no tengan pedidos anómalos antes del 27/10.

**Qué no podemos saber hoy:** quién ejecutó cada comando y desde dónde, ni qué pasó
entre el 17/10 y el 27/10. Hasta tener la copia del paso 1, **no se puede declarar
que estamos limpios**: no tener evidencia no prueba que no haya pasado nada.

---

## 4. Transferencia: CVE-2026-46300 "Fragnesia"

Elegí una falla de otra naturaleza: no está en una aplicación sino en el kernel
Linux, que comparten todos los servicios del mismo equipo. Gravedad 7,8 sobre 10
(menor porque requiere haber entrado antes), afecta versiones anteriores al
13/05/2026 y CISA la agregó a su lista de explotadas el 28/10.

1. **¿La tenemos?** Hay que mirar el sistema operativo: un inventario por versión de
   PHP o Node no la encuentra. Lo relevé en el laboratorio: kernel 6.10.14 de Docker
   Desktop, compilado el 17/05/2025. Por fecha es **candidato a afectado**; no lo
   contrasté con las correcciones del proveedor, así que no lo doy por confirmado.
2. **¿Se explota?** Sí, encadenada con la falla que ya tenemos en el portal.
3. **¿Está expuesta?** No directamente, pero el registro del 27/10 sugiere justo el
   requisito: alguien adentro.
4. **¿Hay medida temporal?** Parcial. Los servicios corren sin permisos especiales
   del sistema, lo que *podría* dificultar llegar a la parte afectada. No lo probé
   (no se ejecutan ataques) y no lo uso para demorar la corrección.

**Decisión:** corregir en < 24 h junto con PHP. La prioridad no sale de su 7,8
aislado sino de la cadena.

**Qué cambia en el plan:** volver a la versión anterior de PHP deja de ser aceptable
mientras el sistema operativo siga vulnerable, porque reabre la cadena completa. Y
limpiar ya no es solo reconstruir el servicio: si alguien llegó a administrador, hay
que revisar el equipo entero.

---

## 5. Qué cambiaría en los procesos

1. **Probar las defensas, no solo leerlas.** La configuración decía 128 MB de memoria
   y el límite real era el doble. Hasta el 30/10 los controles figuraban como
   verificados por haber leído la configuración.
2. **Pensar la evidencia antes del incidente.** Registros enviados a un servidor
   externo y un procedimiento de copia probado: el obvio fallaba sin avisar.
3. **Inventariar por capas:** aplicación, componentes que vienen adentro y sistema
   operativo. Cada falla de este mes estaba en una capa distinta.
4. **No darle información al atacante:** errores genéricos hacia afuera, el detalle
   al registro interno.
5. **Ensayar el parche y la vuelta atrás antes de necesitarlos.** En el equipo del
   taller el antivirus frenó la actualización; en otro funcionó sin cambios, y volver
   atrás llevó cinco segundos.

---

**Fuentes:** [`recursos/contexto.md`](../../recursos/contexto.md) y su revisión del
29/10 (Fragnesia, explotación de Node2Shell); entregables del grupo
([`entrega.md`](entrega.md), [`deteccion.md`](deteccion.md)); capturas propias del
01/11 ([`08`](capturas/08-contencion-pruebas-antes.txt) a
[`16`](capturas/16-kernel-y-arquitectura.txt)).
