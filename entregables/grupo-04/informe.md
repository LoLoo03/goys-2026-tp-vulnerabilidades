# Informe individual — Grupo 04

**Integrante:** Lorenzo Bellomo · **Fecha:** jueves 29/10/2026
**Destinatario:** gerente de operaciones / comité de crisis

Tomo como caso la organización del laboratorio: tiene un portal web donde se cargan
legajos del personal (hecho en PHP), una API que usan las aplicaciones de los clientes
(Node.js) y un servicio interno (Python).

---

## 1. Situación y riesgo

El 21 de octubre se publicaron dos fallas de seguridad que nos afectan.

La primera, PHP2Shell, está en PHP, el lenguaje con el que está hecho el portal de
legajos. Permite que alguien desde Internet ejecute comandos en el servidor sin
necesidad de usuario ni contraseña. Es la más preocupante porque ya se está usando
para atacar sitios reales: CISA, la agencia de ciberseguridad de Estados Unidos, la
agregó a su lista de fallas explotadas.

La segunda, Node2Shell, está en un componente que descomprime datos y que viene
incluido en Node.js y en Python. La usan nuestra API y el servicio interno. Se
demostró que se puede aprovechar, pero por ahora no hay ataques reales confirmados.

Los tres sistemas están afectados, pero no tienen el mismo riesgo. El portal es el más
urgente: está expuesto a Internet, tiene datos personales y la falla ya se explota.
La API viene después y el servicio interno último, porque no recibe tráfico de afuera.

Además, al revisar los registros del 27/10 encontramos actividad sospechosa: en tres
servidores se ejecutaron comandos que esos sistemas normalmente no ejecutan, entre
ellos descargas de archivos desde direcciones externas. Eso indica que alguien
probablemente logró entrar. Lo que todavía no sabemos es hasta dónde llegó.

En el laboratorio ya aplicamos una medida temporal en el portal y actualizamos los tres
sistemas, y siguen funcionando. Como los servidores no tienen salida a Internet, esas
descargas no deberían haber funcionado.

---

## 2. Plan de acción priorizado

| Acción | Activo | Plazo | Dueño | Reversión |
|---|---|---|---|---|
| Aislar los servidores con actividad sospechosa y guardar los registros | Los tres | Hoy, primera hora | Responsable de seguridad | Volver a conectarlos cuando se confirme que están limpios |
| Aplicar la medida temporal en PHP | Portal | Hoy, primera hora | Responsable del portal | Volver a activar la opción |
| Actualizar PHP | Portal | Menos de 24 h | Responsable del portal | Volver a la versión anterior |
| Actualizar Node.js | API | Menos de 72 h | Responsable de la API | Volver a la versión anterior |
| Actualizar el componente en Python | Servicio interno | Dentro de la semana | Responsable del servicio | Volver a la versión anterior |

Las dos fallas tienen la misma gravedad en papel, así que no ordené por ese número.
Puse primero el portal porque la falla ya se está explotando y porque está expuesto.
La API va segunda porque también recibe datos de afuera, pero todavía no hay ataques
conocidos. El servicio interno queda último porque para llegar a él primero hay que
estar adentro de la red.

Antes de actualizar, aislaría los servidores, porque si alguien ya entró, actualizar
no lo saca. También pediría cambiar las contraseñas que usan estos sistemas.

Si apareciera un ataque real con Node2Shell, la API pasaría a ser tan urgente como el
portal.

---

## 3. Indicadores de compromiso

Lo que confirmaría que hubo un ataque:

- Que el servidor web, la API o el servicio interno ejecuten comandos o descarguen
  archivos. Esto ya lo vimos en los registros del 27/10.
- Que esos servidores se conecten a direcciones externas que no conocemos.
- Archivos o usuarios nuevos que nadie del equipo creó.

Lo que lo descartaría:

- Que las descargas hayan fallado (por la falta de salida a Internet) y que no
  aparezcan archivos ni procesos nuevos.
- Que las sesiones que vimos en el servidor de base de datos sean de alguien del
  equipo que estaba trabajando en ese momento.

Lo que no podemos saber con los registros actuales: quién ejecutó cada comando, desde
dónde vino el ataque y qué pasó antes del 27/10, porque el registro solo cubre unos
minutos de ese día.

---

## 4. Transferencia

La consigna propone CVE-2026-115560, pero no encontré información pública sobre ella,
así que no puedo decir qué producto afecta ni qué tan grave es. Lo que sí puedo
hacer es explicar cómo la analizaría usando lo mismo que aprendí con estos dos casos.

Primero me fijaría si usamos el producto afectado y en qué sistemas. Con Node2Shell
aprendí que esto no es tan obvio: el componente vulnerable venía adentro de Node.js y
de Python sin que nadie lo hubiera instalado a propósito.

Después vería si ya se está explotando y si el sistema afectado está expuesto a
Internet. Con esas dos respuestas decidiría el plazo: si se explota y está expuesto,
se actualiza en el día; si no, se programa para la ventana normal de cambios.

Por último, buscaría si hay una medida temporal como la de PHP, que se pueda aplicar
enseguida mientras se prepara la actualización.

---

## 5. Lecciones y procesos

- Necesitamos saber bien qué tenemos instalado, incluidos los componentes que vienen
  adentro de otros programas. En el registro apareció un servidor de base de datos que
  ni siquiera teníamos en nuestro inventario.
- Hay que guardar más información en los registros y por más tiempo. Con lo que hay
  hoy podemos ver que algo pasó, pero no quién lo hizo.
- Conviene probar el proceso de actualización antes de necesitarlo. En el laboratorio,
  el antivirus de la computadora bloqueó la descarga de componentes y nos demoró.
- Cada tarea tiene que tener un responsable. Esta vez hice todo yo solo, y en un
  incidente real eso no alcanza.
