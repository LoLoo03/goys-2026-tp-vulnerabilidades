# Entregable — TP PHP2Shell / Node2Shell

**Grupo:** 04 · **Fork del grupo:** https://github.com/LoLoo03/goys-2026-tp-vulnerabilidades · **Rama:** `grupo-04`
**Fecha:** jueves 29/10/2026

| Integrante | Usuario de GitHub | Rol en el TP |
|---|---|---|
| | | |
| | | |
| | | |
| | | |

> Roles sugeridos: inventario, cambios/parche, detección, contención/comunicación.
> Todos tienen que poder explicar su parte y una parte ajena.

---

## 1. Inventario

| Activo | Versión | ¿Expuesto a Internet? | ¿Procesa contenido no confiable? | ¿Afectado? | Evidencia |
|--------|---------|:---------------------:|:--------------------------------:|:----------:|-----------|
| Portal PHP | | | | | |
| API Node.js | | | | | |
| Servicio Python | | | | | |

**Supuestos de exposición:** _¿qué asumieron sobre el proxy, la red y el despliegue?_

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
| | | | | | |
| | | | | | |
| | | | | | |

**Justificación:** _¿por qué ese orden? ¿qué evidencia nueva cambiaría la decisión?_

---

## 3. Mitigación, parche y reversión

| Fecha/hora | Activo | Cambio | Antes | Después | Reversión |
|------------|--------|--------|-------|---------|-----------|
| 29/10/2026, antes del taller | Entorno (build de API Node.js) | Build de `goys-vuln-lab-node:22.23.3-bookworm-slim` y `:22.23.4-bookworm-slim` con un `Dockerfile` temporal que confía en la CA de Kaspersky (comando abajo) | `npm install` fallaba con `SELF_SIGNED_CERT_IN_CHAIN`; el lab no arrancaba | `./scripts/arrancar-2h.sh`: `php-lab`, `node-lab` y `py-lab` en `healthy`; inventario: PHP 8.3.35, Node v22.23.3 / brotli 1.1.0, Python brotli 1.0.9 | `docker rmi goys-vuln-lab-node:22.23.3-bookworm-slim goys-vuln-lab-node:22.23.4-bookworm-slim` y reconstruir con `docker compose --env-file versions.env build` en un equipo sin intercepción HTTPS |
| | | | | | |

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

**Prueba funcional mínima:** _¿qué verificaron para saber que la app sigue viva?_

**Qué no se pudo probar:**

- Que las imágenes de Node construidas con el `Dockerfile` de la cátedra, sin el
  ajuste de Kaspersky, se comporten igual. En este equipo ese build falla. La
  diferencia esperada es nula: el ajuste solo cambia en qué CA confía npm al bajar
  `express`.
- `./scripts/parchear.sh` corre `docker compose up -d --build`, que reconstruye Node
  con el `Dockerfile` original y va a fallar por la misma causa. El parche de Node
  usa la imagen `22.23.4-bookworm-slim` ya construida con el ajuste.

---

## 4. Detección y caza

**Hipótesis:** _una frase: proceso, padre, horario, evidencia esperada._

**Hallazgos en `audit.log`:**

| Línea / timestamp | Host | Padre → hijo | ¿Anómalo? | Por qué |
|-------------------|------|--------------|:---------:|---------|
| | | | | |
| | | | | |

**¿Hay compromiso?** _sí/no/indeterminado, con evidencia._

**Regla propuesta para Node.js:** _qué proceso observa, qué condición y qué falso
negativo podría tener._

**Limitaciones del log:** _usuario, IP de origen, retención, ruido, etc._

---

## 5. Contención

| Control | Configuración | Evidencia | ¿Funciona? |
|---------|---------------|-----------|:----------:|
| Red sin salida | `internal: true` | | |
| Usuario sin privilegios | | | |
| Filesystem read-only | | | |
| Capabilities mínimas | | | |
| Límites de memoria/PIDs | | | |
| Rechazo de Brotli innecesario | | | |

**Prueba de salida a Internet:** _resultado en los tres servicios._

---

## 6. Conclusión (5 líneas)

_¿Qué harían distinto en las primeras 2 horas?_

---

## 7. Checklist antes de entregar

- [x] El laboratorio arrancó y los 3 servicios quedaron `healthy`.
- [ ] Inventario con evidencia (versión, SAPI, configuración).
- [ ] Matriz con decisión y plazo.
- [ ] Parche aplicado y verificado; reversión documentada.
- [ ] Al menos 3 controles de contención probados.
- [ ] `deteccion.md` completo.
- [ ] `informe.md` individual completo.
- [ ] Sin claves, tokens ni placeholders.
- [ ] Repo pusheado y PR abierto.

Checklist completa: [`../docs/checklist-entrega.md`](../docs/checklist-entrega.md).
