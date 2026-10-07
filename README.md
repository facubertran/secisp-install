# secisp-install

Bundle de instalación de **Security-ISP** (`secisp`): sistema de detección y mitigación de DDoS, spam SMTP, scans y otras amenazas para un ISP, basado en **IPFIX/NetFlow** exportado por los routers de borde. Detecta con el engine y mitiga insertando address-lists en **MikroTik RouterOS** (REST API sobre `www-ssl`).

Este repositorio **no contiene código fuente**: trae el binario ya compilado más los archivos de despliegue.

| Ruta | Contenido |
|---|---|
| `secisp` / `bin/secisp` | Binario único (`collector`, `engine`, `mitigator`, `watchdog` y la CLI) |
| `deploy/install.sh` | Instalador: usuario, directorios, unidades systemd, sysctl, `doctor --pre` |
| `deploy/config/` | Plantillas de configuración (routers, prefijos, exporters, never_block, policy) |
| `deploy/routeros/` | Plantillas `.rsc` para MikroTik (usuario dedicado, keepalive de `www-ssl`) |
| `deploy/systemd/` | Unidades systemd |
| `infra/` | `docker-compose.yml` con ClickHouse, Prometheus, Grafana, Alertmanager y node-exporter |
| `mitigator.env.example`, `engine.env.example` | Variables de entorno de los servicios |

## Arquitectura en una línea

```
Routers (IPFIX) ──► collector ──► ClickHouse ──► engine (detectores) ──► mitigator ──► RouterOS (address-lists + firewall RAW)
                                      ▲                                      
                      watchdog / doctor / Prometheus / Grafana / Alertmanager (Telegram)
```

Servicios systemd: `secisp-collector`, `secisp-engine`, `secisp-mitigator`, `secisp-watchdog` (más `secisp-doctor.timer`).
ClickHouse y el stack de monitoreo corren en Docker (`/opt/secisp/infra`).

## Requisitos

- Linux con **systemd** (Debian/Ubuntu recomendado), acceso **root**.
- **Docker** y **Docker Compose v2** (`docker compose`).
- `git`.
- Conectividad desde el host hacia el `www-ssl` (443) de cada router MikroTik, y desde los routers hacia el host por UDP (puerto IPFIX configurado en `collector.yaml`).
- Disco: el WAL (`/var/lib/secisp/wal`) y los datos de ClickHouse (`/var/lib/clickhouse`) deberían estar en **dispositivos distintos** en producción (si ClickHouse se llena, el WAL no puede drenar nunca).

> Todos los comandos se ejecutan como `root`. Las rutas asumen que el repo está clonado en `/root/secisp-install`.

---

## 1. Preparación del host

Zona horaria:

```bash
timedatectl set-timezone America/Argentina/Buenos_Aires
```

Clonar este repositorio:

```bash
cd /root
git clone https://github.com/facubertran/secisp-install.git
cd secisp-install
```

## 2. Instalación de archivos

Variables que usa el instalador y `secisp doctor`:

```bash
export SECISP_BIN=/root/secisp-install/secisp
export SEC_WATCHDOG_DEADMAN_URL=""
export SEC_DOCTOR_ALLOW_MISSING_DEADMAN=true
export SEC_DOCTOR_ALLOW_SHARED_WAL_DEVICE=true
```

> `SEC_DOCTOR_ALLOW_MISSING_DEADMAN` y `SEC_DOCTOR_ALLOW_SHARED_WAL_DEVICE` bajan esos chequeos de FAIL a WARN. Son válidos para laboratorio o instalaciones chicas; en producción configurá un dead-man switch real y separá el disco del WAL.

Ejecutar el instalador:

```bash
./deploy/install.sh
```

El script es idempotente y:

- crea el usuario de sistema `secisp` (sin shell);
- crea `/etc/secisp`, `/var/lib/secisp/{wal,templates,state}`, `/var/backups/secisp` y `/opt/secisp/infra`;
- instala el binario en `/usr/local/bin/secisp`;
- instala **sin pisar** los `*.yaml` por defecto (`config`, `collector`, `engine`, `mitigator`, `watchdog`, `expected_modes`, `policy`, `never_block`);
- instala y habilita (`enable`, **sin arrancar**) las unidades systemd, y escribe `net.core.rmem_max=16777216`;
- copia `docker-compose.yml`, Prometheus, ClickHouse, Alertmanager y los dashboards de Grafana a `/opt/secisp/infra`;
- termina corriendo `secisp doctor --pre` y aborta si hay algún FAIL.

## 3. Archivos de configuración

Copiar cada plantilla y **editarla con los datos del cliente** (hacerlo desde `/root/secisp-install`).

> **Es obligatorio editar** `routers.yaml`, `prefixes.yaml`, `exporters.yaml` y `never_block.yaml` (por ejemplo con `nano /etc/secisp/<archivo>.yaml`). Las plantillas traen valores de ejemplo (IPs de documentación, routers ficticios, fingerprints falsos) que **no sirven tal cual**: si quedan sin editar, el mitigador no conecta a los routers o no detecta/protege los prefijos reales. Hacelo después de cada `cp` y antes de validar.

### Routers (`routers.yaml`)

Credenciales y endpoints de los MikroTik que administra el mitigador. Es secreto: el instalador **no** lo crea y aborta si existe con permisos más laxos que `0600`.

```bash
cp deploy/config/routers.yaml.example /etc/secisp/routers.yaml
chown root:secisp /etc/secisp/routers.yaml
chmod 0600 /etc/secisp/routers.yaml
```

Cada router declara `name`, `host`, `port` (443, **nunca** 8728/8729), `username`, `password_env` (nombre de la variable que trae la contraseña, p. ej. `SEC_MIT_PW_RTR_BORDE_1`) y `tls` (`pin` con fingerprint o `verify` con `ca_file`). Ver comentarios del propio archivo.

### Prefijos (`prefixes.yaml`)

Pools de clientes (`scope: customer`) e infraestructura propia (`scope: infra`, p. ej. el MX saliente).

```bash
cp deploy/config/prefixes.example.yaml /etc/secisp/prefixes.yaml
chown root:secisp /etc/secisp/prefixes.yaml
chmod 0600 /etc/secisp/prefixes.yaml
```

### Exporters (`exporters.yaml`)

Equipos que exportan IPFIX: `id` único y **todas** las IPs (v4 y v6) desde las que exporta cada uno.

```bash
cp deploy/config/exporters.example.yaml /etc/secisp/exporters.yaml
chown root:secisp /etc/secisp/exporters.yaml
chmod 0600 /etc/secisp/exporters.yaml
```

### Never block (`never_block.yaml`)

Prefijos que **jamás** se bloquean (DNS propios, gestión, upstreams). Las plantillas traen prefijos de documentación (RFC 5737/3849): reemplazarlos por los reales. Sin este archivo el mitigador arranca forzado en dry-run.

```bash
cp deploy/config/never_block.yaml.example /etc/secisp/never_block.yaml
chown root:secisp /etc/secisp/never_block.yaml
chmod 0644 /etc/secisp/never_block.yaml
```

### Policy (`policy.yaml`)

Mapeo detector → acción. Viene listo para usar.

```bash
cp deploy/config/policy.yaml /etc/secisp/policy.yaml
chown root:secisp /etc/secisp/policy.yaml
chmod 0644 /etc/secisp/policy.yaml
```

> `install.sh` ya instala `policy.yaml` y `never_block.yaml` si no existían. Estos `cp` sirven para reponerlos; ojo que **pisan** lo que hayas editado.

### Validar y aplicar prefijos y exporters

```bash
secisp config validate --prefixes /etc/secisp/prefixes.yaml --exporters /etc/secisp/exporters.yaml
secisp config apply    --prefixes /etc/secisp/prefixes.yaml --exporters /etc/secisp/exporters.yaml --reason "carga inicial"
```

> `config apply` escribe en ClickHouse, así que necesita que la base ya esté levantada (sección 4). Si todavía no lo está, hacé solo el `validate` ahora y el `apply` después del paso 4.

## 4. Base de datos (ClickHouse + monitoreo)

### Secreto del bot de Telegram (Alertmanager)

```bash
mkdir -p /opt/secisp/infra/secrets
printf '%s' '123456789:TOKEN-REAL-DE-BOTFATHER' > /opt/secisp/infra/secrets/telegram_bot_token
chmod 0600 /opt/secisp/infra/secrets/telegram_bot_token
```

### Levantar el stack Docker

`infra/.env` define `CLICKHOUSE_DEFAULT_PASSWORD`, `GF_ADMIN_PASSWORD`, `SEC_PANEL_CH_PASSWORD` y `GRAFANA_TLS_DIR`. **Cambiá todos los valores por defecto/de ejemplo antes de copiarlo.**

```bash
cd /root/secisp-install
cp infra/.env /opt/secisp/infra/
cd /opt/secisp/infra
docker compose up -d
```

Servicios: ClickHouse (nativo `9000`, HTTP `127.0.0.1:8123`), Prometheus (`127.0.0.1:9090`), Grafana, Alertmanager (`127.0.0.1:9093`) y node-exporter.

### Esquema de la base

```bash
export SEC_CH_DSN="clickhouse://127.0.0.1:9000/isp"
secisp schema apply --verbose
```

Si `default` tiene password (lo define `CLICKHOUSE_DEFAULT_PASSWORD`), incluirla en el DSN.

### Password del usuario de Grafana en ClickHouse

Debe coincidir con `SEC_PANEL_CH_PASSWORD` de `infra/.env`:

```bash
docker compose exec clickhouse clickhouse-client \
  --user default \
  --query "ALTER USER secisp_grafana IDENTIFIED WITH sha256_password BY '<SEC_PANEL_CH_PASSWORD>'"
```

## 5. Variables de entorno de los servicios

```bash
cd /root/secisp-install
cp mitigator.env.example /etc/secisp/mitigator.env
cp engine.env.example /etc/secisp/engine.env
```

Editar `/etc/secisp/mitigator.env`:

| Variable | Descripción |
|---|---|
| `SEC_MIT_LOCAL_IPS` | **IP de la VM del mitigador** (obligatorio ajustarla) |
| `SEC_MIT_PW_<ROUTER>` | Contraseña de cada router, con el nombre indicado en `password_env` de `routers.yaml` |
| `SEC_MIT_DRY_RUN` | `true` = no toca los routers; `false` = mitiga de verdad |
| `SEC_MIT_TLS_INSECURE` | Solo para pruebas; en producción usar `tls.mode: pin`/`verify` |
| `SEC_MIT_MAX_CUSTOMERS_BLOCKED_PER_HOUR` | Tope de clientes bloqueados por hora |
| `SEC_MIT_TICK_SECONDS` | Período del ciclo del mitigador |

`/etc/secisp/engine.env` define el modo de cada detector (`SEC_DETECT_MODE_*`): `alert` solo avisa, `mitigate` actúa (ver sección 9).

> **Cuidado:** los `*.env.example` de este repo traen valores de ejemplo. Reemplazá contraseñas y tokens por los del cliente; no los reutilices. La validación de entorno es **estricta**: un nombre `SEC_*` mal escrito aborta el arranque de los cuatro servicios.

## 6. Licencia

Obtener el fingerprint del host:

```bash
secisp license fingerprint
```

**Solicitar la licencia por WhatsApp al +549375409044** enviando el bundle que imprime el comando. Con el `license.lic` recibido, copiarlo a `/etc/secisp/license.lic` (`0644 root:secisp`).

## 7. Servicios

Arranque inicial:

```bash
systemctl start secisp-collector secisp-engine secisp-mitigator secisp-watchdog
systemctl start secisp-doctor.timer
```

Gestión:

```bash
systemctl status  secisp-collector secisp-engine secisp-mitigator secisp-watchdog
systemctl restart secisp-collector secisp-engine secisp-mitigator secisp-watchdog
systemctl stop    secisp-collector secisp-engine secisp-mitigator secisp-watchdog
```

Logs:

```bash
systemctl status secisp-mitigator --no-pager -l
journalctl -u secisp-mitigator --since "-15 min" --no-pager
journalctl -u secisp-mitigator --since "-1 min" --no-pager
```

Aplicar la configuración inicial (si no lo hiciste en la sección 3) y tomar un backup:

```bash
secisp config apply --exporters /etc/secisp/exporters.yaml --prefixes /etc/secisp/prefixes.yaml
secisp backup
```

> `routers.yaml` y los `.env` **no se recargan en caliente**: cualquier cambio exige `systemctl restart` del servicio.

## 8. Validación

Conectividad con el router y drift de reglas:

```bash
secisp mitigator status --router rtr-borde-1
secisp mitigator drift
```

Salud end-to-end (esquema, diccionarios, prefijos, exporters):

```bash
secisp doctor --post
```

El sink está insertando o está pausado/atascado:

```bash
curl -s http://127.0.0.1:9101/metrics | grep -E '^sec_sink_(paused|parts_active|rows_inserted_total)'
```

### Error de login/contraseña contra el router

Si `mitigator status` falla por credenciales desde tu shell, cargá el entorno del servicio y reintentá:

```bash
set -a
source /etc/secisp/mitigator.env
set +a
secisp mitigator status --router rtr-borde-1
```

## 9. Activar la mitigación

Por defecto los detectores están en modo `alert`. Listarlos:

```bash
secisp detect list
```

Pasarlos a `mitigate` (recomendado: activar de a grupos y observar entre cada uno):

```bash
for d in \
  anomaly.fanout_spike anomaly.level_shift anomaly.new_service anomaly.service_wave anomaly.volume_spike \
  ddos.amp_request ddos.carpet_bombing ddos.spoofed_egress ddos.src_flood ddos.syn_flood ddos.victim_convergence \
  refl.dns refl.generic \
  scan.coordinated scan.horizontal scan.sweep_slow scan.syn_unanswered scan.vertical \
  smtp.fanout smtp.port25_policy smtp.refused smtp.small_session smtp.stalled smtp.volume smtp.low_rate
do
  secisp detect modes --set "${d}=mitigate" --reason "activacion"
done
```

Antes de activar, verificá que `SEC_MIT_DRY_RUN=false`, que `never_block.yaml` tiene tus prefijos críticos y que `secisp mitigator drift` no reporta diferencias.

## 10. MikroTik

### Usuario dedicado

Crear el usuario con mínimo privilegio (no usar `admin`) con la plantilla `deploy/routeros/secisp-user.rsc` — **cambiar la contraseña antes de aplicarla** y guardarla en `SEC_MIT_PW_<ROUTER>`.

### Certificado `www-ssl`

El mitigador usa la REST API sobre `www-ssl`:

```routeros
/certificate
add name=Server common-name=server
sign Server ca-crl-host=192.168.253.1 name=ServerCA
:delay 5
/ip service
set www-ssl disabled=no certificate="Server"
```

> `ca-crl-host` es una IP del propio router. Adaptala a la del equipo.
> Para `tls.mode: pin`, obtené el fingerprint SHA256 del certificado y cargalo en `routers.yaml`. Para evitar que `www-ssl` se caiga, ver también `deploy/routeros/wwwssl_keepalive.rsc`.

### Firewall RAW

El mitigador carga las IPs en address-lists; estas reglas son las que efectivamente las descartan. Los `accept` van **primero** para no bloquear tráfico legítimo (web, QUIC, DNS).

```routeros
/ip firewall raw
add action=accept chain=prerouting dst-port=80,443 protocol=tcp
add action=accept chain=prerouting dst-port=443 protocol=udp
add action=accept chain=prerouting dst-port=53 protocol=udp
add action=drop chain=prerouting src-address-list=secisp_pair_src_ddos_src_flood
add action=drop chain=prerouting src-address-list=secisp_pair_src_scan_vertical
add action=drop chain=prerouting src-address-list=secisp_svc_auto_src
add action=drop chain=prerouting src-address-list=secisp_block_src
add action=drop chain=prerouting src-address-list=secisp_ratelimit_src
add action=drop chain=prerouting dst-port=25,587,465 protocol=tcp src-address-list=secisp_svc_smtp_src
add action=drop chain=prerouting dst-port=25,587,465 protocol=udp src-address-list=secisp_svc_smtp_src
add action=drop chain=prerouting port=0 protocol=udp
```

Además, configurar **Traffic-Flow (IPFIX)** en el router apuntando al host del collector.

---

## Checklist de puesta en marcha

- [ ] `./deploy/install.sh` termina sin FAIL de `doctor --pre`
- [ ] `routers.yaml` (`0600`), `prefixes.yaml`, `exporters.yaml` y `never_block.yaml` ajustados al cliente
- [ ] Contraseñas de `infra/.env` y `*.env` cambiadas (nada de valores de ejemplo)
- [ ] `docker compose up -d` y `secisp schema apply` OK
- [ ] `secisp config validate` y `config apply` OK
- [ ] Servicios arrancados; `secisp doctor --post` sin FAIL
- [ ] `secisp mitigator status --router <router>` conecta
- [ ] Reglas RAW cargadas en MikroTik y flujos IPFIX llegando
- [ ] Detectores pasados a `mitigate` de forma gradual
