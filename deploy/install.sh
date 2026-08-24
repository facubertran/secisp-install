#!/usr/bin/env bash
#
# deploy/install.sh — instalador de archivos de F1 (T-036 · E12a-T05).
#
# Deja el layout de host que el resto de las tasks asume: usuario de sistema,
# /etc/secisp, /var/lib/secisp/{wal,templates,state}, /var/backups/secisp,
# /opt/secisp/infra, el binario en /usr/local/bin/secisp, las cinco unidades
# systemd habilitadas (sin arrancarlas) y el sysctl de SO_RCVBUF. Termina
# invocando `secisp doctor --pre` y aborta si hay algún FAIL (E12 §4.4).
#
# Specs: E12 §4.3 (layout de archivos y unidades) · E12 §3 D1 (binarios nativos,
# el instalador de F1 es un install.sh que copia el binario, escribe las units y
# hace systemctl enable) · E12 §4.4 (`secisp doctor`) · E12 §5.8 (config) ·
# E12 §4.2.3 (WAL y ClickHouse en dispositivos distintos).
#
# Lo que este script NO hace, a propósito:
#   - No hace `git pull` ni asume un working tree de git en el host (§1.2e): el
#     artefacto que se despliega es el binario ya compilado (`make build`) más
#     los archivos versionados de deploy/, no un checkout que se actualiza in situ.
#   - No arranca ningún servicio (`systemctl enable`, nunca `--now`): arrancar
#     es una decisión explícita del operador, después de revisar `doctor --pre`.
#   - No corre `docker compose up`: infra/docker-compose.yml (T-034) es un paso
#     aparte: este instalador solo prepara /opt/secisp/infra para que ese compose
#     tenga dónde vivir en el host.
#
# Idempotencia: correrlo dos veces no duplica nada. Usuario, directorios y
# unidades usan operaciones que ya son idempotentes por naturaleza (mkdir -p,
# useradd con chequeo previo, systemctl enable, escritura del mismo archivo de
# sysctl.d). Los *.example nunca pisan un archivo real ya presente en
# /etc/secisp: se copian solo si el destino no existe.

set -euo pipefail

# ─── Resolución de paths ────────────────────────────────────────────────────────────
#
# El script vive en deploy/install.sh dentro del árbol que `make build` ya
# produjo (bin/secisp) y que versiona deploy/systemd, deploy/etc/secisp/*.example.
# SECISP_BIN permite apuntar a otro binario (por ejemplo, un release descomprimido
# en otra ruta) sin tocar el script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN_SRC="${SECISP_BIN:-${REPO_ROOT}/bin/secisp}"
SYSTEMD_SRC_DIR="${SCRIPT_DIR}/systemd"
ETC_EXAMPLES_DIR="${SCRIPT_DIR}/etc/secisp"
CONFIG_SRC_DIR="${REPO_ROOT}/deploy/config"
INFRA_SRC_DIR="${REPO_ROOT}/infra"
GRAFANA_DASHBOARDS_SRC_DIR="${REPO_ROOT}/deploy/grafana/dashboards"
GRAFANA_PROVISIONING_SRC_DIR="${REPO_ROOT}/deploy/grafana/provisioning"

BIN_DST="/usr/local/bin/secisp"
ETC_DIR="/etc/secisp"
VAR_LIB_DIR="/var/lib/secisp"
BACKUPS_DIR="/var/backups/secisp"
OPT_INFRA_DIR="/opt/secisp/infra"
SYSTEMD_DST_DIR="/etc/systemd/system"
SYSCTL_FILE="/etc/sysctl.d/99-secisp.conf"
ROUTERS_YAML="${ETC_DIR}/routers.yaml"

SECISP_USER="secisp"
SECISP_GROUP="secisp"

log() { printf '[install.sh] %s\n' "$*"; }
die() { printf '[install.sh] ERROR: %s\n' "$*" >&2; exit 1; }

# ─── Precondiciones ─────────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    die "correr como root (sudo $0)"
fi

if [ ! -x "${BIN_SRC}" ]; then
    die "no se encontró el binario en ${BIN_SRC} -- correr 'make build' antes, o exportar SECISP_BIN=/ruta/al/binario"
fi

if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl no está disponible: este instalador es para un host con systemd (E12 §3 D1)"
fi

log "instalando desde ${REPO_ROOT}"

# ─── 1. Usuario de sistema `secisp`, sin shell ──────────────────────────────────────
#
# Mismo comando que sugiere `secisp doctor --pre` (internal/ops/doctor/pre_config.go,
# check "config: usuario secisp") para que instalar y diagnosticar coincidan.
if id -u "${SECISP_USER}" >/dev/null 2>&1; then
    log "usuario ${SECISP_USER} ya existe, no se recrea"
else
    log "creando usuario de sistema ${SECISP_USER} (sin home, sin shell de login)"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SECISP_USER}"
fi

# ─── 2. /etc/secisp ─────────────────────────────────────────────────────────────────
#
# E12 §4.3 fija 0644 root:secisp para config.yaml (y los demás *.yaml del árbol) y
# 0600 root:secisp para routers.yaml -- ningún archivo del directorio es 0600 salvo
# ese, así que el directorio en sí no necesita ocultar nada: 0755 lo hace
# transitable por el grupo `secisp` (los cuatro roles) sin aflojar los archivos que
# sí llevan su propio modo restringido.
log "creando ${ETC_DIR}"
mkdir -p "${ETC_DIR}"
chown root:"${SECISP_GROUP}" "${ETC_DIR}"
chmod 0755 "${ETC_DIR}"

# Los *.example se instalan como su nombre real SOLO si el destino todavía no
# existe -- nunca se pisa una config ya editada por el operador. Cada archivo
# real queda en 0644 root:secisp (E12 §4.3), salvo que sea el propio
# routers.yaml (no se agrega .example para ese: es secreto y el operador lo trae).
install_example() {
    local example="$1" dst="$2"
    if [ -e "${dst}" ]; then
        log "${dst} ya existe, no se pisa"
        return
    fi
    if [ ! -f "${example}" ]; then
        log "aviso: falta el fixture ${example}, se omite ${dst}"
        return
    fi
    install -o root -g "${SECISP_GROUP}" -m 0644 "${example}" "${dst}"
    log "creado ${dst} (desde $(basename "${example}"))"
}

install_example "${ETC_EXAMPLES_DIR}/config.yaml.example"          "${ETC_DIR}/config.yaml"
install_example "${ETC_EXAMPLES_DIR}/collector.yaml.example"       "${ETC_DIR}/collector.yaml"
install_example "${ETC_EXAMPLES_DIR}/engine.yaml.example"          "${ETC_DIR}/engine.yaml"
install_example "${ETC_EXAMPLES_DIR}/mitigator.yaml.example"       "${ETC_DIR}/mitigator.yaml"
install_example "${ETC_EXAMPLES_DIR}/watchdog.yaml.example"        "${ETC_DIR}/watchdog.yaml"
install_example "${ETC_EXAMPLES_DIR}/expected_modes.yaml.example"  "${ETC_DIR}/expected_modes.yaml"

# policy.yaml, a diferencia de los seis de arriba, NO es un *.example: es el
# mapeo detector -> acción real del proyecto (E11 §4.13/§4.2.3), listo para
# correr sin edición -- por eso vive en deploy/config/ y no en
# ${ETC_EXAMPLES_DIR}, y por eso no lleva el sufijo .example. `secisp
# mitigator` lo requiere para arrancar (SEC_MIT_POLICY_PATH, default
# /etc/secisp/policy.yaml, cmd/secisp/mitigator.go) y falla con ENOENT sin
# él -- gap real encontrado en la primera instalación end-to-end de este
# script: reusa install_example (mismo criterio "no pisar un archivo ya
# editado por el operador") aunque el nombre de la función hable de
# "example".
install_example "${CONFIG_SRC_DIR}/policy.yaml"                    "${ETC_DIR}/policy.yaml"

# never_block.yaml.example SÍ es un .example real (a diferencia de policy.yaml
# arriba): trae prefijos de documentación (RFC 5737/3849) que el operador tiene
# que reemplazar por su infraestructura propia, nunca placeholders para correr
# tal cual. Pero como policy.yaml, nunca estuvo en este script -- mismo gap real
# encontrado en la primera instalación end-to-end (SEC_MIT_NEVER_BLOCK_PATH,
# default /etc/secisp/never_block.yaml, cmd/secisp/mitigator.go): sin el
# archivo, BuildNeverBlockSet falla y el mitigador arranca forzado en dry-run
# con SEC-MIT-006 (docs/runbooks/RB-13-mitigador-en-dry-run-inesperado.md).
install_example "${CONFIG_SRC_DIR}/never_block.yaml.example"       "${ETC_DIR}/never_block.yaml"

# routers.yaml: el instalador NO lo crea (es secreto, lo trae el operador), pero
# si ya está ahí tiene que estar en 0600 root:secisp -- si alguien lo dejó más
# laxo, se aborta la instalación en vez de seguir con un secreto expuesto
# (E12 §4.4: "permisos más laxos" es FAIL, no WARN, en el criterio de esta task).
if [ -e "${ROUTERS_YAML}" ]; then
    perm="$(stat -c '%a' "${ROUTERS_YAML}" 2>/dev/null || stat -f '%Lp' "${ROUTERS_YAML}")"
    # cualquier bit fuera de 0600 (grupo u otros con algo) es "más laxo".
    if [ $(( 0${perm} & 0077 )) -ne 0 ]; then
        die "${ROUTERS_YAML} tiene permisos ${perm} (más laxos que 0600) -- chmod 0600 ${ROUTERS_YAML} y volver a correr el instalador"
    fi
    chown root:"${SECISP_GROUP}" "${ROUTERS_YAML}" || true
    log "${ROUTERS_YAML} ya existe con permisos ${perm} (0600 o más estricto), se conserva"
else
    log "${ROUTERS_YAML} no existe todavía -- crearlo con 0600 root:secisp antes de habilitar el mitigador"
fi

# ─── 3. /var/lib/secisp/{wal,templates,state} ───────────────────────────────────────
#
# Los cuatro roles corren como `secisp` (systemd `User=secisp`, ReadWritePaths=
# /var/lib/secisp en las cinco unidades de T-035): el árbol tiene que ser
# escribible por ese usuario, no solo por root.
log "creando ${VAR_LIB_DIR}/{wal,templates,state}"
mkdir -p "${VAR_LIB_DIR}/wal" "${VAR_LIB_DIR}/templates" "${VAR_LIB_DIR}/state"
chown -R "${SECISP_USER}:${SECISP_GROUP}" "${VAR_LIB_DIR}"
chmod 0750 "${VAR_LIB_DIR}" "${VAR_LIB_DIR}/wal" "${VAR_LIB_DIR}/templates" "${VAR_LIB_DIR}/state"

# Requisito duro de E02 §5.7 / E12 §4.2.3: el WAL tiene que vivir en un
# dispositivo DISTINTO al de los datos de ClickHouse. El check real y completo
# (con el fallback al ancestro más cercano que exista) es
# internal/ops/doctor/pre_host.go (T-017); acá se avisa temprano, antes de que
# el operador cargue tráfico, con la misma convención de path
# (/var/lib/clickhouse) que ese check usa para no duplicar un valor distinto.
CLICKHOUSE_DATA_DIR="/var/lib/clickhouse"
wal_dev="$(stat -c '%d' "${VAR_LIB_DIR}/wal" 2>/dev/null || stat -f '%d' "${VAR_LIB_DIR}/wal")"
if [ -e "${CLICKHOUSE_DATA_DIR}" ]; then
    ch_dev="$(stat -c '%d' "${CLICKHOUSE_DATA_DIR}" 2>/dev/null || stat -f '%d' "${CLICKHOUSE_DATA_DIR}")"
    if [ "${wal_dev}" = "${ch_dev}" ]; then
        log "AVISO: ${VAR_LIB_DIR}/wal y ${CLICKHOUSE_DATA_DIR} comparten dispositivo -- mover uno de los dos antes de producción (deadlock documentado en E02 §5.7 / E12 §4.2.3: ClickHouse cae por disco lleno y el WAL no puede drenar nunca). 'secisp doctor --pre' lo va a marcar FAIL (o WARN si corrés con SEC_DOCTOR_ALLOW_SHARED_WAL_DEVICE=true -- solo para laboratorio/prueba, el riesgo de deadlock sigue ahí)."
    else
        log "${VAR_LIB_DIR}/wal y ${CLICKHOUSE_DATA_DIR} están en dispositivos distintos"
    fi
else
    log "${CLICKHOUSE_DATA_DIR} todavía no existe (normal si ClickHouse no arrancó): 'secisp doctor --pre' revalida esto cuando exista"
fi

# ─── 4. /var/backups/secisp ─────────────────────────────────────────────────────────
#
# Destino de `secisp backup` (SEC_OPS_BACKUP_DIR, E12 §5.8), escrito por el
# proceso que corre el backup (CLI bajo el usuario secisp).
log "creando ${BACKUPS_DIR}"
mkdir -p "${BACKUPS_DIR}"
chown "${SECISP_USER}:${SECISP_GROUP}" "${BACKUPS_DIR}"
chmod 0750 "${BACKUPS_DIR}"

# ─── 5. /opt/secisp/infra ───────────────────────────────────────────────────────────
#
# Vive fuera de /etc y /var porque no es config del sistema ni estado de
# secisp: es la infraestructura con estado de E12 §3 D1 (ClickHouse, Prometheus,
# Grafana, Alertmanager) que corre por su cuenta vía `docker compose`. Este
# instalador prepara el árbol y copia lo que ya está versionado; no invoca
# `docker compose up` (ver cabecera).
log "creando ${OPT_INFRA_DIR}"
mkdir -p "${OPT_INFRA_DIR}/prometheus/rules" "${OPT_INFRA_DIR}/grafana/dashboards/secisp" "${OPT_INFRA_DIR}/grafana/provisioning"
chown -R root:root "${OPT_INFRA_DIR}"
chmod -R u=rwX,g=rX,o=rX "${OPT_INFRA_DIR}"

if [ -f "${INFRA_SRC_DIR}/docker-compose.yml" ]; then
    cp -f "${INFRA_SRC_DIR}/docker-compose.yml" "${OPT_INFRA_DIR}/docker-compose.yml"
    log "copiado docker-compose.yml a ${OPT_INFRA_DIR}"
fi
if [ -d "${INFRA_SRC_DIR}/prometheus" ]; then
    cp -Rf "${INFRA_SRC_DIR}/prometheus/." "${OPT_INFRA_DIR}/prometheus/"
fi
if [ -d "${INFRA_SRC_DIR}/clickhouse" ]; then
    mkdir -p "${OPT_INFRA_DIR}/clickhouse"
    cp -Rf "${INFRA_SRC_DIR}/clickhouse/." "${OPT_INFRA_DIR}/clickhouse/"
fi
if [ -d "${INFRA_SRC_DIR}/alertmanager" ]; then
    mkdir -p "${OPT_INFRA_DIR}/alertmanager"
    cp -Rf "${INFRA_SRC_DIR}/alertmanager/." "${OPT_INFRA_DIR}/alertmanager/"
fi
if [ -d "${GRAFANA_DASHBOARDS_SRC_DIR}" ]; then
    cp -Rf "${GRAFANA_DASHBOARDS_SRC_DIR}/." "${OPT_INFRA_DIR}/grafana/dashboards/secisp/" 2>/dev/null || true
fi
if [ -d "${GRAFANA_PROVISIONING_SRC_DIR}" ]; then
    cp -Rf "${GRAFANA_PROVISIONING_SRC_DIR}/." "${OPT_INFRA_DIR}/grafana/provisioning/" 2>/dev/null || true
fi

# ─── 6. Binario ─────────────────────────────────────────────────────────────────────
log "copiando ${BIN_SRC} -> ${BIN_DST}"
install -o root -g root -m 0755 "${BIN_SRC}" "${BIN_DST}"

# ─── 7. Unidades systemd (las cinco de T-035), `systemctl enable` sin arrancar ──────
log "instalando unidades systemd desde ${SYSTEMD_SRC_DIR}"
for unit in secisp-collector.service secisp-engine.service secisp-mitigator.service \
            secisp-watchdog.service secisp-doctor.service secisp-doctor.timer; do
    src="${SYSTEMD_SRC_DIR}/${unit}"
    [ -f "${src}" ] || die "falta ${src} (T-035, E12a-T03)"
    install -o root -g root -m 0644 "${src}" "${SYSTEMD_DST_DIR}/${unit}"
done

systemctl daemon-reload

# Las cuatro unidades de rol más el timer diario de doctor. secisp-doctor.service
# es Type=oneshot disparado por el timer (T-035): no lleva [Install] y no se
# habilita por su cuenta.
for unit in secisp-collector.service secisp-engine.service secisp-mitigator.service \
            secisp-watchdog.service secisp-doctor.timer; do
    systemctl enable "${unit}"
    log "systemctl enable ${unit} (no se arranca)"
done

# ─── 8. sysctl net.core.rmem_max ────────────────────────────────────────────────────
#
# E01 SEC-COL-001 / E12 §4.2.4: el collector necesita SO_RCVBUF >= 16 MiB. Mismo
# archivo (99-secisp.conf) y mismo valor que sugiere `secisp doctor --pre`
# (internal/ops/doctor/pre_host.go): escribir siempre el mismo contenido en el
# mismo archivo es lo que hace esto idempotente en la segunda corrida.
RMEM_MAX_BYTES=16777216
log "escribiendo ${SYSCTL_FILE} (net.core.rmem_max=${RMEM_MAX_BYTES})"
printf 'net.core.rmem_max = %d\n' "${RMEM_MAX_BYTES}" > "${SYSCTL_FILE}"
chmod 0644 "${SYSCTL_FILE}"
sysctl -p "${SYSCTL_FILE}" >/dev/null

# ─── 9. `secisp doctor --pre` ───────────────────────────────────────────────────────
#
# Último paso, siempre: si algo de lo instalado no alcanza (puertos ocupados,
# reloj corrido, disco insuficiente, routers.yaml, dead-man's switch sin
# configurar...), la instalación termina en FAIL y no en "parece que anduvo".
log "corriendo '${BIN_DST} doctor --pre'"
if ! "${BIN_DST}" doctor --pre; then
    die "'secisp doctor --pre' reportó al menos un FAIL -- revisar arriba antes de arrancar los servicios"
fi

log "instalación completa. Los servicios están 'enabled' pero NO arrancados:"
log "  systemctl start secisp-collector secisp-engine secisp-mitigator secisp-watchdog"
log "  systemctl start secisp-doctor.timer"
