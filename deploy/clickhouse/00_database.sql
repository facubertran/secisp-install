-- 00_database.sql [E03]
--
-- T-037 (E03-T01) -- E03 §4.4, §4.9.1 · E00b D-34 · E00d F-2 · E03 §7 (riesgo
-- EXCHANGE TABLES sobre Ordinary).
--
-- Primer archivo del layout de deploy/clickhouse/ (E03 §4.9.1, D-13: el orden
-- lexicografico por BYTES de este directorio ES el orden de dependencias).
-- Deja la base en ENGINE=Atomic -- sin el, EXCHANGE TABLES del rebuild de
-- §4.9.4 deja de ser atomico, y `secisp schema verify` tiene que fallar si
-- system.databases.engine != 'Atomic' -- las dos UDFs de render de E03 y la
-- tabla de versionado que todo proceso `secisp` consulta al arrancar
-- (SEC-OPS-003, E00 §4.5.1).

CREATE DATABASE IF NOT EXISTS isp ENGINE = Atomic;

-- Render humano. La usan TODAS las vistas y todos los paneles.
-- ::ffff:190.1.2.3 -> 190.1.2.3 ; 2001:db8::1 -> 2001:db8::1
--
-- ClickHouse no admite '.' en el nombre de una UDF: el prefijo de namespace
-- es isp_ y no isp. -- E00b D-34 fija isp_ip_str como el UNICO nombre del
-- sistema; ni ip_str( a secas ni isp.ip_str( son validos en ninguna epica.
--
-- Esta UDF es para vistas y paneles, NUNCA para MVs de ingesta: una MV que la
-- referencia queda rota si alguien la dropea o la recrea con otra aridad, y
-- el modo de falla es un INSERT abortado que en un sistema sin Kafka
-- significa WAL. En las MVs la expresion va inline aunque sea mas verbosa.
CREATE FUNCTION IF NOT EXISTS isp_ip_str AS (ip) ->
    replaceRegexpOne(IPv6NumToString(toIPv6(ip)), '^::ffff:', '');

-- Prefijo de red en forma IPv4-mapped. bits_v4 es la longitud EN IPv4
-- (24 -> /24), bits_v6 la longitud en IPv6 (48 -> /48).
CREATE FUNCTION IF NOT EXISTS isp_ip_net AS (ip, ver, bits_v4, bits_v6) ->
    tupleElement(
        IPv6CIDRToRange(toIPv6(ip), toUInt8(if(ver = 4, 96 + bits_v4, bits_v6))),
        1);

-- Registro de lo que el instalador (`secisp schema apply`) aplico: un archivo
-- del layout puede aparecer varias veces si se re-aplica tras un cambio de
-- forma compatible (CREATE ... IF NOT EXISTS / CREATE OR REPLACE VIEW); la
-- ultima fila por (version, file) manda por ReplacingMergeTree(applied_at).
-- La idempotencia del instalador es por sha256 contra esta tabla, NO por
-- IF NOT EXISTS (E03 §4.9.2).
CREATE TABLE IF NOT EXISTS isp.ops_schema_version
(
    version     UInt32,
    file        String,
    sha256      FixedString(64),
    applied_at  DateTime64(3, 'UTC') DEFAULT now64(3),
    applied_by  LowCardinality(String),          -- hostname del que aplico
    binary_ver  LowCardinality(String),          -- version del binario secisp
    duration_ms UInt32,
    status      Enum8('ok' = 1, 'failed' = 2, 'skipped' = 3),
    error       String CODEC(ZSTD(3))
)
ENGINE = ReplacingMergeTree(applied_at)
ORDER BY (version, file);
