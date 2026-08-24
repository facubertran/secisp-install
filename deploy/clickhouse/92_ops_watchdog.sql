-- 92_ops_watchdog.sql [E12]
--
-- T-088 (E12a-T28) -- E12 §5.0, §5.1 · E00b D-13 · E00e no-bloqueante #1 ·
-- E03 §4.9.1.
--
-- Historial de checks del watchdog (E12 §4.8). Sirve para dos cosas que
-- Prometheus no da bien: correlacionar un fallo con el `detail` textual
-- (Prometheus no guarda strings) y responder "¿cuántas veces falló esto en 6
-- meses?" más allá de la retención de 30 días de la TSDB. La escribe
-- exclusivamente `watchdog`; la leen E12 (runbooks) y E10 (panel de salud).
--
-- Discrepancia de nombres DELIBERADA (E00e no-bloqueante #1): el archivo se
-- llama `92_ops_watchdog.sql` pero la tabla es `isp.ops_watchdog_checks`, no
-- `isp.ops_watchdog`. E00e la clasificó como no bloqueante -- "se corrige si
-- el archivo se toca, no justifica otra ronda" -- y decidió no tocarla acá:
-- no es un typo a corregir, es el nombre vigente.
--
-- Solo se escribe en cambio de estado confirmado más una fila por check por
-- hora como heartbeat (E12 §5.1): a 25 checks son ~600 filas/día.
CREATE TABLE IF NOT EXISTS isp.ops_watchdog_checks
(
    ts          DateTime('UTC'),
    instance    LowCardinality(String),
    check_name  LowCardinality(String),
    ok          UInt8,
    severity    Enum8('warning' = 1, 'critical' = 2),
    -- skipped = una dependencia del check estaba caída (no es que pasó ni que falló).
    state       Enum8('up' = 1, 'down' = 2, 'skipped' = 3),
    streak      UInt16,                                -- rondas consecutivas en falla
    value       Float64,                               -- valor numérico auxiliar del check
    duration_ms UInt32,
    detail      String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (check_name, ts)
TTL ts + INTERVAL 180 DAY DELETE;
