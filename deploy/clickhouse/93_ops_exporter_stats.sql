-- 93_ops_exporter_stats.sql [E12]
--
-- T-088 (E12a-T28) -- E12 §5.0, §5.2 · E00b D-13 · E01 §9 Q9 · E03 §4.9.1.
--
-- Resuelve la pregunta Q9 de E01 con la opción (a) que esa épica propuso: el
-- WATCHDOG hace `GET /debug/exporters` al collector y escribe esta tabla. El
-- collector sigue escribiendo solo `flows_raw` (E00 §2.3): esta tabla no
-- rompe "una tabla, un escritor" porque el escritor sigue siendo uno solo
-- (`watchdog`), distinto del que expone el dato (`collector`).
--
-- ReplacingMergeTree(minute) porque cada minuto reemplaza al anterior para
-- el mismo (exporter_id, obs_domain_id): es una foto de estado, no un evento
-- que se acumule. Consumidores: E10 (panel de salud por router) y el propio
-- watchdog (tendencia de flows_lost_estimate).
CREATE TABLE IF NOT EXISTS isp.ops_exporter_stats
(
    minute                DateTime('UTC'),
    exporter_id           LowCardinality(String),
    exporter_ip           IPv6,
    obs_domain_id         UInt32,
    known                 UInt8,
    protos                Array(LowCardinality(String)),
    last_seen             DateTime('UTC'),
    silent_seconds        UInt32,
    packets_total         UInt64,
    flows_total           UInt64,
    decode_errors_total   UInt64,
    template_misses_total UInt64,
    templates_cached      UInt16,
    seq_gaps_total        UInt64,
    flows_lost_estimate   UInt64,
    sampling_applied      UInt32,
    sampling_source       Enum8('none' = 0, 'inband' = 1, 'registry' = 2, 'default' = 3),
    export_lag_p95_s      Float32
)
ENGINE = ReplacingMergeTree(minute)
PARTITION BY toYYYYMM(minute)
ORDER BY (exporter_id, obs_domain_id, minute)
TTL minute + INTERVAL 90 DAY DELETE;

-- Va en el MISMO archivo que su tabla y no en 94c_ops_views.sql: esta vista
-- es de las que 94c_ops_views.sql LEE (E12 §5.5), así que tiene que existir
-- con número menor que 94c cuando ese archivo corre (E00f H-1 / E00e G-3: un
-- CREATE VIEW sobre un objeto de número mayor aborta el archivo entero).
CREATE OR REPLACE VIEW isp.v_ops_exporters
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 24.8 real: sin esta línea, secisp_grafana/secisp_ro reciben
-- ACCESS_DENIED apenas consultan la vista. Sin DEFINER = ... explícito por
-- la misma razón que isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops
-- todavía no existe a esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT * FROM isp.ops_exporter_stats FINAL;
