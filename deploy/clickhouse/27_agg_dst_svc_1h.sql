-- 27_agg_dst_svc_1h.sql [E03]
--
-- T-046 (E03-T09) -- E03 §4.5.8, §4.5.3 · E00b D-4 · E00c C-13 · E00d F-13 ·
-- E03 §9.4 [E00b D-4] · E03 §5.5.
--
-- Tabla de 30 días que sostiene la guarda de prevalencia de E08 §4.7 sin
-- pagar 30 días de agg_dst_svc_1m (que vive solo 6 h). Depende de
-- 26_agg_dst_svc_1m.sql.

CREATE TABLE IF NOT EXISTS isp.agg_dst_svc_1h
(
    window_start          DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    dst_ip                IPv6            CODEC(ZSTD(1)),
    proto                 UInt8           CODEC(ZSTD(1)),
    dst_port              UInt16          CODEC(T64, ZSTD(1)),

    -- Lo ÚNICO que la prevalencia necesita. Sigue siendo un ESTADO, no un
    -- número: E08 pregunta por rangos de 7 y de 30 días, y eso exige volver a
    -- fusionar. Mismo nombre y misma precisión que en agg_dst_svc_1m (D-4).
    uniq_customers_state  AggregateFunction(uniqCombined(12), String)
)
ENGINE = AggregatingMergeTree
PARTITION BY toYYYYMM(window_start)
-- Única tabla del esquema cuya clave no empieza por tiempo, y es deliberado:
-- el 100 % de sus lecturas es "¿qué prevalencia tiene ESTE destino en los
-- últimos N días?" -- un dst_ip fijo contra un rango de tiempo largo.
ORDER BY (dst_ip, proto, dst_port, window_start)
TTL window_start + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

CREATE OR REPLACE VIEW isp.v_agg_dst_svc_1h
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
SELECT
    window_start,
    dst_ip,
    isp_ip_str(dst_ip)                            AS dst_ip_str,
    proto,
    dst_port,
    uniqCombinedMerge(12)(uniq_customers_state)   AS uniq_customers
FROM isp.agg_dst_svc_1h
GROUP BY window_start, dst_ip, proto, dst_port;

-- ============================================================================
-- Roll-up de prevalencia (E00b D-4), texto que `secisp schema rollup`
-- (E03 §4.9.2, T-097) ejecuta con {from:DateTime}, {to:DateTime} y
-- {min_customers:UInt32}. NO es DDL instalable: ver la nota de
-- 22_agg_src_1h.sql sobre por qué un job programado va documentado y no como
-- CREATE.
--
-- uniqCombinedMergeState fusiona los 60 estados del minuto y VUELVE A
-- SERIALIZAR UN ESTADO: es lo que permite pedir prevalencia sobre 7 o 30 días
-- con un solo uniqCombinedMerge(12) más sobre las horas.
--
-- El HAVING de min_customers (default 2) es lo que hace que esta tabla cueste
-- ~1 % de la opción cara: no pierde información porque la prevalencia es
-- uniq_customers/active_customers y un destino tocado por un solo cliente
-- tiene prevalencia mínima por definición.
--
-- Este roll-up NO lleva toString() -- no es un olvido (E00d F-13, §9.6): acá
-- el argumento no es customer_id, es la columna de estado uniq_customers_state
-- de agg_dst_svc_1m, y uniqCombinedMergeState hereda el tipo del estado que
-- fusiona. Si alguien saca el toString() de la MV de 26_agg_dst_svc_1m.sql,
-- esta query deja de compilar también.
--
-- INSERT INTO isp.agg_dst_svc_1h
-- SELECT
--     hour                                              AS window_start,
--     dst_ip,
--     proto,
--     dst_port,
--     uniq_customers_h                                  AS uniq_customers_state
-- FROM
-- (
--     SELECT
--         toStartOfHour(window_start)                       AS hour,
--         dst_ip, proto, dst_port,
--         uniqCombinedMergeState(12)(uniq_customers_state)  AS uniq_customers_h
--     FROM isp.agg_dst_svc_1m
--     WHERE window_start >= {from:DateTime}
--       AND window_start <  {to:DateTime}
--       AND flow_dir IN ('outbound', 'internal')
--     GROUP BY hour, dst_ip, proto, dst_port
--     HAVING uniqCombinedMerge(12)(uniq_customers_state) >= {min_customers:UInt32}
-- )
-- SETTINGS max_memory_usage   = 4294967296,
--          max_execution_time = 600;
-- ============================================================================
