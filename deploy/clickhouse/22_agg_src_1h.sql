-- 22_agg_src_1h.sql [E03]
--
-- T-045 (E03-T08) -- E03 §3 D5, §4.5.3 · E00b D-12 · E00c C-13 · E03 §5.2 ·
-- E03 §9.4 [E00b D-5].
--
-- La serie de 400 días por cliente y hora con las cardinalidades FUSIONADAS a
-- la hora (no por minuto): es lo único sobre lo que E09 puede construir un
-- baseline correcto. NO es una MV: es un roll-up programado (`secisp schema
-- rollup`, T-097) que MERGEA los estados de agg_src_1m. Columnas escalares
-- puras, sin AggregateFunction. Depende de 21_agg_src_1m.sql.

CREATE TABLE IF NOT EXISTS isp.agg_src_1h
(
    window_start      DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    src_ip            IPv6            CODEC(ZSTD(1)),
    customer_id       LowCardinality(String),
    src_scope         Enum8('unknown' = 0, 'customer' = 1, 'infra' = 2, 'external' = 3),

    bytes             UInt64  CODEC(T64, ZSTD(1)),
    packets           UInt64  CODEC(T64, ZSTD(1)),
    flows             UInt64  CODEC(T64, ZSTD(1)),
    tcp_packets       UInt64  CODEC(T64, ZSTD(1)),
    udp_packets       UInt64  CODEC(T64, ZSTD(1)),
    icmp_packets      UInt64  CODEC(T64, ZSTD(1)),
    syn_only_packets  UInt64  CODEC(T64, ZSTD(1)),

    -- Cardinalidades YA FUSIONADAS: números, no estados. Ese es el punto de D5.
    uniq_dst_ips      UInt64  CODEC(T64, ZSTD(1)),
    uniq_dst_ports    UInt64  CODEC(T64, ZSTD(1)),
    uniq_dst_nets     UInt64  CODEC(T64, ZSTD(1)),

    -- Percentiles del minuto DENTRO de la hora: lo que E09 necesita para
    -- distinguir "1 GB repartido en la hora" de "1 GB en un minuto".
    pps_p50           Float32,
    pps_p95           Float32,
    pps_max           Float32,
    bps_p95           Float32,
    bps_max           Float32,
    active_minutes    UInt16,

    sampling_max      UInt32  CODEC(DoubleDelta, ZSTD(1)),
    rolled_at         DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(rolled_at)
PARTITION BY toYYYYMM(window_start)
ORDER BY (window_start, src_ip, customer_id, src_scope)
TTL window_start + INTERVAL 400 DAY DELETE
SETTINGS index_granularity = 8192;

-- Proyección de lectura simple: agg_src_1h ya es escalar. Sin FINAL (E03-14
-- tolera ±1 %; el dedup exacto se verifica aparte con `agg_src_1h FINAL`) y
-- sin flow_dir: es 'outbound' por construcción del roll-up (E03 §5.2).
CREATE OR REPLACE VIEW isp.v_agg_src_1h
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
    window_start, src_ip, isp_ip_str(src_ip) AS src_ip_str, customer_id, src_scope,
    bytes, packets, flows, tcp_packets, udp_packets, icmp_packets, syn_only_packets,
    uniq_dst_ips, uniq_dst_ports, uniq_dst_nets,
    pps_p50, pps_p95, pps_max, bps_p95, bps_max, active_minutes, sampling_max
FROM isp.agg_src_1h;

-- ============================================================================
-- Roll-up canónico de DOS PASADAS (E00b D-12), texto que `secisp schema
-- rollup` (E03 §4.9.2, T-097) ejecuta con {from:DateTime} y {to:DateTime}
-- acotando la hora a procesar. NO es DDL instalable: es job programado, no
-- una MV (ADR-007/008 aplican a MVs, no a jobs), así que va documentado acá y
-- no como CREATE. `secisp schema apply` no lo toca -- no hay ningún `CREATE`
-- que lo envuelva.
--
-- Por qué DOS pasadas y no una: agrupar por columnas AggregateFunction no
-- compila, y aunque se arreglara con any() dejaría las cardinalidades POR
-- MINUTO en vez de fusionadas a la hora (D-12): un cliente que toca 300
-- destinos/minuto durante una hora quedaría con uniq_dst_ips=300 en vez de
-- ~18.000, y el baseline de E09 se construiría sobre un número
-- sistemáticamente bajo, en silencio.
--
-- El alias de la hora es `hour`, NUNCA `window_start` (E00c C-13): con el
-- mismo nombre que la columna base, `GROUP BY window_start` es
-- CYCLIC_ALIASES o agrupa por minuto y dejaría active_minutes=1 en 60 filas
-- que el ReplacingMergeTree(rolled_at) colapsaría a una arbitraria SIN NINGÚN
-- ERROR. La proyección a `window_start` se hace recién en el INSERT externo.
--
-- INSERT INTO isp.agg_src_1h
-- SELECT
--     a.hour                                            AS window_start,
--     a.src_ip                                          AS src_ip,
--     a.customer_id                                     AS customer_id,
--     a.src_scope                                       AS src_scope,
--     a.bytes                                           AS bytes,
--     a.packets                                         AS packets,
--     a.flows                                           AS flows,
--     a.tcp_packets                                     AS tcp_packets,
--     a.udp_packets                                     AS udp_packets,
--     a.icmp_packets                                    AS icmp_packets,
--     a.syn_only_packets                                AS syn_only_packets,
--     b.uniq_dst_ips                                    AS uniq_dst_ips,
--     b.uniq_dst_ports                                  AS uniq_dst_ports,
--     b.uniq_dst_nets                                   AS uniq_dst_nets,
--     toFloat32(a.pps_p50)                              AS pps_p50,
--     toFloat32(a.pps_p95)                              AS pps_p95,
--     toFloat32(a.pps_max)                              AS pps_max,
--     toFloat32(a.bps_p95)                              AS bps_p95,
--     toFloat32(a.bps_max)                              AS bps_max,
--     toUInt16(a.active_minutes)                        AS active_minutes,
--     a.sampling_max                                    AS sampling_max,
--     now64(3)                                          AS rolled_at
-- FROM
-- (
--     SELECT
--         toStartOfHour(window_start)                   AS hour,
--         src_ip, customer_id, src_scope,
--         sum(bytes)                                    AS bytes,
--         sum(packets)                                  AS packets,
--         sum(flows)                                    AS flows,
--         sum(tcp_packets)                               AS tcp_packets,
--         sum(udp_packets)                              AS udp_packets,
--         sum(icmp_packets)                             AS icmp_packets,
--         sum(syn_only_packets)                         AS syn_only_packets,
--         quantile(0.50)(pps)                           AS pps_p50,
--         quantile(0.95)(pps)                           AS pps_p95,
--         max(pps)                                      AS pps_max,
--         quantile(0.95)(bps)                           AS bps_p95,
--         max(bps)                                      AS bps_max,
--         count()                                       AS active_minutes,
--         max(sampling_max)                             AS sampling_max
--     FROM
--     (
--         SELECT
--             window_start, src_ip, customer_id, src_scope,
--             sumMerge(bytes_state)                     AS bytes,
--             sumMerge(packets_state)                   AS packets,
--             sumMerge(flows_state)                     AS flows,
--             sumMerge(tcp_packets_state)                AS tcp_packets,
--             sumMerge(udp_packets_state)                AS udp_packets,
--             sumMerge(icmp_packets_state)               AS icmp_packets,
--             sumMerge(syn_only_packets_state)          AS syn_only_packets,
--             sumMerge(packets_state) / 60.0             AS pps,
--             sumMerge(bytes_state) * 8.0 / 60.0         AS bps,
--             maxMerge(sampling_max_state)               AS sampling_max
--         FROM isp.agg_src_1m
--         WHERE window_start >= {from:DateTime}
--           AND window_start <  {to:DateTime}
--           AND flow_dir = 'outbound'
--         GROUP BY window_start, src_ip, customer_id, src_scope
--     )
--     GROUP BY hour, src_ip, customer_id, src_scope
-- ) AS a
-- INNER JOIN
-- (
--     SELECT
--         toStartOfHour(window_start)                   AS hour,
--         src_ip, customer_id, src_scope,
--         uniqCombinedMerge(17)(uniq_dst_ips_state)     AS uniq_dst_ips,
--         uniqCombinedMerge(17)(uniq_dst_ports_state)   AS uniq_dst_ports,
--         uniqCombinedMerge(17)(uniq_dst_nets_state)    AS uniq_dst_nets
--     FROM isp.agg_src_1m
--     WHERE window_start >= {from:DateTime}
--       AND window_start <  {to:DateTime}
--       AND flow_dir = 'outbound'
--     GROUP BY hour, src_ip, customer_id, src_scope
-- ) AS b
-- USING (hour, src_ip, customer_id, src_scope)
-- SETTINGS max_memory_usage       = 4294967296,
--          max_execution_time     = 600,
--          join_algorithm         = 'partial_merge',
--          max_threads            = 4;
-- ============================================================================
