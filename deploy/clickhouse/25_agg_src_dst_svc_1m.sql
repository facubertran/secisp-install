-- 25_agg_src_dst_svc_1m.sql [E03]
--
-- T-043 (E03-T06) -- E03 §3 D3, D4, §4.5.4 · E00b D-5, D-6, D-7, D-10, D-11 ·
-- E00c C-1, C-2 · E03 §5.2.
--
-- La tabla más grande del esquema: el par atacante -> víctima. Responde hacia
-- qué víctimas, alimenta top_dsts, el drill-down del panel y la resolución de
-- víctimas del mitigador. Depende de 10_flows_raw.sql y 00_database.sql.
--
-- PROHIBIDO filtrar en la MV con un HAVING de volumen: una MV solo ve el
-- bloque insertado (~2 s de tráfico) y descartaría filas que sí cruzarían el
-- umbral al mergear el minuto completo -- pérdida de datos silenciosa.

CREATE TABLE IF NOT EXISTS isp.agg_src_dst_svc_1m
(
    window_start            DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- D-5: columna real, SEGUNDA en el ORDER BY.
    -- E00c C-1: Enum8 idéntico al de flows_raw (10_flows_raw.sql).
    flow_dir                Enum8('unknown' = 0, 'outbound' = 1, 'inbound' = 2, 'internal' = 3, 'transit' = 4),
    src_ip                  IPv6            CODEC(ZSTD(1)),
    dst_ip                  IPv6            CODEC(ZSTD(1)),
    proto                   UInt8           CODEC(ZSTD(1)),
    dst_port                UInt16          CODEC(T64, ZSTD(1)),
    dst_asn                 UInt32          CODEC(T64, ZSTD(1)),
    -- D-11: barata y funcionalmente determinada por src_ip. Evita derivarla
    -- con una comparación de rangos IPv4-mapped en cada query de E06/E08.
    ip_version              UInt8           CODEC(ZSTD(1)),

    bytes_state             AggregateFunction(sum, UInt64),
    packets_state           AggregateFunction(sum, UInt64),
    flows_state             AggregateFunction(sum, UInt64),
    syn_only_packets_state  AggregateFunction(sum, UInt64),
    established_flows_state AggregateFunction(sum, UInt64),
    flags_valid_flows_state AggregateFunction(sum, UInt64),

    -- D-6: contadores de FLUJOS.
    syn_only_flows_state    AggregateFunction(sum, UInt64),
    tcp_flows_state         AggregateFunction(sum, UInt64),

    first_seen_state        AggregateFunction(min, DateTime64(3, 'UTC')),
    last_seen_state         AggregateFunction(max, DateTime64(3, 'UTC')),
    sampling_max_state      AggregateFunction(max, UInt32),

    -- D-7: huella de revisita.
    rows_state              AggregateFunction(count),
    last_inserted_state     AggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toStartOfHour(window_start)
ORDER BY (window_start, flow_dir, src_ip, dst_ip, proto, dst_port, dst_asn, ip_version)
TTL window_start + INTERVAL 6 HOUR DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS isp.mv_agg_src_dst_svc_1m TO isp.agg_src_dst_svc_1m AS
SELECT
    toStartOfInterval(ts_received, INTERVAL 1 MINUTE, 'UTC') AS window_start,
    flow_dir, src_ip, dst_ip, proto, dst_port, dst_asn, ip_version,
    sumState(bytes)                                         AS bytes_state,
    sumState(packets)                                       AS packets_state,
    sumState(toUInt64(flows))                               AS flows_state,
    sumStateIf(packets, tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)     AS syn_only_packets_state,
    sumStateIf(toUInt64(flows), tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x10) != 0)       AS established_flows_state,
    sumStateIf(toUInt64(flows), tcp_flags_valid = 1)        AS flags_valid_flows_state,
    sumStateIf(toUInt64(flows), tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)     AS syn_only_flows_state,
    sumStateIf(toUInt64(flows), proto = 6)                  AS tcp_flows_state,
    minState(ts_start)                                      AS first_seen_state,
    maxState(ts_end)                                        AS last_seen_state,
    maxState(sampling_applied)                              AS sampling_max_state,
    countState()                                            AS rows_state,
    maxState(ts_inserted)                                   AS last_inserted_state
FROM isp.flows_raw
WHERE flow_dir IN ('outbound', 'internal')
GROUP BY window_start, flow_dir, src_ip, dst_ip, proto, dst_port, dst_asn, ip_version;

-- Vista con GROUP BY (E03 §4.6, §5.2). No expone customer_id ni dst_cc (D-11):
-- customer_id se resuelve por src_ip contra v_agg_src_1m; dst_cc sale del evento.
CREATE OR REPLACE VIEW isp.v_agg_src_dst_svc_1m
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
    window_start, flow_dir,
    src_ip, isp_ip_str(src_ip) AS src_ip_str,
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str,
    proto, dst_port, dst_asn, ip_version,
    sumMerge(bytes_state)             AS bytes,
    sumMerge(packets_state)           AS packets,
    sumMerge(flows_state)             AS flows,
    sumMerge(syn_only_packets_state)  AS syn_only_packets,
    sumMerge(established_flows_state) AS established_flows,
    sumMerge(flags_valid_flows_state) AS flags_valid_flows,
    sumMerge(syn_only_flows_state)    AS syn_only_flows,
    sumMerge(tcp_flows_state)         AS tcp_flows,
    minMerge(first_seen_state)        AS first_seen,
    maxMerge(last_seen_state)         AS last_seen,
    maxMerge(sampling_max_state)      AS sampling_max,
    countMerge(rows_state)            AS rows,
    maxMerge(last_inserted_state)     AS last_inserted,
    sumMerge(packets_state) / 60.0     AS pps,
    sumMerge(bytes_state) * 8.0 / 60.0 AS bps
FROM isp.agg_src_dst_svc_1m
GROUP BY window_start, flow_dir, src_ip, dst_ip, proto, dst_port, dst_asn, ip_version;

-- Vista _flat (E00b D-10 / E00c C-2): SIN GROUP BY, finalizeAggregation() fila
-- a fila. Puede devolver más de una fila por clave (una por parte no
-- mergeada) cuando hay partes sin fusionar (E03 §4.6.1).
CREATE OR REPLACE VIEW isp.v_agg_src_dst_svc_1m_flat
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
    window_start, flow_dir,
    src_ip, isp_ip_str(src_ip) AS src_ip_str,
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str,
    proto, dst_port, dst_asn, ip_version,
    finalizeAggregation(bytes_state)               AS bytes,
    finalizeAggregation(packets_state)             AS packets,
    finalizeAggregation(flows_state)               AS flows,
    finalizeAggregation(syn_only_packets_state)    AS syn_only_packets,
    finalizeAggregation(established_flows_state)   AS established_flows,
    finalizeAggregation(flags_valid_flows_state)   AS flags_valid_flows,
    finalizeAggregation(syn_only_flows_state)      AS syn_only_flows,
    finalizeAggregation(tcp_flows_state)           AS tcp_flows,
    finalizeAggregation(first_seen_state)          AS first_seen,
    finalizeAggregation(last_seen_state)           AS last_seen,
    finalizeAggregation(sampling_max_state)        AS sampling_max,
    finalizeAggregation(rows_state)                AS rows,
    finalizeAggregation(last_inserted_state)       AS last_inserted
FROM isp.agg_src_dst_svc_1m;
