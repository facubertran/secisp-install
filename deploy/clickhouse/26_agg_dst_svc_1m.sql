-- 26_agg_dst_svc_1m.sql [E03]
--
-- T-044 (E03-T07) -- E03 §4.5.5 · E00b D-4, D-5, D-7, D-10 · E00c C-1, C-2 ·
-- E00d F-13 · E03 §5.2.
--
-- El lado víctima: uniq_src_ips y uniq_customers, y el estado tipado String
-- que el roll-up de prevalencia (27_agg_dst_svc_1h.sql) va a poder fusionar.
-- Depende de 10_flows_raw.sql y 00_database.sql.

CREATE TABLE IF NOT EXISTS isp.agg_dst_svc_1m
(
    window_start             DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- D-5: columna real, SEGUNDA en el ORDER BY.
    -- E00c C-1: Enum8 idéntico al de flows_raw (10_flows_raw.sql).
    flow_dir                 Enum8('unknown' = 0, 'outbound' = 1, 'inbound' = 2, 'internal' = 3, 'transit' = 4),
    dst_ip                   IPv6            CODEC(ZSTD(1)),
    proto                    UInt8           CODEC(ZSTD(1)),
    dst_port                 UInt16          CODEC(T64, ZSTD(1)),
    dst_asn                  UInt32          CODEC(T64, ZSTD(1)),
    dst_cc                   LowCardinality(String),

    bytes_state              AggregateFunction(sum, UInt64),
    packets_state            AggregateFunction(sum, UInt64),
    flows_state              AggregateFunction(sum, UInt64),
    syn_only_packets_state   AggregateFunction(sum, UInt64),
    uniq_src_ips_state       AggregateFunction(uniqCombined(17), IPv6),
    -- D-4: el nombre es uniq_customers_state, IDÉNTICO al de agg_dst_svc_1h.
    -- Antes se llamaba uniq_src_customers_state y E08 §5.1 R5 la pedía con el
    -- nombre corto; renombrarla acá evita el rebuild el día que E08 la lea.
    uniq_customers_state     AggregateFunction(uniqCombined(12), String),
    sampling_max_state       AggregateFunction(max, UInt32),

    -- D-7: huella de revisita.
    rows_state               AggregateFunction(count),
    last_inserted_state      AggregateFunction(max, DateTime64(3, 'UTC')),

    -- E08 §5.1 R8: la investigación de un caso filtra por dst_ip sobre varias
    -- horas y dst_ip no es prefijo utilizable con flow_dir delante.
    INDEX idx_dst_ip dst_ip TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = AggregatingMergeTree
PARTITION BY toStartOfHour(window_start)
ORDER BY (window_start, flow_dir, dst_ip, proto, dst_port, dst_asn, dst_cc)
TTL window_start + INTERVAL 6 HOUR DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS isp.mv_agg_dst_svc_1m TO isp.agg_dst_svc_1m AS
SELECT
    toStartOfInterval(ts_received, INTERVAL 1 MINUTE, 'UTC') AS window_start,
    flow_dir, dst_ip, proto, dst_port, dst_asn, dst_cc,
    sumState(bytes)                                         AS bytes_state,
    sumState(packets)                                       AS packets_state,
    sumState(toUInt64(flows))                               AS flows_state,
    sumStateIf(packets, tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)     AS syn_only_packets_state,
    uniqCombinedState(17)(src_ip)                           AS uniq_src_ips_state,
    -- E00d F-13: toString() OBLIGATORIO. La columna es
    -- AggregateFunction(uniqCombined(12), String) y customer_id es
    -- LowCardinality(String): sin el cast el estado que produce la MV es
    -- AggregateFunction(uniqCombined(12), LowCardinality(String)), que NO es el
    -- mismo tipo. Es un error de tipo en una MV -> clase `schema` -> detiene el sink.
    uniqCombinedState(12)(toString(customer_id))            AS uniq_customers_state,
    maxState(sampling_applied)                              AS sampling_max_state,
    countState()                                            AS rows_state,
    maxState(ts_inserted)                                   AS last_inserted_state
FROM isp.flows_raw
WHERE flow_dir IN ('outbound', 'internal')
GROUP BY window_start, flow_dir, dst_ip, proto, dst_port, dst_asn, dst_cc;

-- Vista con GROUP BY (E03 §4.6, §5.2).
CREATE OR REPLACE VIEW isp.v_agg_dst_svc_1m
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
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str,
    proto, dst_port, dst_asn, dst_cc,
    sumMerge(bytes_state)                          AS bytes,
    sumMerge(packets_state)                        AS packets,
    sumMerge(flows_state)                          AS flows,
    sumMerge(syn_only_packets_state)               AS syn_only_packets,
    uniqCombinedMerge(17)(uniq_src_ips_state)      AS uniq_src_ips,
    uniqCombinedMerge(12)(uniq_customers_state)    AS uniq_customers,
    maxMerge(sampling_max_state)                   AS sampling_max,
    countMerge(rows_state)                         AS rows,
    maxMerge(last_inserted_state)                  AS last_inserted,
    sumMerge(packets_state) / 60.0                 AS pps,
    sumMerge(bytes_state) * 8.0 / 60.0             AS bps
FROM isp.agg_dst_svc_1m
GROUP BY window_start, flow_dir, dst_ip, proto, dst_port, dst_asn, dst_cc;

-- Vista _flat (E00b D-10 / E00c C-2): SIN GROUP BY, finalizeAggregation()
-- fila a fila.
CREATE OR REPLACE VIEW isp.v_agg_dst_svc_1m_flat
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
    dst_ip, isp_ip_str(dst_ip) AS dst_ip_str,
    proto, dst_port, dst_asn, dst_cc,
    finalizeAggregation(bytes_state)               AS bytes,
    finalizeAggregation(packets_state)             AS packets,
    finalizeAggregation(flows_state)               AS flows,
    finalizeAggregation(syn_only_packets_state)    AS syn_only_packets,
    finalizeAggregation(uniq_src_ips_state)        AS uniq_src_ips,
    finalizeAggregation(uniq_customers_state)      AS uniq_customers,
    finalizeAggregation(sampling_max_state)        AS sampling_max,
    finalizeAggregation(rows_state)                AS rows,
    finalizeAggregation(last_inserted_state)       AS last_inserted
FROM isp.agg_dst_svc_1m;
