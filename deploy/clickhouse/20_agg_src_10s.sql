-- 20_agg_src_10s.sql [E03]
--
-- T-041 (E03-T04) -- E03 §3 D2, §4.5.1 · E00b D-3, D-5, D-6, D-7, D-8, D-9 ·
-- E00c C-1 · E03 §5.2.
--
-- Ventana corta que sostiene O1 (MTTD flood p95 <= 90 s). Puramente
-- volumétrica (D2): CERO estados de cardinalidad -- D-3 los rechaza
-- explícitamente para esta tabla (es la de mayor cardinalidad del esquema, una
-- fila por 10s x IP de cliente activa) y los deja en agg_src_1m, que ya los
-- tiene. Depende de 10_flows_raw.sql.

CREATE TABLE IF NOT EXISTS isp.agg_src_10s
(
    window_start           DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- D-5: columna real, SEGUNDA en el ORDER BY. No es un filtro de la MV.
    -- E00c C-1: el Enum8 es EXACTAMENTE el de flows_raw (10_flows_raw.sql). Si
    -- acá dijera 'unknown'=5, el CAST Enum->Enum que arma la MV se rechaza y
    -- el INSERT del sink falla entero como clase `schema`.
    flow_dir               Enum8('unknown' = 0, 'outbound' = 1, 'inbound' = 2, 'internal' = 3, 'transit' = 4),
    src_ip                 IPv6            CODEC(ZSTD(1)),
    customer_id            LowCardinality(String),
    src_scope              Enum8('unknown' = 0, 'customer' = 1, 'infra' = 2, 'external' = 3),

    bytes_state            AggregateFunction(sum, UInt64),
    packets_state          AggregateFunction(sum, UInt64),
    flows_state            AggregateFunction(sum, UInt64),
    tcp_packets_state      AggregateFunction(sum, UInt64),
    udp_packets_state      AggregateFunction(sum, UInt64),
    icmp_packets_state     AggregateFunction(sum, UInt64),
    -- D-6: proto NOT IN (1,6,17,58). GRE, ESP y proto 0 son vectores reales;
    -- sin esta columna el attack_subtype del flood miente.
    other_packets_state    AggregateFunction(sum, UInt64),
    syn_only_packets_state AggregateFunction(sum, UInt64),

    -- D-6: contadores de FLUJOS (intentos), no de paquetes.
    syn_only_flows_state   AggregateFunction(sum, UInt64),
    tcp_flows_state        AggregateFunction(sum, UInt64),
    -- D-6: flujos de fragmentos, proto IN (6,17) AND dst_port = 0.
    -- Única forma de ver un flood de fragmentos sin DPI.
    frag_flows_state       AggregateFunction(sum, UInt64),

    sampling_max_state     AggregateFunction(max, UInt32),

    -- D-7: huella de revisita.
    rows_state             AggregateFunction(count),
    last_inserted_state    AggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toStartOfHour(window_start)
ORDER BY (window_start, flow_dir, src_ip, customer_id, src_scope)
TTL window_start + INTERVAL 6 HOUR DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS isp.mv_agg_src_10s TO isp.agg_src_10s AS
SELECT
    toStartOfInterval(ts_received, INTERVAL 10 SECOND, 'UTC') AS window_start,
    flow_dir,
    src_ip,
    customer_id,
    src_scope,
    sumState(bytes)                                        AS bytes_state,
    sumState(packets)                                      AS packets_state,
    sumState(toUInt64(flows))                              AS flows_state,
    sumStateIf(packets, proto = 6)                         AS tcp_packets_state,
    sumStateIf(packets, proto = 17)                        AS udp_packets_state,
    sumStateIf(packets, proto IN (1, 58))                  AS icmp_packets_state,
    sumStateIf(packets, proto NOT IN (1, 6, 17, 58))       AS other_packets_state,
    sumStateIf(packets, tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)    AS syn_only_packets_state,

    sumStateIf(toUInt64(flows), tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)    AS syn_only_flows_state,
    sumStateIf(toUInt64(flows), proto = 6)                 AS tcp_flows_state,
    sumStateIf(toUInt64(flows), proto IN (6, 17)
                            AND dst_port = 0)              AS frag_flows_state,

    maxState(sampling_applied)                             AS sampling_max_state,

    countState()                                           AS rows_state,
    maxState(ts_inserted)                                  AS last_inserted_state
FROM isp.flows_raw
WHERE flow_dir IN ('outbound', 'internal')
GROUP BY window_start, flow_dir, src_ip, customer_id, src_scope;

-- Contrato de lectura, E03 §5.2: tcp_packets + udp_packets + icmp_packets +
-- other_packets = packets es una identidad verificable, no una aproximación.
-- No hay uniq_* acá (D2 · D-3): la cardinalidad se lee de v_agg_src_1m.
CREATE OR REPLACE VIEW isp.v_agg_src_10s
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
    window_start, flow_dir, src_ip, isp_ip_str(src_ip) AS src_ip_str,
    customer_id, src_scope,
    sumMerge(bytes_state)              AS bytes,
    sumMerge(packets_state)            AS packets,
    sumMerge(flows_state)              AS flows,
    sumMerge(tcp_packets_state)        AS tcp_packets,
    sumMerge(udp_packets_state)        AS udp_packets,
    sumMerge(icmp_packets_state)       AS icmp_packets,
    sumMerge(other_packets_state)      AS other_packets,
    sumMerge(syn_only_packets_state)   AS syn_only_packets,
    sumMerge(syn_only_flows_state)     AS syn_only_flows,
    sumMerge(tcp_flows_state)          AS tcp_flows,
    sumMerge(frag_flows_state)         AS frag_flows,
    maxMerge(sampling_max_state)       AS sampling_max,
    countMerge(rows_state)             AS rows,
    maxMerge(last_inserted_state)      AS last_inserted,
    sumMerge(packets_state) / 10.0     AS pps,
    sumMerge(bytes_state) * 8.0 / 10.0 AS bps
FROM isp.agg_src_10s
GROUP BY window_start, flow_dir, src_ip, customer_id, src_scope;
