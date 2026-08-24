-- 21_agg_src_1m.sql [E03]
--
-- T-042 (E03-T05) -- E03 §4.5.2, §4.6, §4.6.1 · E00b D-5, D-6, D-7, D-10 ·
-- E00c C-1, C-2 · E03 §9.1 A2 · E03 §5.2.
--
-- La tabla de trabajo de la detección: única fuente de cardinalidad y de
-- composición extendida (D-3 sacó los uniqCombined de agg_src_10s, que
-- produce 6x más filas por segundo). Depende de 10_flows_raw.sql y
-- 00_database.sql (UDF isp_ip_str).
--
-- Enmienda A2 sobre ADR-012: established_flows_state y flags_valid_flows_state
-- son sum() sobre la columna `flows`, no count(): count() cuenta FILAS de
-- flows_raw, y una fila puede representar N flujos reales (sFlow expandido,
-- exportador que agrega). Los NOMBRES de columna no cambian.

CREATE TABLE IF NOT EXISTS isp.agg_src_1m
(
    window_start            DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    -- D-5: columna real, SEGUNDA en el ORDER BY (E06 §5.1 R1, E08 §5.1).
    -- E00c C-1: Enum8 idéntico al de flows_raw (10_flows_raw.sql).
    flow_dir                Enum8('unknown' = 0, 'outbound' = 1, 'inbound' = 2, 'internal' = 3, 'transit' = 4),
    src_ip                  IPv6            CODEC(ZSTD(1)),
    customer_id             LowCardinality(String),
    src_scope               Enum8('unknown' = 0, 'customer' = 1, 'infra' = 2, 'external' = 3),
    ip_version              UInt8,

    bytes_state             AggregateFunction(sum, UInt64),
    packets_state           AggregateFunction(sum, UInt64),
    flows_state             AggregateFunction(sum, UInt64),
    tcp_packets_state       AggregateFunction(sum, UInt64),
    udp_packets_state       AggregateFunction(sum, UInt64),
    icmp_packets_state      AggregateFunction(sum, UInt64),

    -- ADR-012: señales de flags. Nombres fijados por E00.
    syn_only_packets_state  AggregateFunction(sum, UInt64),
    rst_packets_state       AggregateFunction(sum, UInt64),
    established_flows_state AggregateFunction(sum, UInt64),
    flags_valid_flows_state AggregateFunction(sum, UInt64),

    -- D-6: el ratio SYN se calcula sobre INTENTOS, no sobre paquetes.
    syn_only_flows_state    AggregateFunction(sum, UInt64),
    tcp_flows_state         AggregateFunction(sum, UInt64),

    -- ADR-014: cardinalidades con uniqCombined(17).
    uniq_dst_ips_state      AggregateFunction(uniqCombined(17), IPv6),
    uniq_dst_ports_state    AggregateFunction(uniqCombined(17), UInt16),
    uniq_dst_nets_state     AggregateFunction(uniqCombined(17), IPv6),
    uniq_dst_asns_state     AggregateFunction(uniqCombined(12), UInt32),

    sampling_max_state      AggregateFunction(max, UInt32),

    -- D-7: huella de revisita.
    rows_state              AggregateFunction(count),
    last_inserted_state     AggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toDate(window_start)
ORDER BY (window_start, flow_dir, src_ip, customer_id, src_scope, ip_version)
TTL window_start + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW IF NOT EXISTS isp.mv_agg_src_1m TO isp.agg_src_1m AS
SELECT
    toStartOfInterval(ts_received, INTERVAL 1 MINUTE, 'UTC') AS window_start,
    flow_dir,
    src_ip,
    customer_id,
    src_scope,
    ip_version,

    sumState(bytes)                                         AS bytes_state,
    sumState(packets)                                       AS packets_state,
    sumState(toUInt64(flows))                               AS flows_state,
    sumStateIf(packets, proto = 6)                          AS tcp_packets_state,
    sumStateIf(packets, proto = 17)                         AS udp_packets_state,
    sumStateIf(packets, proto IN (1, 58))                   AS icmp_packets_state,

    sumStateIf(packets, tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)     AS syn_only_packets_state,
    sumStateIf(packets, tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x04) != 0)       AS rst_packets_state,
    sumStateIf(toUInt64(flows), tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x10) != 0)       AS established_flows_state,
    sumStateIf(toUInt64(flows), tcp_flags_valid = 1)        AS flags_valid_flows_state,

    sumStateIf(toUInt64(flows), tcp_flags_valid = 1
                    AND bitAnd(tcp_flags, 0x12) = 0x02)     AS syn_only_flows_state,
    sumStateIf(toUInt64(flows), proto = 6)                  AS tcp_flows_state,

    uniqCombinedState(17)(dst_ip)                           AS uniq_dst_ips_state,
    -- E06 §5.1 R3: solo TCP/UDP. Un ping sweep no debe inflar el fanout de puertos.
    uniqCombinedStateIf(17)(dst_port, proto IN (6, 17))     AS uniq_dst_ports_state,
    -- /24 en IPv4 (= /120 en la forma mapped) y /48 en IPv6: la granularidad
    -- del carpet bombing. Expresión inline, NO la UDF (§4.4).
    uniqCombinedState(17)(
      tupleElement(IPv6CIDRToRange(dst_ip, toUInt8(if(ip_version = 4, 120, 48))), 1)
    )                                                       AS uniq_dst_nets_state,
    uniqCombinedState(12)(dst_asn)                          AS uniq_dst_asns_state,

    maxState(sampling_applied)                              AS sampling_max_state,

    countState()                                            AS rows_state,
    maxState(ts_inserted)                                   AS last_inserted_state
FROM isp.flows_raw
WHERE flow_dir IN ('outbound', 'internal')
GROUP BY window_start, flow_dir, src_ip, customer_id, src_scope, ip_version;

-- Vista con GROUP BY: *Merge de cada _state (E03 §4.6). flow_dir se expone,
-- no se filtra (D-5). packets_per_flow/syn_ratio/syn_flow_ratio/
-- flags_available son derivadas de lectura, E03 §5.2.
CREATE OR REPLACE VIEW isp.v_agg_src_1m
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
    flow_dir,
    src_ip,
    isp_ip_str(src_ip)                             AS src_ip_str,
    customer_id,
    src_scope,
    ip_version,

    sumMerge(bytes_state)                          AS bytes,
    sumMerge(packets_state)                        AS packets,
    sumMerge(flows_state)                          AS flows,
    sumMerge(tcp_packets_state)                    AS tcp_packets,
    sumMerge(udp_packets_state)                    AS udp_packets,
    sumMerge(icmp_packets_state)                   AS icmp_packets,

    sumMerge(syn_only_packets_state)               AS syn_only_packets,
    sumMerge(rst_packets_state)                    AS rst_packets,
    sumMerge(established_flows_state)              AS established_flows,
    sumMerge(flags_valid_flows_state)              AS flags_valid_flows,

    -- D-6: contadores de FLUJOS, expuestos sin el sufijo _state.
    sumMerge(syn_only_flows_state)                 AS syn_only_flows,
    sumMerge(tcp_flows_state)                      AS tcp_flows,

    uniqCombinedMerge(17)(uniq_dst_ips_state)      AS uniq_dst_ips,
    uniqCombinedMerge(17)(uniq_dst_ports_state)    AS uniq_dst_ports,
    uniqCombinedMerge(17)(uniq_dst_nets_state)     AS uniq_dst_nets,
    uniqCombinedMerge(12)(uniq_dst_asns_state)     AS uniq_dst_asns,

    maxMerge(sampling_max_state)                   AS sampling_max,

    -- D-7: huella de revisita.
    countMerge(rows_state)                         AS rows,
    maxMerge(last_inserted_state)                  AS last_inserted,

    sumMerge(packets_state) / 60.0                 AS pps,
    sumMerge(bytes_state) * 8.0 / 60.0             AS bps,
    sumMerge(packets_state)
      / greatest(sumMerge(flows_state), 1)         AS packets_per_flow,
    -- syn_ratio SOBRE PAQUETES: se conserva por compatibilidad con los umbrales
    -- calibrados del prototipo.
    sumMerge(syn_only_packets_state)
      / greatest(sumMerge(packets_state), 1)       AS syn_ratio,
    -- D-6: el ratio que importa es sobre INTENTOS. Denominador = flujos TCP,
    -- no flujos totales: un cliente con mucho UDP no diluye su propio SYN flood.
    sumMerge(syn_only_flows_state)
      / greatest(sumMerge(tcp_flows_state), 1)     AS syn_flow_ratio,
    -- 0 = el exportador no informó flags en NINGÚN flujo de la ventana.
    -- Todo detector que use syn_ratio o syn_flow_ratio DEBE filtrar
    -- flags_available = 1.
    if(sumMerge(flags_valid_flows_state) > 0, 1, 0) AS flags_available
FROM isp.agg_src_1m
GROUP BY window_start, flow_dir, src_ip, customer_id, src_scope, ip_version;

-- Vista _flat (E00b D-10, enmendada por E00c C-2): SIN GROUP BY,
-- finalizeAggregation() de cada _state, fila a fila. Puede devolver más de
-- una fila por clave (una por parte no mergeada); el consumidor reagrega él
-- mismo (E03 §4.6.1).
CREATE OR REPLACE VIEW isp.v_agg_src_1m_flat
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
    customer_id, src_scope, ip_version,
    finalizeAggregation(bytes_state)               AS bytes,
    finalizeAggregation(packets_state)             AS packets,
    finalizeAggregation(flows_state)               AS flows,
    finalizeAggregation(tcp_packets_state)         AS tcp_packets,
    finalizeAggregation(udp_packets_state)         AS udp_packets,
    finalizeAggregation(icmp_packets_state)        AS icmp_packets,
    finalizeAggregation(syn_only_packets_state)    AS syn_only_packets,
    finalizeAggregation(rst_packets_state)         AS rst_packets,
    finalizeAggregation(established_flows_state)   AS established_flows,
    finalizeAggregation(flags_valid_flows_state)   AS flags_valid_flows,
    finalizeAggregation(syn_only_flows_state)      AS syn_only_flows,
    finalizeAggregation(tcp_flows_state)           AS tcp_flows,
    finalizeAggregation(uniq_dst_ips_state)        AS uniq_dst_ips,
    finalizeAggregation(uniq_dst_ports_state)      AS uniq_dst_ports,
    finalizeAggregation(uniq_dst_nets_state)       AS uniq_dst_nets,
    finalizeAggregation(uniq_dst_asns_state)       AS uniq_dst_asns,
    finalizeAggregation(sampling_max_state)        AS sampling_max,
    finalizeAggregation(rows_state)                AS rows,
    finalizeAggregation(last_inserted_state)       AS last_inserted
FROM isp.agg_src_1m;
