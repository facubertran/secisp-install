-- 30_agg_src_port_1m.sql [E03]
--
-- T-050 (E03-T10) -- E03 §3 D7, §4.5.6, §4.6.3 · E00b D-2, D-7, D-8, D-9 ·
-- E00c C-12, C-14 · E00d F-14 · E00f H-4, deudas #2 y #3.
--
-- Transcripción literal del DDL de E08 §5.2 (D-2: E08 gana este texto, es su
-- único consumidor). El bloque ejecutable de la tabla y de la MV es idéntico
-- carácter por carácter, tras normalizar comentarios, al de
-- internal/detect/ddos/schema.go (T-049); test/schema/agg_src_port_1m_identity_test.go
-- lo verifica. Depende de 10_flows_raw.sql.
--
-- PROHIBIDO tocar la lista de 25 puertos acá: cambiarla después del primer
-- INSERT es migración con el sink pausado (T-048).

CREATE TABLE IF NOT EXISTS isp.agg_src_port_1m
(
    window_start   DateTime('UTC') CODEC(DoubleDelta, ZSTD(1)),
    proto          UInt8,
    -- Puerto de SERVICIO del cliente (no el efímero). Filtrado a dim_amp_ports por la MV.
    svc_port       UInt16,
    -- IP DEL CLIENTE, sea que actúe de servidor (resp) o que reciba consultas (req).
    svc_ip         IPv6,
    ip_version     UInt8,
    src_scope      Enum8('unknown'=0,'customer'=1,'infra'=2,'external'=3),
    customer_id    LowCardinality(String),

    -- pata SALIENTE: el cliente responde DESDE svc_port
    resp_packets_state AggregateFunction(sumIf,   UInt64, UInt8),
    resp_bytes_state   AggregateFunction(sumIf,   UInt64, UInt8),
    resp_flows_state   AggregateFunction(countIf, UInt8),
    -- pata ENTRANTE: el cliente recibe consultas HACIA svc_port
    req_packets_state  AggregateFunction(sumIf,   UInt64, UInt8),
    req_bytes_state    AggregateFunction(sumIf,   UInt64, UInt8),
    req_flows_state    AggregateFunction(countIf, UInt8),

    uniq_peer_resp_state     AggregateFunction(uniqCombinedIf(17), IPv6,  UInt8),
    -- E00c C-12: se llamaba uniq_peer_resp_24_state y la MV la poblaba con
    -- máscara fija /120. La unidad de concentración es /24 en IPv4 y /48 en IPv6,
    -- así que el nombre no puede prometer un /24.
    uniq_peer_resp_net_state AggregateFunction(uniqCombinedIf(17), IPv6,  UInt8),
    uniq_peer_resp_asns_state AggregateFunction(uniqCombinedIf(17), UInt32, UInt8),
    uniq_peer_req_state      AggregateFunction(uniqCombinedIf(17), IPv6,  UInt8),

    -- D-9: es AggregateFunction y lleva el sufijo _state (E00 §4.5.1).
    sampling_max_state AggregateFunction(max, UInt32),

    -- D-7: huella de revisita.
    rows_state         AggregateFunction(count),
    last_inserted_state AggregateFunction(max, DateTime64(3, 'UTC'))
)
ENGINE = AggregatingMergeTree
PARTITION BY toStartOfHour(window_start)
-- E00c C-14: ip_version, src_scope y customer_id VAN EN LA CLAVE. La MV agrupa por
-- las siete columnas; una columna que en AggregatingMergeTree no es ni clave ni
-- estado toma un valor ARBITRARIO al fusionar partes — no hay error, hay dato
-- inventado. El prefijo (window_start, proto, svc_port) que D-2 exige se conserva.
ORDER BY (window_start, proto, svc_port, svc_ip, ip_version, src_scope, customer_id)
TTL window_start + INTERVAL 7 DAY DELETE
SETTINGS index_granularity = 8192,
         ttl_only_drop_parts = 1,
         non_replicated_deduplication_window = 1000;

CREATE MATERIALIZED VIEW isp.mv_agg_src_port_1m TO isp.agg_src_port_1m AS
WITH
    (flow_dir = 'outbound') AS is_resp,
    (flow_dir = 'inbound')  AS is_req
SELECT
    toStartOfMinute(ts_received)                       AS window_start,
    proto,
    if(is_resp, src_port, dst_port)                    AS svc_port,
    if(is_resp, src_ip,   dst_ip)                      AS svc_ip,
    if(is_resp, ip_version, ip_version)                AS ip_version,
    if(is_resp, src_scope, dst_scope)                  AS src_scope,
    customer_id,

    sumIfState(bytes,   is_resp)                       AS resp_bytes_state,
    sumIfState(packets, is_resp)                       AS resp_packets_state,
    countIfState(is_resp)                              AS resp_flows_state,
    sumIfState(bytes,   is_req)                        AS req_bytes_state,
    sumIfState(packets, is_req)                        AS req_packets_state,
    countIfState(is_req)                               AS req_flows_state,

    uniqCombinedIfState(17)(dst_ip, is_resp)                          AS uniq_peer_resp_state,
    -- E00c C-12: máscara CONDICIONAL, la misma que agg_src_1m usa para
    -- uniq_dst_nets_state. Con /120 fijo, un peer IPv6 nativo cae en un bloque
    -- propio (256 direcciones dentro de su mismo /64) y peer_concentration da ≈ 0
    -- para CUALQUIER reflector IPv6, aunque las víctimas estén en un /48.
    uniqCombinedIfState(17)(
      IPv6CIDRToRange(dst_ip, toUInt8(if(ip_version = 4, 120, 48))).1, is_resp
    )                                                                 AS uniq_peer_resp_net_state,
    uniqCombinedIfState(17)(dst_asn, is_resp AND dst_asn > 0)         AS uniq_peer_resp_asns_state,
    uniqCombinedIfState(17)(src_ip, is_req)                           AS uniq_peer_req_state,

    maxState(sampling_applied)                         AS sampling_max_state,
    countState()                                       AS rows_state,
    maxState(ts_inserted)                              AS last_inserted_state
FROM isp.flows_raw
WHERE proto = 17
  AND (   (flow_dir = 'outbound' AND src_scope = 'customer' AND src_port IN (
              17, 19, 53, 69, 111, 123, 137, 161, 177, 389, 520, 623, 1434, 1900,
              3283, 3702, 5093, 5351, 5353, 5678, 10001, 11211, 27015, 33848, 37810))
       OR (flow_dir = 'inbound'  AND dst_scope = 'customer' AND dst_port IN (
              17, 19, 53, 69, 111, 123, 137, 161, 177, 389, 520, 623, 1434, 1900,
              3283, 3702, 5093, 5351, 5353, 5678, 10001, 11211, 27015, 33848, 37810)) )
GROUP BY window_start, proto, svc_port, svc_ip, ip_version, src_scope, customer_id;

-- Vista de lectura, E03 §4.6.3 / §5.2 (dueña E03, no transcripción de E08).
-- Nota de tipos: los estados de agg_src_port_1m son sumIf/countIf/uniqCombinedIf,
-- así que se resuelven con sumIfMerge/countIfMerge/uniqCombinedIfMerge, NUNCA
-- con sumMerge -- es el error de transcripción más probable de todo el esquema.
CREATE OR REPLACE VIEW isp.v_agg_src_port_1m
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
    window_start, proto, svc_port, svc_ip, isp_ip_str(svc_ip) AS svc_ip_str,
    ip_version, src_scope, customer_id,
    sumIfMerge(resp_packets_state)                     AS resp_packets,
    sumIfMerge(resp_bytes_state)                        AS resp_bytes,
    countIfMerge(resp_flows_state)                      AS resp_flows,
    sumIfMerge(req_packets_state)                       AS req_packets,
    sumIfMerge(req_bytes_state)                         AS req_bytes,
    countIfMerge(req_flows_state)                       AS req_flows,
    uniqCombinedIfMerge(17)(uniq_peer_resp_state)        AS uniq_peer_resp,
    -- E00c C-12: el ESTADO se llama uniq_peer_resp_net_state (máscara /24 en v4,
    -- /48 en v6). La COLUMNA de la vista conserva el nombre uniq_peer_resp_24
    -- porque es el que la query R1 de E08 §4.6.4 lee para calcular
    -- peer_concentration, y E00c C-11 la reproduce con ese nombre.
    uniqCombinedIfMerge(17)(uniq_peer_resp_net_state)   AS uniq_peer_resp_24,
    uniqCombinedIfMerge(17)(uniq_peer_resp_asns_state)  AS uniq_peer_resp_asns,
    uniqCombinedIfMerge(17)(uniq_peer_req_state)        AS uniq_peer_req,
    sumIfMerge(resp_bytes_state)
      / greatest(sumIfMerge(req_bytes_state), 1)        AS amp_factor_bytes,
    sumIfMerge(resp_packets_state)
      / greatest(sumIfMerge(req_packets_state), 1)      AS amp_factor_packets,
    sumIfMerge(resp_bytes_state)
      / greatest(sumIfMerge(resp_packets_state), 1)     AS resp_bpp,
    if(countIfMerge(req_flows_state) > 0, 1, 0)         AS request_side_visible,
    maxMerge(sampling_max_state)                        AS sampling_max,
    countMerge(rows_state)                              AS rows,
    maxMerge(last_inserted_state)                       AS last_inserted,
    sumIfMerge(resp_packets_state) / 60.0                AS resp_pps,
    sumIfMerge(resp_bytes_state) * 8.0 / 60.0            AS resp_bps
FROM isp.agg_src_port_1m
GROUP BY window_start, proto, svc_port, svc_ip, ip_version, src_scope, customer_id;
