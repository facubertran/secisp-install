-- bl_service_seen.sql [E09]
--
-- T-335 (E09-T13) -- E09 §4.8.5 · E00e G-5 · E00b D-11, D-10 · E00e G-4a ·
-- E09 §9.6 N16 · E00d F-2.
--
-- J7: qué pares (proto, dst_port) de la watchlist habló saliente cada
-- entidad, con hours_seen/first_seen/last_seen/packets/max_uniq_dsts
-- acumulados (bl_service_seen es AggregatingMergeTree con
-- SimpleAggregateFunction, §5.1: re-fusiona solo, no hace falta FINAL
-- para leer un valor correcto).
--
-- Esto es el bloqueante que G-5 cerró (E00e G-5, N16): v_agg_src_dst_svc_1m_flat
-- NO expone customer_id ni src_scope (D-11 las rechazó por el tamaño de
-- agg_src_dst_svc_1m) -- el cliente sale de net_customer(src_ip) y el
-- scope de net_scope(src_ip)=1, las UDF de E04 §4.1.3 (09_udf_net.sql,
-- F-2). Nombrar src_scope/customer_id como columnas de esta vista es
-- exactamente el UNKNOWN_IDENTIFIER que tumbaba el motor entero (E05
-- §4.3.3 paso 5, aunque los jobs no pasan por ahí -- el bug era el mismo
-- para los tres consumidores de esta vista).
--
-- flow_dir='outbound' tiene que ser EXACTAMENTE el mismo filtro que
-- anomaly.new_service (fase 3, todavía no escrito) va a usar: si J7
-- acumulara outbound+internal y el detector mirara solo outbound,
-- "servicio nunca visto" pasaría a significar otra cosa y genera falsos
-- negativos.
--
-- Idempotente por HORA, no por ejecución: hours_seen es
-- SimpleAggregateFunction(sum, UInt64), así que re-correr la MISMA hora
-- suma dos veces -- por eso corre a :12 sobre la hora ya cerrada y el
-- runbook de E12 no la re-dispara a mano (§4.8.5). first_seen/last_seen
-- (min/max) y packets/max_uniq_dsts (sum/max) SÍ son idempotentes ante
-- una re-corrida de la misma hora; hours_seen es la única excepción.
--
-- Parámetros: {from:DateTime} {to:DateTime} {v6_bits:UInt8}
-- {watchlist:Array(Tuple(UInt8, UInt16))}

INSERT INTO isp.bl_service_seen
    (entity_kind, entity_key, proto, dst_port,
     first_seen, last_seen, hours_seen, packets, max_uniq_dsts)
SELECT
    -- resolveEntity (§4.3), idéntica a J2/J5 -- salvo que acá el cliente
    -- y el scope salen de las UDF, no de columnas reales (ver arriba).
    multiIf(net_customer(src_ip) != '', toUInt8(2),
            src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
            toUInt8(4))                                                  AS entity_kind,
    multiIf(net_customer(src_ip) != '', net_customer(src_ip),
            src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
            isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                || '/' || toString({v6_bits:UInt8}))                     AS entity_key,
    proto,
    dst_port,
    min(window_start)                                                    AS first_seen,
    max(window_start)                                                    AS last_seen,
    toUInt64(1)                                                          AS hours_seen,
    -- G-4a: el alias de agregación no puede llamarse "packets" (la
    -- columna cruda que sum() consume) -- packets_total no sombrea nada.
    sum(packets)                                                         AS packets_total,
    uniqExact(dst_ip)                                                    AS max_uniq_dsts
FROM isp.v_agg_src_dst_svc_1m_flat
WHERE window_start >= {from:DateTime} AND window_start < {to:DateTime}
  AND flow_dir = 'outbound'
  AND net_scope(src_ip) = 1
  AND (proto, dst_port) IN {watchlist:Array(Tuple(UInt8, UInt16))}
GROUP BY entity_kind, entity_key, proto, dst_port
SETTINGS max_memory_usage = 4294967296, max_execution_time = 180;
