-- bl_service_1h.sql [E09]
--
-- T-336 (E09-T14) -- E09 §4.8.5 · E09 §9.7 N26 · E00e G-5 · E00b D-10, D-5.
--
-- J8: volumen del ISP entero por (proto, dst_port) y hora -- la serie que
-- perfila anomaly.service_wave (fase 3) y su top-20 de contribuyentes.
--
-- Fuente: isp.v_agg_src_dst_svc_1m_flat, NO v_agg_dst_svc_1m_flat (N26,
-- deuda de transcripción de E00f: §4.8.5 decía la segunda, pero esa vista
-- está keyeada en la VÍCTIMA y no expone src_ip -- y J8 necesita
-- uniqExact(src_ip) para uniq_src_entities, E03 §4.6.1). Se elige
-- src_dst_svc porque ya la usa el bloque de evidencia (Q-E09-8 queda
-- abierta: si E03 adopta esta agregación como agg_svc_1h, E09 consume esa
-- tabla y borra la suya).
--
-- Mismo filtro que el top-20 de contribuyentes de anomaly.service_wave
-- (§4.11.5) y que J7 (bl_service_seen.sql): flow_dir='outbound' y
-- net_scope(src_ip)=1 -- la vista no expone src_scope como columna (D-11,
-- G-5), igual razón que J7.
--
-- D-10: _flat resuelve los estados fila a fila y no lleva GROUP BY sobre
-- la vista sin colapsar antes -- collapsed (abajo) hace esa fusión UNA
-- sola vez, y las dos ramas de agregación (totales+cardinalidades por un
-- lado, pps_p95/pps_max por otro) parten de ella en vez de repetir la
-- lectura de la vista.
--
-- Re-ejecutable: MergeTree con ORDER BY (window_start, proto, dst_port) y
-- {from:DateTime} fijo por corrida -- una re-corrida agrega una fila
-- gemela, no un ReplacingMergeTree como bl_entities/bl_profiles; el
-- runbook de E12 asume que J8 corre una vez por hora igual que J7 (§4.8.5).
--
-- Parámetros: {from:DateTime} {to:DateTime}

INSERT INTO isp.bl_service_1h
    (window_start, proto, dst_port, packets, bytes, flows,
     uniq_src_entities, uniq_dst_ips, pps_p95, pps_max, sampling_max)
WITH
    -- NIVEL 1 (D-10): colapsar las partes de _flat para la clave completa
    -- ANTES de cualquier max()/sum() sobre ella.
    collapsed AS
    (
        SELECT
            window_start, src_ip, dst_ip, proto, dst_port,
            sum(packets)     AS packets,
            sum(bytes)       AS bytes,
            sum(flows)       AS flows,
            max(sampling_max) AS sampling_max
        FROM isp.v_agg_src_dst_svc_1m_flat
        WHERE window_start >= {from:DateTime} AND window_start < {to:DateTime}
          AND flow_dir  = 'outbound'
          AND net_scope(src_ip) = 1
        GROUP BY window_start, src_ip, dst_ip, proto, dst_port
    ),
    -- Totales y cardinalidades de la HORA entera, por (proto, dst_port).
    totals AS
    (
        SELECT
            proto, dst_port,
            sum(packets)          AS packets,
            sum(bytes)            AS bytes,
            sum(flows)            AS flows,
            uniqExact(src_ip)     AS uniq_src_entities,
            uniqExact(dst_ip)     AS uniq_dst_ips,
            max(sampling_max)     AS sampling_max
        FROM collapsed
        GROUP BY proto, dst_port
    ),
    -- pps del ISP entero por MINUTO (todas las entidades sumadas), para
    -- percentilar/maximizar sobre los 60 minutos de la hora.
    perminute AS
    (
        SELECT
            window_start, proto, dst_port,
            sum(packets) / 60.0 AS pps_min
        FROM collapsed
        GROUP BY window_start, proto, dst_port
    ),
    rates AS
    (
        SELECT
            proto, dst_port,
            quantile(0.95)(pps_min) AS pps_p95,
            max(pps_min)            AS pps_max
        FROM perminute
        GROUP BY proto, dst_port
    )
SELECT
    {from:DateTime}          AS window_start,
    t.proto                  AS proto,
    t.dst_port                AS dst_port,
    t.packets                 AS packets,
    t.bytes                    AS bytes,
    t.flows                     AS flows,
    t.uniq_src_entities          AS uniq_src_entities,
    t.uniq_dst_ips                AS uniq_dst_ips,
    toFloat32(r.pps_p95)           AS pps_p95,
    toFloat32(r.pps_max)            AS pps_max,
    t.sampling_max                   AS sampling_max
FROM totals AS t
INNER JOIN rates AS r ON r.proto = t.proto AND r.dst_port = t.dst_port
SETTINGS max_memory_usage = 4294967296, max_execution_time = 180;
