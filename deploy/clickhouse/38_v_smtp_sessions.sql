-- 38_v_smtp_sessions.sql [E03]
--
-- T-053 (E03-T12) -- E03 §4.6.2 · E00b D-1 · E00c C-4 · E00c C-15 · E00d F-5 ·
-- E03 §5.2 · E03 §9.2 Q4.
--
-- Vista parametrizada de costura por hueco: la definición CANÓNICA de
-- "sesión SMTP" del sistema (E07 §4.3, cuerpo único por C-4). Va después de
-- 35_agg_smtp_sessions.sql porque depende de esa tabla. Los cuatro
-- parámetros son obligatorios y sin default: win_from, win_to, stitch_gap,
-- max_dur.
--
-- Nota de transcripción (F-5, verificada por test/schema/v_smtp_sessions_test.go
-- carácter por carácter, sin normalizar espacios): la línea de `chunks` lleva
-- una sola coma y un solo espacio antes de `sf`, aunque los elementos de un
-- solo dígito de arriba lleven dos por alineación visual. No es cosmético:
-- sin esa suma exacta, E07 §4.4.2 dividía registros de flujo por filas de
-- tabla y el gate de smtp.refused nunca se activaba.
CREATE OR REPLACE VIEW isp.v_smtp_sessions
SQL SECURITY DEFINER
AS
SELECT
    src_ip, dst_ip, src_port, dst_port, port_class, dst_scope,
    ip_version, customer_id, dst_asn, dst_cc,
    frag_count                                                  AS fragments_total,
    length(sf)                                                  AS fragments,
    sessions_in_tuple,
    -- sf viene ordenado por flow_start: el primero es el inicio de la sesión.
    sf[1].1                                                     AS session_start,
    arrayMax(x -> x.2, sf)                                      AS session_end,
    arrayMax(x -> x.2, sf) >= sf[1].1
      AND dateDiff('second', sf[1].1, arrayMax(x -> x.2, sf)) <= {max_dur:UInt32}
                                                                AS duration_valid,
    greatest(dateDiff('second', sf[1].1, arrayMax(x -> x.2, sf)), 0) AS duration_sec,
    arraySum(x -> x.5,  sf)                                     AS packets_out,
    arraySum(x -> x.6,  sf)                                     AS bytes_out,
    arraySum(x -> x.7,  sf)                                     AS packets_in,
    arraySum(x -> x.8,  sf)                                     AS bytes_in,
    arraySum(x -> x.9, sf)                                      AS chunks,
    arraySum(x -> x.10, sf)                                     AS syn_only_chunks,
    arraySum(x -> x.11, sf)                                     AS established_chunks,
    arraySum(x -> x.12, sf)                                     AS rst_chunks,
    arraySum(x -> x.14, sf)                                     AS flags_valid_chunks,
    arrayMax(x -> x.15, sf)                                     AS sampling_max,
    -- Métricas derivadas. greatest(...,1) evita la división por cero sin inventar
    -- duración: una sesión de un solo chunk tiene duration_sec = 0 y pps = packets.
    toFloat64(packets_out) / greatest(toFloat64(duration_sec), 1.0)     AS pps_out,
    toFloat64(bytes_out)   / greatest(toFloat64(packets_out), 1.0)  AS bpp_out,
    toFloat64(bytes_out)   / greatest(toFloat64(duration_sec), 1.0) AS bps_out
FROM
(
    SELECT
        src_ip, dst_ip, src_port, dst_port, port_class, dst_scope,
        any(ip_version)  AS ip_version,
        -- max y no any (E00c C-15): '' es el mínimo de String, así que si algún
        -- fragmento de la 5-tupla trae el abonado, la sesión cosida lo conserva.
        max(customer_id) AS customer_id,
        any(dst_asn)     AS dst_asn,
        any(dst_cc)      AS dst_cc,
        count()          AS frag_count,
        -- (1) fragmentos de la 5-tupla, ordenados por inicio real
        arraySort(f -> f.1, groupArray((
            flow_start, flow_end, first_seen, last_seen,          -- 1..4
            packets_out, bytes_out, packets_in, bytes_in,          -- 5..8
            chunks, syn_only_chunks, established_chunks,           -- 9..11
            rst_chunks, fin_chunks, flags_valid_chunks,            -- 12..14
            -- D-9: sampling_max_state es AggregateFunction; fila a fila se
            -- resuelve con finalizeAggregation, no con maxMerge.
            finalizeAggregation(sampling_max_state)                -- 15
        ))) AS frags,
        -- (2) fin del fragmento anterior, alineado por posición
        arrayPushFront(arrayPopBack(arrayMap(f -> f.2, frags)), frags[1].1) AS prev_end,
        -- (3) corte donde el hueco supera el gap => puerto efímero reusado
        arraySplit((f, pe) -> dateDiff('second', pe, f.1) > {stitch_gap:UInt32},
                   frags, prev_end) AS sessions,
        length(sessions) AS sessions_in_tuple
    FROM isp.agg_smtp_sessions
    WHERE window_start >= {win_from:DateTime}
      AND window_start <  {win_to:DateTime}
    GROUP BY src_ip, dst_ip, src_port, dst_port, port_class, dst_scope
) ARRAY JOIN sessions AS sf;
