-- bl_profile_l2.sql [E09]
--
-- T-333 (E09-T11) -- E09 §4.8.3, §4.6.3, §4.3 · E09 D5.
--
-- J4: perfil propio L2 (entity_kind ∈ {2,3,4}) para las top-N entidades,
-- idéntico a bl_shape.sql (J3) en el kernel y el MAD de dos pasadas, pero
-- agrupando por (entity_kind, entity_key) en vez de por cohorte y sobre
-- log1p(value) DIRECTO -- no sobre el residual de nivel: acá el perfil
-- ES el nivel, no una forma que se le suma a otro.
--
-- Selección, en orden (§4.8.3):
--   (a) active_hours >= L2_MIN_ACTIVE_RATIO · horas del período
--   (b) p95 observado >= piso D9 / 4 en AL MENOS UNA métrica -- no tiene
--       sentido gastar un perfil propio en una entidad que nunca va a
--       poder cruzar el piso absoluto (trampa de T-333)
--   (c) ORDER BY level_log DESC LIMIT L2_MAX_ENTITIES
-- Los cinco pisos de D9 (pps=500, bps=4 Mbps, uniq_dst_ips=15,
-- uniq_dst_ports=10, flows=600) son constantes fijas de la épica -- no
-- están en SEC_DETECT_BASELINE_* (E09 §5.8 no las lista): se derivan del
-- umbral fijo del detector equivalente de E06/E08 y viven en este job
-- como parámetros con ese default literal, no leídas en vivo de otra
-- épica (D4: este job no conoce Spec.Params de scan/ddos).
--
-- bl_profiles es de escritor único por entity_kind (ver bl_shape.sql):
-- J3 escribe 0/1, este job escribe 2..4.
--
-- Parámetros: {from:DateTime} {to:DateTime} {tz:String} {v6_bits:UInt8}
-- {min_samples:UInt32} {l2_min_active_ratio:Float64} {l2_max_entities:UInt32}
-- {floor_pps:Float64} {floor_bps:Float64} {floor_uniq_dst_ips:Float64}
-- {floor_uniq_dst_ports:Float64} {floor_flows:Float64}

INSERT INTO isp.bl_profiles
    (entity_kind, entity_key, metric, slot, mu_log, shape_log, mad_log, p95_log,
     n_eff, ready, quality, built_at)
WITH
    dateDiff('hour', {from:DateTime}, {to:DateTime})                     AS period_hours,
    -- Filtro (a): activa lo suficiente en el período, en estado usable.
    candidates AS
    (
        SELECT entity_kind, entity_key, level_log
        FROM isp.bl_entities FINAL
        WHERE metric = 'pps'
          AND active_hours >= {l2_min_active_ratio:Float64} * period_hours
          AND state IN ('ready', 'warmup')
    ),
    -- resolveEntity (§4.3), idéntica a bl_cohorts.sql/bl_level.sql/bl_shape.sql.
    raw AS
    (
        SELECT
            window_start,
            multiIf(customer_id != '', toUInt8(2),
                    src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
                    toUInt8(4))                                          AS entity_kind,
            multiIf(customer_id != '', customer_id,
                    src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
                    isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                        || '/' || toString({v6_bits:UInt8}))             AS entity_key,
            pps_p95, bps_p95, uniq_dst_ips, uniq_dst_ports, flows
        FROM isp.v_agg_src_1h
        WHERE window_start >= {from:DateTime} AND window_start < {to:DateTime}
          AND src_scope = 'customer'
    ),
    unpivoted AS
    (
        SELECT
            r.entity_kind AS entity_kind, r.entity_key AS entity_key, r.window_start AS window_start,
            mv.1 AS metric, mv.2 AS value
        FROM raw AS r
        ARRAY JOIN
        [
            ('pps',            toFloat64(r.pps_p95)),
            ('bps',            toFloat64(r.bps_p95)),
            ('uniq_dst_ips',   toFloat64(r.uniq_dst_ips)),
            ('uniq_dst_ports', toFloat64(r.uniq_dst_ports)),
            ('flows',          toFloat64(r.flows))
        ] AS mv
    ),
    -- Filtro (b): p95 observado REAL sobre la ventana, restringido a los
    -- candidatos de (a) para acotar el costo.
    observed AS
    (
        SELECT
            u.entity_kind AS entity_kind, u.entity_key AS entity_key, u.metric AS metric,
            quantile(0.95)(u.value)                                       AS p95_obs
        FROM unpivoted AS u
        INNER JOIN candidates AS c ON c.entity_kind = u.entity_kind AND c.entity_key = u.entity_key
        GROUP BY u.entity_kind, u.entity_key, u.metric
    ),
    passes_floor AS
    (
        SELECT entity_kind, entity_key
        FROM observed
        WHERE (metric = 'pps'            AND p95_obs >= {floor_pps:Float64} / 4)
           OR (metric = 'bps'            AND p95_obs >= {floor_bps:Float64} / 4)
           OR (metric = 'uniq_dst_ips'   AND p95_obs >= {floor_uniq_dst_ips:Float64} / 4)
           OR (metric = 'uniq_dst_ports' AND p95_obs >= {floor_uniq_dst_ports:Float64} / 4)
           OR (metric = 'flows'          AND p95_obs >= {floor_flows:Float64} / 4)
        GROUP BY entity_kind, entity_key
    ),
    -- Filtro (c): el tope duro, aplicado AL FINAL sobre lo que ya pasó
    -- (a) y (b).
    selected AS
    (
        SELECT c.entity_kind AS entity_kind, c.entity_key AS entity_key
        FROM candidates AS c
        INNER JOIN passes_floor AS pf ON pf.entity_kind = c.entity_kind AND pf.entity_key = c.entity_key
        ORDER BY c.level_log DESC
        LIMIT {l2_max_entities:UInt32}
    ),
    -- log1p(value) DIRECTO (no residual de nivel): acá el perfil ES el
    -- nivel.
    joined AS
    (
        SELECT u.entity_kind AS entity_kind, u.entity_key AS entity_key, u.metric AS metric,
               u.window_start AS window_start, log1p(u.value) AS r
        FROM unpivoted AS u
        INNER JOIN selected AS s ON s.entity_kind = u.entity_kind AND s.entity_key = u.entity_key
    ),
    -- Slot/daytype en hora local y kernel de vecindad: mismo cálculo que
    -- bl_shape.sql (§4.5).
    withslot AS
    (
        SELECT
            entity_kind, entity_key, metric, r,
            toUInt8(daytype * 24 + hour) AS slot_base, daytype, hour
        FROM
        (
            SELECT
                entity_kind, entity_key, metric, r,
                toDate(lstart)                                            AS lday,
                toHour(lstart)                                            AS hour,
                dictGetOrDefault('isp.dict_bl_calendar', 'daytype', tuple(toDate(lstart)),
                                 if(toDayOfWeek(toDate(lstart)) >= 6, toUInt8(1), toUInt8(0))) AS daytype
            FROM
            (
                SELECT entity_kind, entity_key, metric, r, toTimeZone(window_start, {tz:String}) AS lstart
                FROM joined
            )
        )
    ),
    kerneled AS
    (
        SELECT entity_kind, entity_key, metric, r, sw.1 AS slot, sw.2 AS w
        FROM withslot
        ARRAY JOIN
        [
            (slot_base, toUInt8(2)),
            (toUInt8(daytype * 24 + ((hour + 23) % 24)), toUInt8(1)),
            (toUInt8(daytype * 24 + ((hour + 1) % 24)), toUInt8(1))
        ] AS sw
    ),
    mu AS
    (
        SELECT entity_kind, entity_key, metric, slot,
               quantileExactWeighted(0.5)(r, w)                          AS mu_raw,
               sum(w)                                                    AS n_eff
        FROM kerneled
        GROUP BY entity_kind, entity_key, metric, slot
    )
SELECT
    m.entity_kind                                                        AS entity_kind,
    m.entity_key                                                         AS entity_key,
    m.metric                                                             AS metric,
    m.slot                                                               AS slot,
    m.mu_raw                                                             AS mu_log,
    0.0                                                                  AS shape_log, -- no aplica en L2
    quantileExactWeighted(0.5)(abs(k.r - m.mu_raw), k.w)                 AS mad_log,
    quantileExactWeighted(0.95)(k.r, k.w)                                AS p95_log,
    toUInt32(m.n_eff)                                                    AS n_eff,
    toUInt8(m.n_eff >= {min_samples:UInt32})                             AS ready,
    toFloat32(least(1.0, m.n_eff / ({min_samples:UInt32} * 4.0)))        AS quality,
    now64(3)                                                             AS built_at
FROM mu AS m
INNER JOIN kerneled AS k
    ON k.entity_kind = m.entity_kind AND k.entity_key = m.entity_key AND k.metric = m.metric AND k.slot = m.slot
GROUP BY m.entity_kind, m.entity_key, m.metric, m.slot, m.mu_raw, m.n_eff
SETTINGS max_memory_usage = 4294967296, max_execution_time = 600;
