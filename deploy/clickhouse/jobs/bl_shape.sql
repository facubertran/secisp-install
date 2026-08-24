-- bl_shape.sql [E09]
--
-- T-332 (E09-T10) -- E09 §4.8.2, §4.6.2, §4.5 · E09 D3 · E09 D5.
--
-- J3: forma de cohorte (entity_kind=1) y forma global (entity_kind=0),
-- las dos en la misma corrida -- cada fila de observación se cuenta a la
-- vez en su cohorte (L1) y en el global (L0) vía arrayJoin([cohort,
-- '__global__']), así que las dos variantes comparten el mismo cálculo de
-- shape/MAD sin duplicar la query (§4.8.2: "la variante global es la
-- misma query sin cohort en el GROUP BY").
--
-- bl_profiles es de escritor ÚNICO por entity_kind: J3 escribe 0 y 1;
-- J4 (bl_profile_l2.sql, T-333) escribe 2..4. No hay carry-forward de
-- columnas de otro dueño acá (a diferencia de bl_entities, §5.1): cada
-- fila de bl_profiles la escribe un solo job.
--
-- El recentrado (shape_log = shape_raw − mean_s(shape_raw)) es lo que
-- hace que level_log + shape_log sea consistente con mu_log (§4.6.2): sin
-- él, L1 queda con un sesgo constante por cohorte. El JOIN de la segunda
-- pasada (para el MAD, una mediana de desviaciones respecto de una
-- mediana) es legal porque esto es un job programado, no una MV (E03 D5).
--
-- Parámetros: {from:DateTime} {to:DateTime} {tz:String} {v6_bits:UInt8}
-- {min_samples:UInt32}

INSERT INTO isp.bl_profiles
    (entity_kind, entity_key, metric, slot, mu_log, shape_log, mad_log, p95_log,
     n_eff, ready, quality, built_at)
WITH
    -- resolveEntity (§4.3), idéntica a bl_cohorts.sql/bl_level.sql.
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
    -- ARRAY JOIN de las cinco métricas (E09 §4.4), igual que J2.
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
    -- El residual de nivel (r = log1p(value) − level_log) es lo que J3
    -- perfila, no el valor crudo: level_log ya es de bl_entities (J2).
    -- Las entidades quarantined no aportan muestras a la forma de su
    -- cohorte (criterio de aceptación de T-332): un perfil contaminado no
    -- puede prestarle su forma a los demás miembros.
    joined AS
    (
        SELECT
            u.entity_kind AS entity_kind, u.metric AS metric, u.window_start AS window_start,
            e.cohort AS cohort,
            log1p(u.value) - e.level_log AS r
        FROM unpivoted AS u
        INNER JOIN isp.bl_entities AS e FINAL
            ON e.entity_kind = u.entity_kind AND e.entity_key = u.entity_key AND e.metric = u.metric
        WHERE e.state != 'quarantined'
    ),
    -- Slot y daytype en hora LOCAL (E09 §4.5): mismo dictGetOrDefault
    -- sobre dict_bl_calendar que degrada a fin de semana sin fila, mismo
    -- criterio que stats.Slot (Go, T-325).
    withslot AS
    (
        SELECT
            entity_kind, metric, cohort, r,
            toUInt8(daytype * 24 + hour) AS slot_base, daytype, hour
        FROM
        (
            SELECT
                entity_kind, metric, cohort, r,
                toDate(lstart)                                            AS lday,
                toHour(lstart)                                            AS hour,
                dictGetOrDefault('isp.dict_bl_calendar', 'daytype', tuple(toDate(lstart)),
                                 if(toDayOfWeek(toDate(lstart)) >= 6, toUInt8(1), toUInt8(0))) AS daytype
            FROM
            (
                SELECT entity_kind, metric, cohort, r, toTimeZone(window_start, {tz:String}) AS lstart
                FROM joined
            )
        )
    ),
    -- Kernel de vecindad de §4.5: slot central peso 2, h−1/h+1 peso 1, con
    -- wrap DENTRO del mismo daytype (mismo kernel que stats.NeighborKernel,
    -- Go, T-325).
    kerneled AS
    (
        SELECT entity_kind, metric, cohort, r, sw.1 AS slot, sw.2 AS w
        FROM withslot
        ARRAY JOIN
        [
            (slot_base, toUInt8(2)),
            (toUInt8(daytype * 24 + ((hour + 23) % 24)), toUInt8(1)),
            (toUInt8(daytype * 24 + ((hour + 1) % 24)), toUInt8(1))
        ] AS sw
    ),
    -- Cada observación cuenta DOS veces: una para su cohorte (L1) y una
    -- para el global (L0, group_key='__global__') -- así las dos
    -- variantes de §4.8.2 salen del mismo GROUP BY sin repetir la query.
    dualgrouped AS
    (
        SELECT entity_kind, metric, slot, r, w, arrayJoin([cohort, '__global__']) AS group_key
        FROM kerneled
    ),
    -- Primera pasada: shape_raw por (grupo, métrica, slot).
    shape AS
    (
        SELECT
            group_key, metric, slot,
            quantileExactWeighted(0.5)(r, w)                              AS shape_raw,
            sum(w)                                                        AS n_eff
        FROM dualgrouped
        GROUP BY group_key, metric, slot
    )
-- Segunda pasada: MAD de las desviaciones respecto de shape_raw, más el
-- recentrado (suma de los 48 slots = 0 por grupo y métrica).
SELECT
    if(sh.group_key = '__global__',
       CAST(0 AS Enum8('global' = 0, 'cohort' = 1, 'customer' = 2, 'src_ip' = 3, 'src_prefix' = 4, 'service' = 5)),
       CAST(1 AS Enum8('global' = 0, 'cohort' = 1, 'customer' = 2, 'src_ip' = 3, 'src_prefix' = 4, 'service' = 5)))
                                                                           AS entity_kind,
    if(sh.group_key = '__global__', '', sh.group_key)                    AS entity_key,
    sh.metric                                                            AS metric,
    sh.slot                                                              AS slot,
    0.0                                                                  AS mu_log, -- no aplica en L1/L0
    sh.shape_raw - avg(sh.shape_raw) OVER (PARTITION BY sh.group_key, sh.metric) AS shape_log,
    quantileExactWeighted(0.5)(abs(da.r - sh.shape_raw), da.w)           AS mad_log,
    quantileExactWeighted(0.95)(da.r, da.w)                              AS p95_log,
    toUInt32(sh.n_eff)                                                   AS n_eff,
    toUInt8(sh.n_eff >= {min_samples:UInt32})                            AS ready,
    toFloat32(least(1.0, sh.n_eff / ({min_samples:UInt32} * 4.0)))       AS quality,
    now64(3)                                                             AS built_at
FROM shape AS sh
INNER JOIN dualgrouped AS da
    ON da.group_key = sh.group_key AND da.metric = sh.metric AND da.slot = sh.slot
GROUP BY sh.group_key, sh.metric, sh.slot, sh.shape_raw, sh.n_eff
SETTINGS max_memory_usage = 8589934592, max_execution_time = 600;
