-- bl_level.sql [E09]
--
-- T-330 (E09-T08) + T-331 (E09-T09) -- E09 §4.8.1, §4.6.1, §4.4, §4.4.2 ·
-- E00b D-5, D-12 · E00e G-4a · E00c C-13 · E09 D10 · E09 §4.10 · E09 §4.9.
--
-- J2: nivel por (entidad, métrica) sobre 28 días de v_agg_src_1h (el
-- llamador arma {from:DateTime}/{to:DateTime}), con las tres defensas de
-- D10: exclusión de horas cubiertas por un caso confirmado/mitigating/
-- mitigated, congelamiento de la ACTUALIZACIÓN (no de la evaluación)
-- mientras hay un caso abierto, y clamp de deriva con cuarentena visible.
--
-- bl_entities es de DOBLE ESCRITOR (§5.1, ver bl_cohorts.sql): este job es
-- dueño de (level_log, level_prev_log, level_ratio_day, samples,
-- active_hours, excluded_hours, state, quality, frozen_until, first_seen,
-- last_seen); bl_cohorts.sql (J1) es dueño de (cohort, cohort_candidate,
-- cohort_candidate_days). Cada INSERT lleva los campos del OTRO dueño
-- intactos, leídos de isp.bl_entities FINAL.
--
-- resolveEntity (E09 §4.3) idéntica carácter a carácter a la de
-- bl_cohorts.sql: el mismo multiIf sobre customer_id/src_ip, incluido en
-- la resolución de casos de det_cases (para que un caso de un cliente con
-- varias IPs excluya las horas de TODAS sus IPs, no solo la que abrió el
-- caso).
--
-- 'quarantined'/'frozen' quedan escritos en bl_entities.state; emitir
-- SEC-DET-013 y sec_detect_baseline_quarantined_total al MOMENTO de la
-- transición es de T-339/T-340 (salud del subsistema), que lee este
-- estado -- este job no loguea nada por sí mismo (mismo criterio que
-- bl_cohorts.sql).
--
-- Re-ejecutable: ReplacingMergeTree + clave natural. La lectura es sobre
-- la VISTA v_agg_src_1h, nunca sobre agg_src_1h -- la vista proyecta el
-- ReplacingMergeTree SIN FINAL a propósito (una hora duplicada pesa
-- 2/672 en una mediana, D2; FINAL costaría la fusión completa en cada
-- corrida horaria).
--
-- Parámetros: {from:DateTime} {to:DateTime} {tz:String} {v6_bits:UInt8}
-- {min_samples:UInt32} {max_level_ratio:Float64} {freeze_seconds:UInt32}

INSERT INTO isp.bl_entities
    (entity_kind, entity_key, metric, cohort, cohort_candidate, cohort_candidate_days,
     level_log, level_prev_log, level_ratio_day, samples, active_hours, excluded_hours,
     state, quality, frozen_until, first_seen, last_seen, built_at)
WITH
    log({max_level_ratio:Float64})                                        AS ln_r,
    -- resolveEntity (§4.3), idéntica a bl_cohorts.sql.
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
        -- El roll-up de E03 §4.5.3 ya filtró flow_dir='outbound': agg_src_1h
        -- no lleva flow_dir en su clave (D-5/§4.4.2). No existe ningún
        -- toggle de INCLUDE_INTERNAL.
        FROM isp.v_agg_src_1h
        WHERE window_start >= {from:DateTime} AND window_start < {to:DateTime}
          AND src_scope = 'customer'
    ),
    -- D10 defensa 1: las horas cubiertas por un caso CONFIRMADO de esa
    -- misma entidad (mismo resolveEntity que arriba: un caso de una IP de
    -- un cliente excluye las horas de TODAS sus IPs). SELECT DISTINCT
    -- porque dos casos superpuestos del mismo cliente no pueden duplicar
    -- la fila de observación en el LEFT JOIN de abajo.
    case_hours AS
    (
        SELECT DISTINCT
            multiIf(customer_id != '', toUInt8(2),
                    src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
                    toUInt8(4))                                          AS entity_kind,
            multiIf(customer_id != '', customer_id,
                    src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
                    isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                        || '/' || toString({v6_bits:UInt8}))             AS entity_key,
            arrayJoin(arrayMap(
                i -> toStartOfHour(opened_at) + toIntervalHour(i),
                range(toUInt32(dateDiff('hour', toStartOfHour(opened_at), toStartOfHour(last_event_at))) + 1)
            ))                                                            AS bad_hour
        FROM isp.v_det_cases
        WHERE state IN ('confirmed', 'mitigating', 'mitigated')
          AND last_event_at >= {from:DateTime}
    ),
    -- D10 defensa 2: la marca de congelamiento es por CUALQUIER caso vivo
    -- (open incluido -- "durante el incidente", no solo tras confirmarlo),
    -- nunca por un evento anomaly.* (eso realimentaría el sistema con su
    -- propia salida).
    frozen AS
    (
        SELECT
            multiIf(customer_id != '', toUInt8(2),
                    src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
                    toUInt8(4))                                          AS entity_kind,
            multiIf(customer_id != '', customer_id,
                    src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
                    isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                        || '/' || toString({v6_bits:UInt8}))             AS entity_key,
            max(last_event_at)                                           AS last_event_at
        FROM isp.v_det_cases
        WHERE state IN ('open', 'confirmed', 'mitigating', 'mitigated')
        GROUP BY entity_kind, entity_key
    ),
    -- Marca is_contaminated por (entidad, hora) sin duplicar filas: join_use_nulls
    -- (SETTINGS, abajo) hace que ch.entity_kind sea NULL cuando la hora no
    -- está cubierta por ningún caso.
    joined AS
    (
        SELECT
            r.entity_kind AS entity_kind, r.entity_key AS entity_key, r.window_start AS window_start,
            r.pps_p95 AS pps_p95, r.bps_p95 AS bps_p95, r.uniq_dst_ips AS uniq_dst_ips,
            r.uniq_dst_ports AS uniq_dst_ports, r.flows AS flows,
            ch.entity_kind IS NOT NULL                                    AS is_contaminated
        FROM raw AS r
        LEFT JOIN case_hours AS ch
            ON ch.entity_kind = r.entity_kind AND ch.entity_key = r.entity_key AND ch.bad_hour = r.window_start
    ),
    -- ARRAY JOIN de las cinco métricas (E09 §4.4). level_raw, samples y
    -- active_hours se calculan SOLO sobre horas no contaminadas;
    -- excluded_hours cuenta las que sí lo estaban -- las tres cifras salen
    -- del mismo GROUP BY, sin una segunda pasada.
    levels AS
    (
        SELECT
            j.entity_kind                                                AS entity_kind,
            j.entity_key                                                 AS entity_key,
            mv.1                                                         AS metric,
            quantileExactWeightedIf(0.5)(log1p(mv.2), toUInt64(1), mv.2 > 0 AND NOT j.is_contaminated) AS level_raw,
            countIf(NOT j.is_contaminated)                                AS samples,
            countIf(mv.2 > 0 AND NOT j.is_contaminated)                   AS active_hours,
            countIf(j.is_contaminated)                                    AS excluded_hours,
            max(j.window_start)                                           AS last_hour
        FROM joined AS j
        ARRAY JOIN
        [
            ('pps',            toFloat64(j.pps_p95)),
            ('bps',            toFloat64(j.bps_p95)),
            ('uniq_dst_ips',   toFloat64(j.uniq_dst_ips)),
            ('uniq_dst_ports', toFloat64(j.uniq_dst_ports)),
            ('flows',          toFloat64(j.flows))
        ] AS mv
        GROUP BY j.entity_kind, j.entity_key, mv.1
    ),
    -- Estado vigente: level_log/built_at (para days_elapsed) son de ESTE
    -- job; cohort/cohort_candidate/cohort_candidate_days son del OTRO
    -- dueño (J1) y se leen acá solo para carry-forward en el SELECT final.
    existing AS
    (
        SELECT entity_kind, entity_key, metric, level_log, built_at,
               samples                                        AS prev_samples,
               cohort, cohort_candidate, cohort_candidate_days,
               state, quality, frozen_until, first_seen, last_seen
        FROM isp.bl_entities FINAL
    ),
    -- D10 defensa 3: clamp de deriva. level_prev_log/days_elapsed nacen
    -- del último built_at de ESTE job para esta fila. "Sin medición previa
    -- de J2" NO es lo mismo que "sin fila en bl_entities": J1 crea la fila
    -- de las 5 métricas para toda entidad nueva ANTES de que J2 corra por
    -- primera vez, con level_log/samples en su cero de fábrica (bl_cohorts.sql)
    -- -- ese cero es un placeholder, no una medición real de nivel 0, y
    -- clampear contra él dispararía cuarentena en el primer cálculo real de
    -- cualquier entidad. e.prev_samples (que solo ESTE job pone en un valor
    -- > 0) es la señal correcta: level_prev_log = level_raw y días_elapsed
    -- = 1/24 mientras J2 nunca corrió antes para esta fila, exista o no la
    -- fila.
    clamped AS
    (
        SELECT
            l.entity_kind                                                AS entity_kind,
            l.entity_key                                                 AS entity_key,
            l.metric                                                     AS metric,
            l.samples                                                    AS samples,
            l.active_hours                                               AS active_hours,
            l.excluded_hours                                             AS excluded_hours,
            l.last_hour                                                  AS last_hour,
            if(coalesce(e.prev_samples, 0) > 0, e.level_log, l.level_raw)             AS level_prev_log,
            if(coalesce(e.prev_samples, 0) > 0,
               greatest(dateDiff('second', e.built_at, {to:DateTime}) / 86400.0, 1 / 24.),
               1 / 24.)                                                  AS days_elapsed,
            l.level_raw                                                  AS level_raw
        FROM levels AS l
        LEFT JOIN existing AS e
            ON e.entity_kind = l.entity_kind AND e.entity_key = l.entity_key AND e.metric = l.metric
    ),
    staged AS
    (
        SELECT
            entity_kind, entity_key, metric, samples, active_hours, excluded_hours, last_hour,
            level_prev_log,
            least(
                greatest(level_raw, level_prev_log - ln_r * days_elapsed),
                level_prev_log + ln_r * days_elapsed
            )                                                             AS level_log_clamped,
            toFloat32(exp(abs(level_raw - level_prev_log) / days_elapsed)) AS level_ratio_day,
            (excluded_hours > 0 AND samples > 0 AND (excluded_hours / samples) > 0.5) AS mostly_contaminated
        FROM clamped
    )
SELECT
    s.entity_kind                                                        AS entity_kind,
    s.entity_key                                                         AS entity_key,
    s.metric                                                             AS metric,
    coalesce(e.cohort, 'unknown')                                        AS cohort,
    coalesce(e.cohort_candidate, '')                                     AS cohort_candidate,
    coalesce(e.cohort_candidate_days, toUInt8(0))                        AS cohort_candidate_days,
    -- Congelado: NO se actualiza (D10 defensa 2) -- el valor vigente se
    -- re-escribe tal cual, no el recién calculado.
    if(f.entity_kind IS NOT NULL
           AND (f.last_event_at + toIntervalSecond({freeze_seconds:UInt32})) > {to:DateTime},
       s.level_prev_log, s.level_log_clamped)                            AS level_log,
    s.level_prev_log                                                     AS level_prev_log,
    s.level_ratio_day                                                    AS level_ratio_day,
    s.samples                                                            AS samples,
    s.active_hours                                                       AS active_hours,
    s.excluded_hours                                                     AS excluded_hours,
    -- Prioridad CORREGIDA (T-342, hallado con las tres pruebas de D10
    -- corriendo de verdad contra un ClickHouse real -- las dos primeras
    -- pasaban, la tercera no, y arreglarla ingenuamente rompía la
    -- primera: las tres defensas de §4.10 no son un solo nivel de
    -- prioridad, son dos).
    --
    -- 1) mostly_contaminated (defensa 1, exclusión por caso CONFIRMADO)
    --    gana siempre, incluso sobre frozen: si la mayoría de la ventana
    --    son horas excluidas, no hay suficiente historia limpia para
    --    confiar en NINGÚN nivel -- ni el nuevo ni, por extensión, seguir
    --    sirviendo el viejo como si nada, que es lo que frozen haría.
    -- 2) frozen (defensa 2, caso VIVO -- open incluido) le gana a
    --    level_ratio_day (defensa 3, el clamp de deriva): level_ratio_day
    --    se calcula contra level_raw, el nivel RECIÉN CALCULADO sobre la
    --    ventana entera sin importar si se va a congelar -- una entidad
    --    con un caso abierto que además recibe el pico real del propio
    --    incidente dispara level_ratio_day > R igual, aunque ese
    --    level_raw nunca se vaya a escribir (line 213: level_log =
    --    s.level_prev_log cuando frozen). case_hours (arriba) NO
    --    considera casos 'open' -- por eso un caso abierto nunca aporta
    --    excluded_hours, y mostly_contaminated queda en false: la única
    --    señal que compite ahí es level_ratio_day, y frozen tiene que
    --    ganarle (§4.10 defensa 2: "congela la actualización... si
    --    congelara la evaluación, un atacante podría apagarse el
    --    baseline" -- quarantined SÍ apaga la evaluación, frozen no).
    multiIf(
        s.mostly_contaminated,
            CAST(4 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5)),
        f.entity_kind IS NOT NULL
            AND (f.last_event_at + toIntervalSecond({freeze_seconds:UInt32})) > {to:DateTime},
            CAST(5 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5)),
        s.level_ratio_day > {max_level_ratio:Float64},
            CAST(4 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5)),
        s.samples >= {min_samples:UInt32},
            CAST(2 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5)),
        CAST(1 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5))
    )                                                                     AS state,
    coalesce(e.quality, toFloat32(0.))                                   AS quality,
    -- frozen_until se refresca mientras haya un caso vivo; sin uno, se
    -- conserva el valor vigente (o el default de "nunca" si tampoco había).
    if(f.entity_kind IS NOT NULL,
       f.last_event_at + toIntervalSecond({freeze_seconds:UInt32}),
       coalesce(e.frozen_until, toDateTime(0, 'UTC')))                   AS frozen_until,
    coalesce(e.first_seen, s.last_hour)                                  AS first_seen,
    s.last_hour                                                         AS last_seen,
    now64(3)                                                             AS built_at
FROM staged AS s
LEFT JOIN existing AS e
    ON e.entity_kind = s.entity_kind AND e.entity_key = s.entity_key AND e.metric = s.metric
LEFT JOIN frozen AS f
    ON f.entity_kind = s.entity_kind AND f.entity_key = s.entity_key
SETTINGS max_memory_usage = 6442450944, max_execution_time = 300, join_use_nulls = 1;
