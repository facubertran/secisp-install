-- bl_cohorts.sql [E09]
--
-- T-329 (E09-T07) -- E09 §4.7, D8 · E09 §4.8 · E09 §5.1 · E00b D-5.
--
-- J1: cohorte determinista (banda de nivel × patrón horario) con
-- histéresis de {hysteresis_days} días, sobre v_agg_src_1h ({from:DateTime}
-- .. {to:DateTime}, normalmente 14 días -- el llamador arma el rango; este
-- job no conoce "14 días" como constante propia). Nada de k-means: la
-- cohorte tiene que ser explicable en una frase a un operador que va a
-- justificar un corte (D8).
--
-- bl_entities es de DOBLE ESCRITOR (§5.1): este job es dueño de
-- (cohort, cohort_candidate, cohort_candidate_days); bl_level.sql (J2,
-- T-330) es dueño de (level_log, level_prev_log, level_ratio_day,
-- samples, active_hours, excluded_hours, state, quality, frozen_until,
-- first_seen, last_seen). Como ReplacingMergeTree reemplaza la fila
-- ENTERA por clave (entity_kind, metric, entity_key), cada INSERT tiene
-- que llevar los campos del OTRO dueño intactos -- se leen de
-- isp.bl_entities FINAL y se re-escriben tal cual, o con el default de
-- "primera vez" si la fila todavía no existe. bl_level.sql tiene que
-- hacer la misma operación simétrica con (cohort, cohort_candidate,
-- cohort_candidate_days) cuando se escriba.
--
-- Re-ejecutable: ReplacingMergeTree + clave natural (entity_kind, metric,
-- entity_key) -- correr sobre el mismo rango no cambia ningún valor,
-- salvo que built_at avanza (no afecta el contenido tras la fusión).
--
-- Parámetros: {from:DateTime} {to:DateTime} {tz:String} {v6_bits:UInt8}
-- {hysteresis_days:UInt8}

INSERT INTO isp.bl_entities
    (entity_kind, entity_key, metric, cohort, cohort_candidate, cohort_candidate_days,
     level_log, level_prev_log, level_ratio_day, samples, active_hours, excluded_hours,
     state, quality, frozen_until, first_seen, last_seen, built_at)
WITH
    -- resolveEntity (E09 §4.3), idéntica a la de J2/J5 y a la del
    -- detector: customer_id ya es una columna real de v_agg_src_1h (E03
    -- §4.5.3), no hace falta net_customer()/net_scope() acá.
    raw AS
    (
        SELECT
            multiIf(customer_id != '', toUInt8(2),
                    src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
                    toUInt8(4))                                          AS entity_kind,
            multiIf(customer_id != '', customer_id,
                    src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
                    isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                        || '/' || toString({v6_bits:UInt8}))             AS entity_key,
            pps_p95,
            toHour(window_start, {tz:String})                            AS local_hour
        -- El roll-up de E03 §4.5.3 ya filtró flow_dir='outbound': agg_src_1h
        -- no lleva flow_dir en su clave (D-5/§4.4.2). src_scope='customer'
        -- es el mismo filtro que J2 aplica: el perfil y la observación
        -- tienen que medir la misma población.
        FROM isp.v_agg_src_1h
        WHERE window_start >= {from:DateTime} AND window_start < {to:DateTime}
          AND src_scope = 'customer'
    ),
    -- Features de §4.7. day_med/night_med/nivel_diario se calculan solo
    -- sobre horas con tráfico real (pps_p95 > 0): sin ese filtro, una hora
    -- muerta empuja las dos medianas hacia 0 y corrompe ratio_horario.
    features AS
    (
        SELECT
            entity_kind, entity_key,
            quantileExactWeightedIf(0.5)(log1p(pps_p95), toUInt64(1), pps_p95 > 0) AS nivel_diario,
            quantileIf(0.5)(pps_p95, pps_p95 > 0 AND local_hour BETWEEN 9 AND 18)  AS day_med,
            quantileIf(0.5)(pps_p95, pps_p95 > 0 AND (local_hour >= 20 OR local_hour <= 1)) AS night_med,
            count()                                                       AS samples,
            countIf(pps_p95 > 0)                                          AS active_hours
        FROM raw
        GROUP BY entity_kind, entity_key
    ),
    -- Banda de nivel × patrón horario (cortes literales de §4.7), o
    -- 'unknown' con menos de 24 h activas en la ventana: sin suficiente
    -- historia no hay cohorte que justificar frente a un cliente.
    classified AS
    (
        SELECT
            entity_kind, entity_key, samples, active_hours,
            multiIf(
                active_hours < 24, 'unknown',
                concat(
                    -- ClickHouse no tiene expm1(): exp(x)-1 (sin piso de
                    -- precisión especial, aceptable acá porque nivel_diario
                    -- nunca está cerca de 0 salvo en n0, donde el corte de
                    -- banda es ancho).
                    multiIf(exp(nivel_diario) - 1 < 20,   'n0',
                            exp(nivel_diario) - 1 < 200,  'n1',
                            exp(nivel_diario) - 1 < 2000, 'n2',
                            'n3'),
                    '_',
                    multiIf(day_med / greatest(night_med, 1e-6) < 0.7, 'res',
                            day_med / greatest(night_med, 1e-6) > 1.4, 'biz',
                            'flat')
                )
            )                                                             AS cohort_candidate_new
        FROM features
    ),
    -- Estado vigente: los tres campos que ESTE job es dueño de escribir.
    -- join_use_nulls (SETTINGS, abajo) hace que una entidad sin fila
    -- previa dé NULL acá, no el default numérico del tipo -- así
    -- coalesce() en el paso siguiente distingue "primera vez" de "0 real".
    existing AS
    (
        SELECT
            entity_kind, entity_key,
            any(cohort)                 AS cohort,
            any(cohort_candidate)       AS cohort_candidate,
            any(cohort_candidate_days)  AS cohort_candidate_days
        FROM isp.bl_entities FINAL
        GROUP BY entity_kind, entity_key
    ),
    -- Histéresis (§4.7): la racha del candidato solo avanza si la nueva
    -- clasificación repite la del último run -- si CAMBIÓ, la racha
    -- arranca de nuevo en 1, nunca hereda el contador de la clasificación
    -- anterior (esa fue la primera versión de este archivo, y el propio
    -- test contra ClickHouse real de T-329 la atrapó: un cliente que pasa
    -- de res a biz promovía en el primer run, no en el tercero, porque
    -- el contador viejo de 'res' se seguía comparando contra el umbral
    -- después del cambio). Corta a 255 (UInt8) antes de castear, para que
    -- una racha larguísima no dé la vuelta en silencio.
    decided AS
    (
        SELECT
            c.entity_kind                                                AS entity_kind,
            c.entity_key                                                 AS entity_key,
            c.samples                                                    AS samples,
            c.active_hours                                               AS active_hours,
            c.cohort_candidate_new                                       AS cohort_candidate,
            if(c.cohort_candidate_new = coalesce(e.cohort_candidate, ''),
               toUInt8(least(toUInt16(coalesce(e.cohort_candidate_days, toUInt8(0))) + toUInt16(1), toUInt16(255))),
               toUInt8(1))                                                AS cohort_candidate_days,
            coalesce(e.cohort, 'unknown')                                 AS cohort_prev
        FROM classified AS c
        LEFT JOIN existing AS e ON e.entity_kind = c.entity_kind AND e.entity_key = c.entity_key
    ),
    -- La cohorte VIGENTE solo se pisa cuando la racha (ya correcta, de
    -- `decided`) alcanza el umbral de §4.7 -- salvo 'unknown', que se
    -- aplica de inmediato (no es un candidato ambiguo en el borde de una
    -- banda: es "no hay suficiente historia para clasificar", y sostener
    -- la cohorte vieja 3 días más sería mostrarle al operador una banda
    -- que ya no tiene datos que la sostengan).
    promoted AS
    (
        SELECT
            entity_kind, entity_key, samples, active_hours,
            cohort_candidate,
            multiIf(cohort_candidate = 'unknown', toUInt8(0), cohort_candidate_days) AS cohort_candidate_days,
            multiIf(cohort_candidate = 'unknown', 'unknown',
                    cohort_candidate_days >= {hysteresis_days:UInt8}, cohort_candidate,
                    cohort_prev)                                          AS cohort
        FROM decided
    ),
    metrics AS (SELECT arrayJoin(['pps', 'bps', 'uniq_dst_ips', 'uniq_dst_ports', 'flows']) AS metric),
    expanded AS
    (
        SELECT
            p.entity_kind             AS entity_kind,
            p.entity_key              AS entity_key,
            m.metric                  AS metric,
            p.cohort                  AS cohort,
            p.cohort_candidate        AS cohort_candidate,
            p.cohort_candidate_days   AS cohort_candidate_days
        FROM promoted AS p
        CROSS JOIN metrics AS m
    )
-- Carry-forward de los campos que J2 (bl_level.sql) es dueño de escribir,
-- por (entity_kind, entity_key, metric): 'primera vez' usa los defaults
-- de warm-up de §4.9, no NULL ni el cero silencioso del tipo.
SELECT
    x.entity_kind                                             AS entity_kind,
    x.entity_key                                               AS entity_key,
    x.metric                                                    AS metric,
    x.cohort                                                    AS cohort,
    x.cohort_candidate                                          AS cohort_candidate,
    x.cohort_candidate_days                                     AS cohort_candidate_days,
    coalesce(b.level_log, 0.)                                   AS level_log,
    coalesce(b.level_prev_log, 0.)                              AS level_prev_log,
    coalesce(b.level_ratio_day, toFloat32(1.))                  AS level_ratio_day,
    coalesce(b.samples, toUInt32(0))                            AS samples,
    coalesce(b.active_hours, toUInt32(0))                       AS active_hours,
    coalesce(b.excluded_hours, toUInt32(0))                     AS excluded_hours,
    coalesce(b.state, CAST(1 AS Enum8('warmup' = 1, 'ready' = 2, 'stale' = 3, 'quarantined' = 4, 'frozen' = 5))) AS state,
    coalesce(b.quality, toFloat32(0.))                          AS quality,
    coalesce(b.frozen_until, toDateTime(0, 'UTC'))              AS frozen_until,
    coalesce(b.first_seen, {to:DateTime})                       AS first_seen,
    coalesce(b.last_seen, {to:DateTime})                        AS last_seen,
    now64(3)                                                    AS built_at
FROM expanded AS x
LEFT JOIN
(
    SELECT
        entity_kind, entity_key, metric,
        level_log, level_prev_log, level_ratio_day, samples, active_hours, excluded_hours,
        state, quality, frozen_until, first_seen, last_seen
    FROM isp.bl_entities FINAL
) AS b
ON b.entity_kind = x.entity_kind AND b.entity_key = x.entity_key AND b.metric = x.metric
SETTINGS max_memory_usage = 4294967296, max_execution_time = 300, join_use_nulls = 1;
