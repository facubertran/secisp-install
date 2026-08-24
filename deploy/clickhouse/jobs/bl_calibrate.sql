-- bl_calibrate.sql [E09]
--
-- T-337 (E09-T15) + T-338 (E09-T16) -- E09 §4.6.6, §4.6.7, §4.6.8 · E00b
-- D-12 · E09 §9.4 N1, N2 · E09 §5.8, §5.10.
--
-- J6: calibra offset_log/sigma_scale (J6a, T-337) y k_sigma/h_c (J6b,
-- T-338) sobre 14 días de isp.bl_residuals (su propio TTL), excluyendo
-- entidades con caso confirmado/mitigando/mitigado en isp.det_cases, y
-- escribe isp.bl_thresholds keyeado por (detector_id='anomaly.level_shift',
-- metric) -- la misma clave que J5 (bl_residuals.sql, T-334) usa para leer
-- offset_log/sigma_scale via dict_bl_thresholds. Es la única clave que
-- existe hoy: E09 todavía no tiene un job por detector (anomaly.volume_spike
-- / fanout_spike / service_wave llegan en task futura), así que J6 calibra
-- una sola vez por métrica y todo futuro detector que consuma esa métrica
-- lee de acá.
--
-- resid_crudo NO se reconstruye desde z/obs/exp de bl_residuals (ese
-- camino exige invertir z = resid/sigma_use, inestable justo donde más
-- importa: la mayoría de las observaciones normales tiene z cerca de 0,
-- el modo de la campana, así que dividir por z ahí explota). En cambio
-- J6 vuelve a resolver mu_eff/sigma_hat HOY mismo con el mismo patrón
-- L2→L1→L0 que J5 (T-334), usando (entity_kind, entity_key, slot) que sí
-- quedaron grabados en bl_residuals -- resid_crudo = log1p(obs) − mu_eff
-- sale directo, sin aproximar ningún offset viejo.
--
-- Las 5 métricas se resuelven en UNA sola pasada via ARRAY JOIN sobre una
-- tupla (metric, obs) por fila -- dictGetOrDefault acepta `metric` como
-- columna, no hace falta repetir el bloque de resolución 5 veces (a
-- diferencia de bl_residuals.sql/T-334, que sí lo generaba con plantilla
-- porque ahí `metric` decide el NOMBRE de columna de salida, acá no).
--
-- El cuantil de k_sigma sí exige 5 bloques (uno por métrica): el nivel de
-- quantileExact() tiene que ser una expresión constante por consulta, no
-- puede variar por GRUPO dentro de la misma pasada -- target_rate depende
-- de entities_tested, que es distinto por métrica. Cada bloque es una
-- subconsulta escalar no correlacionada (referencia una métrica literal),
-- así que ClickHouse la resuelve una sola vez.
--
-- h_c de anomaly.level_shift (T-338, criterio 5) se calibra SOLO para la
-- fila metric='pps': level_shift es por definición el detector de cambios
-- de NIVEL (pps), y bl_thresholds.k_sigma sirve doble función según el
-- comentario del DDL ("umbral vigente, o h de CUSUM") -- en esa fila
-- concreta, k_sigma ES h_c, calibrado con CUSUM (stats.CUSUMMax, k_c=0.5)
-- en vez del cuantil de z crudo. Las otras 4 métricas quedan con su
-- k_sigma de cuantil-de-z estándar, sin consumidor todavía, publicadas
-- por completitud/auditoría (criterio de aceptación de T-337: "el vigente
-- y el medido... las publican").
--
-- Parámetros: {from:DateTime} {to:DateTime} {mad_log_floor:Float64}
--   {max_offset_log_rate:Float64} {max_offset_log_card:Float64}
--   {max_offset_step:Float64} {sigma_scale_min:Float64}
--   {sigma_scale_max:Float64} {target_fp_per_day:Float64} {k_min:Float64}
--   {k_max:Float64} {k_max_step:Float64} {k_min_samples:UInt64}
--   {k_c:Float64} {h_c_default:Float64} {windows_per_day:Float64}
--   {floor_pps:Float64} {floor_bps:Float64} {floor_uniq_dst_ips:Float64}
--   {floor_uniq_dst_ports:Float64} {floor_flows:Float64} {veto_max_sigma:Float64}
--   {veto_ceiling_pps:Float64} {veto_ceiling_uniq_dst:Float64}

INSERT INTO isp.bl_thresholds
    (detector_id, metric, k_sigma, k_sigma_measured, offset_log, offset_log_measured,
     max_offset_log, sigma_scale, sigma_scale_measured, floor_value, veto_max_sigma,
     veto_ceiling, target_fp_per_day, measured_fp_per_day, entities_tested,
     residual_samples, calibration_source)
WITH
    -- Entidades con caso activo (confirmado en adelante) en la ventana:
    -- solo customer/src_ip tienen correspondencia directa con det_cases
    -- (keyeado por (src_ip, attack_class), E05 §4). cohort/global/prefix
    -- agregan muchas IPs -- un caso de una IP no descalifica el cohorte
    -- entero, misma lógica que la exclusión de J2 (bl_level.sql, T-331)
    -- aplicada a nivel de entidad, no de agregado.
    excluded_entities AS
    (
        SELECT DISTINCT toUInt8(2) AS entity_kind, customer_id AS entity_key
        FROM isp.det_cases
        WHERE state IN ('confirmed', 'mitigating', 'mitigated')
          AND customer_id != ''
          AND last_event_at >= {from:DateTime}
        UNION ALL
        SELECT DISTINCT toUInt8(3) AS entity_kind, isp_ip_str(src_ip) AS entity_key
        FROM isp.det_cases
        WHERE state IN ('confirmed', 'mitigating', 'mitigated')
          AND last_event_at >= {from:DateTime}
    ),
    -- Las 5 métricas de bl_residuals, desplegadas como filas (metric, obs).
    unpivoted AS
    (
        SELECT
            r.entity_kind AS entity_kind, r.entity_key AS entity_key,
            r.slot AS slot, r.window_start AS window_start,
            m.1 AS metric, m.2 AS obs
        FROM isp.bl_residuals AS r
        ARRAY JOIN
            [tuple('pps', r.obs_pps), tuple('bps', r.obs_bps),
             tuple('uniq_dst_ips', toFloat64(r.obs_uniq_dst_ips)),
             tuple('uniq_dst_ports', toFloat64(r.obs_uniq_dst_ports)),
             tuple('flows', toFloat64(r.obs_flows))] AS m
        WHERE r.window_start >= {from:DateTime} AND r.window_start < {to:DateTime}
          AND (r.entity_kind, r.entity_key) NOT IN (SELECT entity_kind, entity_key FROM excluded_entities)
    ),
    -- Re-resolución HOY de mu_eff/sigma_hat, mismo patrón L2→L1→L0 que
    -- J5 (E09 §4.6.5, bl_residuals.sql).
    fresh AS
    (
        SELECT
            u.entity_kind AS entity_kind, u.entity_key AS entity_key,
            u.window_start AS window_start, u.metric AS metric, u.obs AS obs,
            dictGetOrDefault('isp.dict_bl_profile', ('mu_log', 'mad_log', 'ready', 'quality', 'n_eff'),
                             (u.entity_kind, u.entity_key, u.metric, u.slot),
                             (toFloat64(0), toFloat64(0), toUInt8(0), toFloat32(0), toUInt32(0)))  AS p2,
            dictGetOrDefault('isp.dict_bl_entity', ('cohort', 'level_log', 'state', 'quality'),
                             (u.entity_kind, u.entity_key, u.metric),
                             ('unknown', toFloat64(0), toUInt8(0), toFloat32(0)))                   AS en,
            dictGetOrDefault('isp.dict_bl_profile', ('shape_log', 'mad_log', 'ready', 'quality', 'n_eff'),
                             (toUInt8(1), en.1, u.metric, u.slot),
                             (toFloat64(0), toFloat64(0), toUInt8(0), toFloat32(0), toUInt32(0)))   AS p1,
            dictGetOrDefault('isp.dict_bl_profile', ('shape_log', 'mad_log', 'ready', 'quality', 'n_eff'),
                             (toUInt8(0), '', u.metric, u.slot),
                             (toFloat64(0), toFloat64(0), toUInt8(0), toFloat32(0), toUInt32(0)))   AS p0,
            multiIf(p2.3 = 1 AND en.3 != 4, p2.1,
                    p1.3 = 1 AND en.3 IN (2, 5), en.2 + p1.1,
                    p0.3 = 1 AND en.3 IN (2, 5), en.2 + p0.1,
                    CAST(nan, 'Float64'))                                                           AS mu_eff,
            greatest(1.4826 * multiIf(p2.3 = 1 AND en.3 != 4, p2.2,
                                      p1.3 = 1, p1.2,
                                      p0.2),
                     {mad_log_floor:Float64})                                                       AS sigma_hat
        FROM unpivoted AS u
    ),
    -- Solo entidades con algún nivel resuelto (mu_eff no NaN) -- las que
    -- no tienen ni L2 ni L1 ni L0 no aportan residual crudo utilizable.
    resolved AS
    (
        SELECT
            entity_kind, entity_key, window_start, metric, obs, mu_eff, sigma_hat,
            log1p(obs) - mu_eff AS resid_crudo
        FROM fresh
        WHERE NOT isNaN(mu_eff)
    ),
    offset_per_metric AS
    (
        SELECT metric, quantileExact(0.5)(resid_crudo) AS offset_measured
        FROM resolved
        GROUP BY metric
    ),
    deviations AS
    (
        SELECT
            r.entity_kind AS entity_kind, r.entity_key AS entity_key, r.metric AS metric,
            abs(r.resid_crudo - o.offset_measured) AS dev, r.sigma_hat AS sigma_hat
        FROM resolved AS r
        INNER JOIN offset_per_metric AS o ON o.metric = r.metric
    ),
    scale_per_metric AS
    (
        SELECT
            metric,
            1.4826 * quantileExact(0.5)(dev)   AS mad_dev,
            quantileExact(0.5)(sigma_hat)      AS sigma_hat_median,
            count()                            AS residual_samples,
            uniqExact(entity_kind, entity_key) AS entities_tested
        FROM deviations
        GROUP BY metric
    ),
    current_vigente AS
    (
        SELECT metric, offset_log AS offset_vigente, sigma_scale AS sigma_scale_vigente,
               k_sigma AS k_sigma_vigente
        FROM isp.bl_thresholds FINAL
        WHERE detector_id = 'anomaly.level_shift'
    ),
    -- Guardas de J6a (T-337): tope absoluto por métrica, paso diario en
    -- offset, recorte + paso relativo del 50 % en sigma_scale, forzado a
    -- 1.0 en pps/bps "por construcción" (criterio de aceptación).
    calibrated_offset_scale AS
    (
        SELECT
            o.metric AS metric,
            s.residual_samples AS residual_samples,
            s.entities_tested AS entities_tested,
            o.offset_measured AS offset_measured_raw,
            multiIf(o.metric IN ('pps', 'bps'), {max_offset_log_rate:Float64}, {max_offset_log_card:Float64}) AS max_offset_log,
            coalesce(v.offset_vigente, toFloat64(0))      AS offset_vigente,
            coalesce(v.sigma_scale_vigente, toFloat64(1)) AS sigma_scale_vigente,
            coalesce(v.k_sigma_vigente, toFloat64(6.0))   AS k_sigma_vigente,
            (s.mad_dev / greatest(s.sigma_hat_median, 1e-6)) AS sigma_scale_measured_raw,
            -- offset: tope absoluto por métrica, después paso diario vs vigente.
            least(max_offset_log, greatest(-max_offset_log, o.offset_measured))         AS offset_capped,
            multiIf(abs(offset_capped - offset_vigente) > {max_offset_step:Float64},
                    offset_vigente + sign(offset_capped - offset_vigente) * {max_offset_step:Float64},
                    offset_capped)                                                       AS offset_new,
            -- sigma_scale: forzado a 1.0 en pps/bps; si no, recorte [min,max]
            -- y paso relativo máximo del 50 % vs vigente.
            multiIf(o.metric IN ('pps', 'bps'), toFloat64(1),
                    least({sigma_scale_max:Float64}, greatest({sigma_scale_min:Float64}, sigma_scale_measured_raw))) AS sigma_scale_capped,
            multiIf(o.metric IN ('pps', 'bps'), toFloat64(1),
                    sigma_scale_vigente > 0 AND abs(sigma_scale_capped / sigma_scale_vigente - 1) > 0.5,
                    least({sigma_scale_max:Float64}, greatest({sigma_scale_min:Float64},
                          sigma_scale_vigente * (1 + sign(sigma_scale_capped - sigma_scale_vigente) * 0.5))),
                    sigma_scale_capped)                                                  AS sigma_scale_new,
            (abs(offset_new - offset_capped) > 1e-9 OR abs(sigma_scale_new - sigma_scale_capped) > 1e-9) AS was_clamped
        FROM offset_per_metric AS o
        INNER JOIN scale_per_metric AS s ON s.metric = o.metric
        LEFT JOIN current_vigente AS v ON v.metric = o.metric
    ),
    -- z recalculado con el offset/escala YA calibrados de este mismo run
    -- (T-338: el cuantil de k_sigma tiene que reflejar la calibración
    -- nueva, no la vieja que pudo haber quedado obsoleta hace 14 días).
    z_fresh_rows AS
    (
        SELECT
            r.entity_kind AS entity_kind, r.entity_key AS entity_key,
            r.window_start AS window_start, r.metric AS metric,
            (r.resid_crudo - c.offset_new) / (r.sigma_hat * c.sigma_scale_new) AS z
        FROM resolved AS r
        INNER JOIN calibrated_offset_scale AS c ON c.metric = r.metric
    ),
    -- Cuantil de k por métrica: 5 subconsultas escalares no correlacionadas
    -- (una por metric literal) -- quantileExact() exige un nivel constante
    -- por consulta, no puede variar por GRUPO en una sola pasada.
    k_quantiles AS
    (
        SELECT 'pps' AS metric,
               quantileExact(greatest(0.0, least(0.999999,
                   1 - {target_fp_per_day:Float64} / (greatest(coalesce((SELECT entities_tested FROM scale_per_metric WHERE metric = 'pps'), 1), 1) * {windows_per_day:Float64})
               )))(z) AS k_measured
        FROM z_fresh_rows WHERE metric = 'pps'
        UNION ALL
        SELECT 'bps' AS metric,
               quantileExact(greatest(0.0, least(0.999999,
                   1 - {target_fp_per_day:Float64} / (greatest(coalesce((SELECT entities_tested FROM scale_per_metric WHERE metric = 'bps'), 1), 1) * {windows_per_day:Float64})
               )))(z) AS k_measured
        FROM z_fresh_rows WHERE metric = 'bps'
        UNION ALL
        SELECT 'uniq_dst_ips' AS metric,
               quantileExact(greatest(0.0, least(0.999999,
                   1 - {target_fp_per_day:Float64} / (greatest(coalesce((SELECT entities_tested FROM scale_per_metric WHERE metric = 'uniq_dst_ips'), 1), 1) * {windows_per_day:Float64})
               )))(z) AS k_measured
        FROM z_fresh_rows WHERE metric = 'uniq_dst_ips'
        UNION ALL
        SELECT 'uniq_dst_ports' AS metric,
               quantileExact(greatest(0.0, least(0.999999,
                   1 - {target_fp_per_day:Float64} / (greatest(coalesce((SELECT entities_tested FROM scale_per_metric WHERE metric = 'uniq_dst_ports'), 1), 1) * {windows_per_day:Float64})
               )))(z) AS k_measured
        FROM z_fresh_rows WHERE metric = 'uniq_dst_ports'
        UNION ALL
        SELECT 'flows' AS metric,
               quantileExact(greatest(0.0, least(0.999999,
                   1 - {target_fp_per_day:Float64} / (greatest(coalesce((SELECT entities_tested FROM scale_per_metric WHERE metric = 'flows'), 1), 1) * {windows_per_day:Float64})
               )))(z) AS k_measured
        FROM z_fresh_rows WHERE metric = 'flows'
    ),
    -- h_c de anomaly.level_shift (CUSUM, T-338 criterio 5): solo pps.
    -- S_0=0, S_t=max(0,S_{t-1}+z_t−k_c), max_t(S_t) POR ENTIDAD
    -- (stats.CUSUMMax, T-324), después cuantil sobre la población de
    -- entidades -- mismo camino que k_sigma, pero la unidad de muestreo
    -- es "una entidad durante 14 días", no "una ventana de 5 min".
    per_entity_z_pps AS
    (
        SELECT entity_kind, entity_key, groupArray(z) AS zs, count() AS n
        FROM (SELECT entity_kind, entity_key, window_start, z FROM z_fresh_rows WHERE metric = 'pps' ORDER BY entity_kind, entity_key, window_start)
        GROUP BY entity_kind, entity_key
        HAVING n >= 10
    ),
    per_entity_cusum_max AS
    (
        SELECT
            entity_kind, entity_key,
            arrayFold((acc, z) -> tuple(
                          greatest(0.0, acc.1 + z - {k_c:Float64}),
                          greatest(acc.2, greatest(0.0, acc.1 + z - {k_c:Float64}))
                      ), zs, tuple(0.0, 0.0)).2 AS cusum_max
        FROM per_entity_z_pps
    ),
    -- quantileExact() exige un nivel constante: count() es en sí mismo un
    -- agregado sobre las MISMAS filas, así que no puede ir adentro del
    -- nivel de OTRO agregado en la misma pasada -- se separa en un CTE
    -- previo, igual que k_quantiles con scale_per_metric.
    hc_entity_count AS
    (
        SELECT count() AS entities_for_hc FROM per_entity_cusum_max
    ),
    h_c_result AS
    (
        SELECT
            quantileExact(greatest(0.0, least(0.999999,
                1 - {target_fp_per_day:Float64} * 14 / greatest((SELECT entities_for_hc FROM hc_entity_count), 1)
            )))(cusum_max) AS h_c_measured
        FROM per_entity_cusum_max
    ),
    -- k_sigma/h_c final por métrica: recorte [K_MIN,K_MAX] (h_c reusa el
    -- mismo piso/techo que k_sigma -- T-338: "h_c... se calibra por el
    -- MISMO camino", y no hay un H_MIN/H_MAX propio en BaselineConfig; sin
    -- este recorte, corridas repetidas con h_c_measured≈0 -- CUSUM que
    -- nunca acumula, ver el comentario de per_entity_cusum_max -- hacían
    -- que el paso diario de 0.5 arrastrara h_c por debajo de K_MIN sin
    -- fondo, verificado en vivo: 6→5.5→…→1.5 en seis corridas de prueba,
    -- nunca se detuvo en 3.5) + paso diario 0.5 vs vigente, aparte para
    -- que measured_fp_per_day pueda contar exceedencias contra el MISMO
    -- valor que se termina escribiendo, no contra el crudo.
    k_final AS
    (
        SELECT
            c.metric AS metric,
            c.entities_tested AS entities_tested,
            c.residual_samples AS residual_samples,
            c.was_clamped AS offset_scale_clamped,
            multiIf(c.metric = 'pps',
                    if(hc.entities_for_hc = 0, {h_c_default:Float64},
                       multiIf(abs(least({k_max:Float64}, greatest({k_min:Float64}, h.h_c_measured)) - c.k_sigma_vigente) > {k_max_step:Float64},
                               c.k_sigma_vigente + sign(least({k_max:Float64}, greatest({k_min:Float64}, h.h_c_measured)) - c.k_sigma_vigente) * {k_max_step:Float64},
                               least({k_max:Float64}, greatest({k_min:Float64}, h.h_c_measured)))),
                    c.residual_samples < {k_min_samples:UInt64}, c.k_sigma_vigente,
                    multiIf(abs(least({k_max:Float64}, greatest({k_min:Float64}, k.k_measured)) - c.k_sigma_vigente) > {k_max_step:Float64},
                            c.k_sigma_vigente + sign(least({k_max:Float64}, greatest({k_min:Float64}, k.k_measured)) - c.k_sigma_vigente) * {k_max_step:Float64},
                            least({k_max:Float64}, greatest({k_min:Float64}, k.k_measured))))          AS k_final,
            if(c.metric = 'pps', h.h_c_measured, k.k_measured)                                          AS k_measured,
            multiIf(c.metric = 'pps',
                    hc.entities_for_hc != 0 AND abs(least({k_max:Float64}, greatest({k_min:Float64}, h.h_c_measured)) - c.k_sigma_vigente) > {k_max_step:Float64},
                    c.residual_samples >= {k_min_samples:UInt64}
                        AND abs(least({k_max:Float64}, greatest({k_min:Float64}, k.k_measured)) - c.k_sigma_vigente) > {k_max_step:Float64}) AS k_was_clamped
        FROM calibrated_offset_scale AS c
        LEFT JOIN k_quantiles AS k ON k.metric = c.metric
        CROSS JOIN h_c_result AS h
        CROSS JOIN hc_entity_count AS hc
    ),
    -- FP/día medido contra el k/h_c FINAL (ya recortado): exceedencias
    -- de z (o de cusum_max en pps) sobre 14 días, normalizadas a 1 día.
    exceedances AS
    (
        SELECT
            z.metric AS metric,
            countIf(z.z > f.k_final) / 14.0 AS measured_fp_per_day
        FROM z_fresh_rows AS z
        INNER JOIN k_final AS f ON f.metric = z.metric
        WHERE z.metric != 'pps'
        GROUP BY z.metric
        UNION ALL
        SELECT
            'pps' AS metric,
            countIf(cm.cusum_max > (SELECT k_final FROM k_final WHERE metric = 'pps')) / 14.0 AS measured_fp_per_day
        FROM per_entity_cusum_max AS cm
    )
SELECT
    'anomaly.level_shift' AS detector_id,
    c.metric AS metric,
    f.k_final AS k_sigma,
    f.k_measured AS k_sigma_measured,
    c.offset_new AS offset_log,
    c.offset_measured_raw AS offset_log_measured,
    c.max_offset_log AS max_offset_log,
    c.sigma_scale_new AS sigma_scale,
    c.sigma_scale_measured_raw AS sigma_scale_measured,
    -- floor_value es "espejo del Param del detector, para auditoría"
    -- (63_bl_thresholds.sql): los mismos pisos D9 que bl.profile_l2 (J4)
    -- ya expone como floor_pps/floor_bps/etc (profile_l2.go) -- no se
    -- vuelven a dividir por FLOOR_DIVISOR acá, ya vienen divididos.
    multiIf(c.metric = 'pps', {floor_pps:Float64},
            c.metric = 'bps', {floor_bps:Float64},
            c.metric = 'uniq_dst_ips', {floor_uniq_dst_ips:Float64},
            c.metric = 'uniq_dst_ports', {floor_uniq_dst_ports:Float64},
            {floor_flows:Float64})                         AS floor_value,
    {veto_max_sigma:Float64} AS veto_max_sigma,
    -- veto_ceiling es por métrica en BaselineConfig (VetoCeilingPPS /
    -- VetoCeilingUniqDst, E09 §4.12): bps/flows no tienen techo propio
    -- todavía (el veto en sí es T-347, sin construir) -- 0 = sin techo.
    multiIf(c.metric = 'pps', {veto_ceiling_pps:Float64},
            c.metric IN ('uniq_dst_ips', 'uniq_dst_ports'), {veto_ceiling_uniq_dst:Float64},
            toFloat64(0))                                  AS veto_ceiling,
    {target_fp_per_day:Float64} AS target_fp_per_day,
    coalesce(e.measured_fp_per_day, toFloat64(0)) AS measured_fp_per_day,
    c.entities_tested AS entities_tested,
    c.residual_samples AS residual_samples,
    multiIf(c.was_clamped OR f.k_was_clamped, 'clamped',
            c.metric != 'pps' AND c.residual_samples < {k_min_samples:UInt64}, 'default',
            'empirical') AS calibration_source
FROM calibrated_offset_scale AS c
INNER JOIN k_final AS f ON f.metric = c.metric
LEFT JOIN exceedances AS e ON e.metric = c.metric
-- join_use_nulls=1: sin esto, current_vigente/LEFT JOIN devuelve el cero
-- del tipo (Float64 0) en vez de NULL para una métrica sin fila previa en
-- bl_thresholds, y coalesce(...,6.0) nunca cae al default -- mismo bug de
-- clase que J2 (bl_level.sql, T-331) ya documentó y corrigió.
SETTINGS max_memory_usage = 4294967296, max_execution_time = 300, join_use_nulls = 1;
