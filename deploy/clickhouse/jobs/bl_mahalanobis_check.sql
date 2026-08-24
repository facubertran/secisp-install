-- bl_mahalanobis_check.sql [E09]
--
-- T-432 (E09-T35) -- E09 D12, §4.6.9, E09-13: el criterio MEDIBLE para
-- revisar D12 ("nada de ML pesado -- una mediana, un MAD y una suma
-- acumulada son el límite superior de complejidad de esta épica"). D12
-- dice literal cuándo se revisa: "si tras 90 días de operación de F3 el
-- análisis de residuales muestra que existen ataques confirmados (casos
-- con mitigación efectiva) en los que ninguna métrica univariada superó
-- k, pero la combinación sí es atípica". Este archivo mide la MITAD
-- observable de esa frase (cuántos casos así existen) -- la otra mitad
-- ("pero la combinación sí es atípica") es, textual, la justificación
-- para construir Mahalanobis, no algo que se pueda medir SIN Mahalanobis
-- ya construido -- E09-13 no lo pide: pide la fracción de casos "ciegos"
-- al univariado, el número que dispara la conversación, no una prueba de
-- que Mahalanobis los habría atrapado.
--
-- "mitigación efectiva" = isp.det_cases.state='mitigated' ("aplicado en
-- TODOS los routers destino", comentario literal del DDL, 40_det.sql) --
-- un caso no llega a 'mitigated' sin haber sido 'confirmed' antes (E00
-- §4.3.6, la máquina de estados es lineal open->confirmed->mitigating->
-- mitigated), así que filtrar por este único estado ya captura "confirmado
-- CON mitigación efectiva" sin un JOIN aparte contra isp.mit_actions.
--
-- Sin restricción de attack_class a propósito: la pregunta de D12 es si
-- el ANÁLISIS UNIVARIADO (cualquier detector, cualquier clase) se habría
-- perdido el caso -- scan/ddos_out/smtp_spam/anomaly cuentan igual.
--
-- resolveEntity (E09 §4.3) idéntica carácter a carácter a bl_level.sql/
-- bl_shape.sql/bl_profile_l2.sql -- el mismo criterio de siempre: J5 y
-- este archivo tienen que resolver la MISMA clave o el JOIN contra
-- bl_residuals no encuentra nada, en silencio.
--
-- k es un solo umbral para las cinco métricas, a propósito (D12 no pide
-- un k por métrica acá): es el mismo k_sigma_default que volume_spike/
-- fanout_spike/level_shift comparten cuando no se recalibró (E09 §4.6.6),
-- el "cuántas sigmas es sospechoso" genérico de la épica, no el k_sigma
-- calibrado de un detector puntual -- ver el comentario de cabecera de
-- report.go sobre por qué una constante única, no cinco calibradas, es
-- la lectura correcta de "el límite superior de complejidad... es una
-- mediana, un MAD" (D12): este informe no recalibra nada, solo cuenta.
--
-- Límite real, a propósito de nombrar acá: isp.bl_residuals tiene TTL de
-- 14 días (62_bl_residuals.sql, D11) -- un caso 'mitigated' de hace más
-- de 14 días ya NO TIENE residuales que consultar, y esta query lo va a
-- contar como "sin métrica univariada por encima de k" no porque el
-- univariado lo haya pasado por alto, sino porque la EVIDENCIA expiró.
-- "Informe mensual" (E09-13) es literal en la historia, pero solo es
-- CORRECTO si algo corre esta query con más frecuencia que el TTL (al
-- menos cada 14 días) y ARCHIVA el resultado para la comparación de 2
-- meses -- esta task entrega la MEDICIÓN de un mes ya cerrado tal como
-- GenerateMahalanobisReport la pide (ver el comentario de cabecera de
-- report.go), no el scheduler/persistencia que la hace válida corriendo
-- una vez al mes sobre datos de hace semanas. Documentado, no resuelto
-- acá -- mismo criterio que el resto de esta ola aplica a huecos reales
-- más grandes que una task puntual.
--
-- Parámetros: {from:DateTime('UTC')} {to:DateTime('UTC')} {k:Float64} {v6_bits:UInt8}

SELECT
    count()                                        AS cases_total,
    countIf(NOT univariate_exceeded)                AS cases_no_univariate,
    toFloat64(countIf(NOT univariate_exceeded)) / greatest(count(), 1) AS fraction
FROM
(
    SELECT
        c.case_id AS case_id,
        -- La condición de ventana vive ACÁ, no en el ON de abajo:
        -- ClickHouse (24.8 y 25.11, las dos versiones que corre esta
        -- ola) rechaza un JOIN cuyo ON mezcla una columna de cada lado
        -- con una desigualdad ("join expression contains column from
        -- left and right table") salvo con
        -- allow_experimental_join_condition -- una bandera experimental
        -- que este archivo evita a propósito (mismo criterio de
        -- conservadurismo que el resto del repo con "experimental_*").
        -- El ON de abajo solo iguala (entity_kind, entity_key) -- trae
        -- TODOS los residuales de esa entidad -- y esta fila descarta
        -- los que caen fuera de [opened_at, last_event_at+5m) adentro
        -- del propio max(): un residual fuera de ventana contribuye
        -- `false`, exactamente como si no existiera.
        max(
            r.window_start >= c.opened_at AND r.window_start < c.last_event_at + toIntervalMinute(5)
            AND (
                abs(r.z_pps) > {k:Float64} OR abs(r.z_bps) > {k:Float64}
                OR abs(r.z_uniq_dst_ips) > {k:Float64} OR abs(r.z_uniq_dst_ports) > {k:Float64}
                OR abs(r.z_flows) > {k:Float64}
            )
        ) AS univariate_exceeded
    FROM
    (
        SELECT
            case_id, src_ip, customer_id, opened_at, last_event_at,
            multiIf(customer_id != '', toUInt8(2),
                    src_ip <= toIPv6('::ffff:255.255.255.255'), toUInt8(3),
                    toUInt8(4))                                          AS entity_kind,
            multiIf(customer_id != '', customer_id,
                    src_ip <= toIPv6('::ffff:255.255.255.255'), isp_ip_str(src_ip),
                    isp_ip_str(tupleElement(IPv6CIDRToRange(src_ip, {v6_bits:UInt8}), 1))
                        || '/' || toString({v6_bits:UInt8}))             AS entity_key
        FROM isp.det_cases
        WHERE state = 'mitigated'
          AND opened_at >= {from:DateTime('UTC')} AND opened_at < {to:DateTime('UTC')}
    ) AS c
    -- LEFT JOIN: un caso sin NINGÚN residual en su ventana (entidad bajo
    -- el piso de inclusión de J5, D11, o el residual todavía no corrió)
    -- cuenta como univariate_exceeded=false (max() de un conjunto vacío
    -- de condiciones -- ninguna métrica pudo haber superado k porque no
    -- hay ninguna medición -- honesto, no un falso "sí lo atrapó").
    LEFT JOIN
    (
        SELECT window_start, entity_kind, entity_key,
               z_pps, z_bps, z_uniq_dst_ips, z_uniq_dst_ports, z_flows
        FROM isp.bl_residuals
    ) AS r
    ON r.entity_kind = c.entity_kind AND r.entity_key = c.entity_key
    GROUP BY c.case_id
)
