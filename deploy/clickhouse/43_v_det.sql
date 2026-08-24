-- 43_v_det.sql [E05]
--
-- T-074 (E05-T06) -- E05 §4.11, §5.4, §5.8 · E00b D-34, D-35 · E00c C-6, C-7 ·
-- E00f H-1 · E05 §9 Q10, Q13.
--
-- Las cuatro vistas de E05 que NO quedaron en 40_det.sql: §4.11/§5.4 declara
-- v_det_case_events, v_det_runs y v_det_suppressed_1h junto a
-- v_det_events/v_det_cases, y §5.8 declara v_det_detectors sobre
-- isp.dim_detectors (42_dim_detectors.sql). Por la regla de propiedad de
-- archivos (../../docs/plan/secuencia-de-desarrollo.md §7 bis, nota final),
-- T-073 (40_det.sql) se quedó con v_det_events/v_det_cases y esta task hereda
-- las otras cuatro más la verificación de que ninguna de las SEIS vistas
-- v_det_* se descubre rota en producción (test/schema/e05_views_smoke_test.go).
--
-- H-1 (E00f): ClickHouse SÍ resuelve el cuerpo de una vista al crearla -- la
-- premisa contraria de la vieja E03 §9.7 es falsa, y es la que dejó a estas
-- mismas siete vistas fuera del instalador en la ronda anterior. Este archivo
-- va DESPUÉS de 40_det.sql (det_events, det_cases, ops_detect_state),
-- 41_det_suppress.sql (comparte el rango 40-43 de E05, aunque ninguna vista
-- de acá lo lea) y 42_dim_detectors.sql (dim_detectors, que v_det_detectors
-- envuelve), y tiene que ir ANTES de 70_v_panel.sql (todavía no escrito --
-- ola posterior), que declara v_ops_blind sobre v_det_runs: si este archivo
-- no existiera, ese CREATE VIEW abortaría y con él TODO 70_ en adelante,
-- incluido 95_roles_grants.sql -- sin roles ni usuarios, Grafana da
-- ACCESS_DENIED en todos los paneles, el mitigador no lee det_cases y el
-- collector no inserta.
--
-- isp.dict_detector_family (COMPLEX_KEY_HASHED, PRIMARY KEY detector_id
-- String, C-6/D-35) YA EXISTE -- lo crea 08_dict.sql (T-066) con SOURCE
-- apuntando a isp.v_det_detectors, la vista que este archivo declara. Es la
-- ÚNICA excepción de orden de todo el layout (08 < 43 mientras el
-- diccionario lee de un archivo de número MAYOR) y es legal SOLO para
-- CREATE DICTIONARY, nunca para CREATE VIEW: la carga diferida
-- (dictionaries_lazy_load=1, default de ClickHouse) hace que el CREATE
-- DICTIONARY no resuelva su SOURCE al crearse, y para cuando el primer
-- dictGet real lo dispare, 43_ ya se aplicó (E03 §4.9.1). Este archivo NO
-- vuelve a declarar el diccionario.
--
-- D-34: la UDF de renderizado de IP se llama isp_ip_str (ClickHouse no admite
-- '.' en un nombre de UDF) -- NUNCA ip_str( ni isp.ip_str(. Ninguna de las
-- cuatro vistas de acá llama a la UDF directamente: las columnas *_str ya
-- vienen resueltas desde v_det_cases/v_det_events (40_det.sql, T-073), que
-- E10 usa en vez de las tablas base (§5.4, párrafo final).

-- ═══════════════════════════════════════════════════════════════════════════
-- v_det_case_events -- join caso<->evento para el drill-down de E10 (§4.11,
-- §5.4). Lee las DOS vistas de 40_det.sql, no las tablas base.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_det_case_events
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
SELECT c.case_id, c.src_ip_str, c.attack_class, c.state, c.peak_score,
       e.event_id, e.window_start, e.detector_id, e.score, e.confidence,
       e.suppressed, e.suppress_reason, e.dst_kind, e.dst_ip_str, e.dst_port, e.proto,
       e.pps, e.bps, e.uniq_dst_ips
FROM isp.v_det_cases AS c
INNER JOIN isp.v_det_events AS e USING (case_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- v_det_runs -- salud del motor por detector y ventana (§4.11, §5.4). Lee
-- ops_detect_state FINAL (ReplacingMergeTree, E05 §5.2): la cola de
-- pendientes del replay del WAL (D-30, status='pending', incluida la fila
-- sintética __replay_cursor__) y el watermark quedan visibles acá para quien
-- se pregunta por qué la cola no drena.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_det_runs
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
SELECT detector_id, detector_version, window_start, window_end, evaluated_at, eval_count,
       status, error_code, findings, events_emitted, events_suppressed, truncated,
       duration_ms, rows_read, memory_peak_bytes, query_id, engine_instance,
       now() - window_end AS lag_s
FROM isp.ops_detect_state FINAL;

-- ═══════════════════════════════════════════════════════════════════════════
-- v_det_suppressed_1h -- agregado de eventos suprimidos por detector y razón
-- (§4.11, §5.4). Es la vista que se mira para promover un detector de
-- shadow a alert: sin ella, E12 no puede medir O5 (E00f H-1).
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_det_suppressed_1h
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
SELECT toStartOfHour(window_start) AS hour,
       detector_id, detector_version, suppress_reason,
       count()                                   AS events,
       uniqExact(src_ip)                         AS uniq_srcs,
       quantile(0.95)(score)                     AS score_p95,
       max(score)                                AS score_max
FROM isp.det_events FINAL
WHERE suppressed = 1
GROUP BY hour, detector_id, detector_version, suppress_reason;

-- ═══════════════════════════════════════════════════════════════════════════
-- v_det_detectors -- catálogo detector_id -> family, version, class, mode,
-- window/cadence, is_composite (§4.11, §5.8). Envuelve isp.dim_detectors
-- (42_dim_detectors.sql, T-073), que el motor reescribe al arrancar y en
-- cada cambio de modo. Es el SOURCE de isp.dict_detector_family
-- (08_dict.sql), aunque esta vista se cree DESPUÉS del diccionario que la
-- lee -- ver la nota de cabecera sobre la única excepción de orden legal.
-- ═══════════════════════════════════════════════════════════════════════════
CREATE OR REPLACE VIEW isp.v_det_detectors
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
SELECT detector_id, detector_version, attack_class, family,
       mode, mode_updated_at,
       window_seconds, cadence_seconds, is_composite,
       description, params_hash, registered_at,
       -- "mode IN (...)" sobre un LowCardinality(String) devuelve
       -- LowCardinality(UInt8) -- y toUInt8(...) NO lo despega, porque los
       -- conversores preservan el LowCardinality del argumento (verificado
       -- contra ClickHouse 24.8 real con toTypeName()). ClickHouse rechaza esa
       -- columna al CREATE VIEW ("prohibited by default due to expected
       -- negative impact on performance") salvo
       -- allow_suspicious_low_cardinality_types, que no hay ninguna razón
       -- para pedir por un solo UInt8. El CAST a String desnudo, ANTES del IN,
       -- es lo que efectivamente despega el LowCardinality (también verificado
       -- con toTypeName(): da UInt8 llano).
       CAST(mode AS String) IN ('alert','mitigate') AS is_actionable
FROM isp.dim_detectors FINAL;
