-- 60_bl_profiles.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.2, §5.3 · E00b D-13 · E00e G-1 · E09 §9.4
-- N10, N11 · E09 §9.6 N18 · E09 §9.7 N25 · E00b D-35 · E00f H-1.
--
-- Forma/perfil por (entidad, métrica, slot): la "forma" de la cohorte y del
-- global (entity_kind 0/1, shape_log) y el perfil propio de L2 (entity_kind
-- 2..4, mu_log) que J2/J3/J4 escriben (E09 §4.6, §4.8). 60_ es ESTE archivo,
-- no 61_: la numeración vieja los tenía cruzados (§9.4 N10) y
-- v_bl_coverage, en 61_bl_entities.sql, lee las dos tablas -- tiene que
-- encontrar bl_profiles ya creada.
--
-- Esta es una de las siete tablas de la tabla archivo<->objeto que E09 §5.1
-- publica como fuente de verdad (G-1): E03 §4.9.1 la transcribe literal y
-- NUNCA al revés. Los nombres son bl_profiles/bl_entities/bl_residuals/
-- bl_thresholds/bl_service_seen/bl_service_1h/bl_calendar -- nunca
-- bl_observations/bl_scores/bl_jobs/bl_cohorts/bl_events, que eran una
-- invención de una versión vieja del plan y que esta épica jamás declaró.
--
-- El diccionario y la vista de lectura van en ESTE archivo, no en un
-- 6x_bl_dict.sql aparte: no existe tal archivo (G-1, N18). Los ocho jobs
-- (INSERT..SELECT que llenan esta tabla) NO viven acá: van en
-- deploy/clickhouse/jobs/bl_*.sql y los carga el proceso `engine` con
-- go:embed, fuera del rango que instala `secisp schema apply` (E09 §5.1).

CREATE TABLE IF NOT EXISTS isp.bl_profiles
(
    entity_kind  Enum8('global'=0,'cohort'=1,'customer'=2,'src_ip'=3,'src_prefix'=4,'service'=5),
    entity_key   String,
    metric       LowCardinality(String),          -- conjunto cerrado, E09 §4.4
    slot         UInt8,                           -- 0..47, E09 §4.5
    mu_log       Float64,                         -- esperado en log; 0 en entity_kind 0/1
    shape_log    Float64,                         -- forma centrada en 0; 0 en entity_kind 2..5
    mad_log      Float64,                         -- mediana de |residual| en log
    p95_log      Float64,                         -- diagnóstico / panel
    n_eff        UInt32,                          -- suma de pesos del kernel
    ready        UInt8,                           -- n_eff >= min_samples
    quality      Float32,                         -- 0..1
    built_at     DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(built_at)
PARTITION BY entity_kind
ORDER BY (entity_kind, metric, entity_key, slot)
TTL toDateTime(built_at) + INTERVAL 30 DAY DELETE
SETTINGS index_granularity = 8192;

-- D-35: la clave de un COMPLEX_KEY_HASHED se consulta con tuple(...); acá
-- solo se declara la fuente, que lee la tabla con FINAL (E09 §5.2).
CREATE DICTIONARY IF NOT EXISTS isp.dict_bl_profile
(
    entity_kind UInt8,
    entity_key  String,
    metric      String,
    slot        UInt8,
    mu_log      Float64 DEFAULT 0,
    shape_log   Float64 DEFAULT 0,
    mad_log     Float64 DEFAULT 0,
    ready       UInt8   DEFAULT 0,
    quality     Float32 DEFAULT 0,
    n_eff       UInt32  DEFAULT 0
)
PRIMARY KEY entity_kind, entity_key, metric, slot
SOURCE(CLICKHOUSE(QUERY '
    SELECT toUInt8(entity_kind), entity_key, toString(metric), slot,
           mu_log, shape_log, mad_log, ready, quality, n_eff
    FROM isp.bl_profiles FINAL'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 240 MAX 360);

-- Vista de lectura para el panel de calibración de E12 y para diagnóstico
-- manual: bl_profiles FINAL más las tres columnas derivadas que E09 §5.3
-- exige (expected, p95, cv_pct). ReplacingMergeTree admite FINAL en una
-- vista (E03 §4.6).
CREATE OR REPLACE VIEW isp.v_bl_profiles
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
SELECT
    entity_kind,
    entity_key,
    metric,
    slot,
    mu_log,
    shape_log,
    mad_log,
    p95_log,
    n_eff,
    ready,
    quality,
    built_at,
    -- ClickHouse 24.8 no tiene expm1(): exp(x) - 1 es el mismo cálculo (ya es
    -- el patrón que cv_pct usa, dos líneas más abajo, en este mismo archivo).
    (exp(mu_log) - 1)                          AS expected,
    (exp(p95_log) - 1)                         AS p95,
    (exp(mad_log * 1.4826) - 1) * 100            AS cv_pct
FROM isp.bl_profiles FINAL;
