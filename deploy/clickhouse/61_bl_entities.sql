-- 61_bl_entities.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.2, §5.3 · E00b D-13 · E00e G-1 · E09 §9.4
-- N10, N11 · E09 §9.6 N18 · E00b D-35 · E00f H-1.
--
-- Nivel, cohorte y estado por (entidad, métrica): D3 dice que el NIVEL es
-- del cliente (esta tabla) y la FORMA es de la cohorte (60_bl_profiles.sql,
-- archivo anterior). 61_ es ESTE archivo, no 60_ -- estaban cruzados en una
-- versión vieja del layout (§9.4 N10) -- porque v_bl_coverage, al final de
-- este mismo archivo, lee bl_profiles (60_, número menor: ya existe) Y
-- bl_entities (este archivo, definida arriba): H-1 exige que todo objeto
-- referenciado por un CREATE VIEW viva en un archivo de número menor o en
-- este mismo archivo antes del punto donde se lo usa.
--
-- Diccionario y vistas van en este archivo (no existe 6x_bl_dict.sql, G-1).

CREATE TABLE IF NOT EXISTS isp.bl_entities
(
    entity_kind            Enum8('global'=0,'cohort'=1,'customer'=2,'src_ip'=3,'src_prefix'=4,'service'=5),
    entity_key             String,
    metric                 LowCardinality(String),
    cohort                 LowCardinality(String) DEFAULT 'unknown',
    cohort_candidate       LowCardinality(String) DEFAULT '',
    cohort_candidate_days  UInt8 DEFAULT 0,       -- histéresis, E09 D8
    level_log              Float64,
    level_prev_log         Float64,
    level_ratio_day        Float32,               -- deriva observada, E09 D10
    samples                UInt32,
    active_hours           UInt32,
    excluded_hours         UInt32,                -- horas descartadas por caso confirmado
    state                  Enum8('warmup'=1,'ready'=2,'stale'=3,'quarantined'=4,'frozen'=5),
    quality                Float32,
    frozen_until           DateTime('UTC') DEFAULT toDateTime(0),
    first_seen             DateTime('UTC'),
    last_seen              DateTime('UTC'),
    built_at               DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(built_at)
ORDER BY (entity_kind, metric, entity_key)
TTL last_seen + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

CREATE DICTIONARY IF NOT EXISTS isp.dict_bl_entity
(
    entity_kind UInt8,
    entity_key  String,
    metric      String,
    cohort      String  DEFAULT 'unknown',
    level_log   Float64 DEFAULT 0,
    state       UInt8   DEFAULT 0,
    quality     Float32 DEFAULT 0
)
PRIMARY KEY entity_kind, entity_key, metric
SOURCE(CLICKHOUSE(QUERY '
    SELECT toUInt8(entity_kind), entity_key, toString(metric),
           toString(cohort), level_log, toUInt8(state), quality
    FROM isp.bl_entities FINAL'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 240 MAX 360);

-- bl_entities FINAL más las columnas derivadas que E09 §5.3 exige: level
-- (el nivel vuelto a escala natural), is_frozen (ventana de congelamiento
-- vigente, E09 §4.10: "congela la actualización, no la evaluación") y
-- days_since_built (para detectar perfiles stale sin tener que restar
-- fechas a mano en el panel).
CREATE OR REPLACE VIEW isp.v_bl_entities
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
    cohort,
    cohort_candidate,
    cohort_candidate_days,
    level_log,
    level_prev_log,
    level_ratio_day,
    samples,
    active_hours,
    excluded_hours,
    state,
    quality,
    frozen_until,
    first_seen,
    last_seen,
    built_at,
    -- ClickHouse 24.8 no tiene expm1(): exp(x) - 1 es el mismo cálculo.
    (exp(level_log) - 1)                          AS level,
    now() < frozen_until                          AS is_frozen,
    dateDiff('day', toDate(built_at), today())     AS days_since_built
FROM isp.bl_entities FINAL;

-- Vista de salud de la épica (E09 §5.3): por métrica y nivel de jerarquía,
-- cuántas entidades son evaluables (tienen historia en bl_entities), cuántas
-- de ésas ya tienen un perfil propio LISTO en algún slot (bl_profiles,
-- entity_kind 2..4, ready=1) y cuántas quedan sin perfil propio -- las que
-- E09 §4.9 documenta que se evalúan igual, cayendo al nivel siguiente de la
-- jerarquía (cohorte o global), pero con menos calidad. E09-04 la usa para
-- verificar la línea de tiempo de warm-up (L0 <= día 3, L1 <= día 5/10, L2
-- <= día 21) sobre datos sintéticos.
CREATE OR REPLACE VIEW isp.v_bl_coverage
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
    metric,
    entity_kind,
    count()                                                  AS entities_evaluables,
    countIf(has_own_profile = 1)                              AS entities_evaluadas,
    countIf(has_own_profile = 0)                              AS entities_sin_perfil,
    round(countIf(has_own_profile = 1) / greatest(count(), 1), 4) AS coverage_ratio
FROM
(
    SELECT
        be.metric      AS metric,
        be.entity_kind AS entity_kind,
        be.entity_key  AS entity_key,
        -- "Evaluable" es CUALQUIER fila de bl_entities para esa métrica (la
        -- entidad tiene historia observada). "Con perfil propio" exige,
        -- además, que exista al menos un slot ready=1 en bl_profiles para
        -- la MISMA clave (entity_kind, entity_key, metric) -- que solo se
        -- puebla para L2 (E09 §4.3): el resto se evalúa por cohorte o
        -- global, y eso es justo lo que esta vista tiene que mostrar como
        -- "sin perfil propio", no como "sin cobertura".
        if(bp.entities_ready > 0, 1, 0) AS has_own_profile
    FROM (SELECT DISTINCT entity_kind, entity_key, metric FROM isp.bl_entities FINAL) AS be
    LEFT JOIN
    (
        SELECT entity_kind, entity_key, metric, max(ready) AS entities_ready
        FROM isp.bl_profiles FINAL
        WHERE entity_kind IN (2, 3, 4)
        GROUP BY entity_kind, entity_key, metric
    ) AS bp
    ON  be.entity_kind = bp.entity_kind
    AND be.entity_key  = bp.entity_key
    AND be.metric      = bp.metric
)
GROUP BY metric, entity_kind
ORDER BY metric, entity_kind;
