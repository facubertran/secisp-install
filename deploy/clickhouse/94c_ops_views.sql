-- 94c_ops_views.sql [E12]
--
-- T-091 (E12a-T29) -- E12 §5.0, §5.5 · E00e G-3 · E00f H-1 · E12-13 ·
-- E11 §5.4 (v_mit_router_events) · E03 §4.9.1.
-- Amendado por T-224 (E12b-T24) -- E00e G-6a · E10 §9.1 Q21 · E12 §5.7.2 ·
-- E12 §8.3: agrega v_ops_panel_quota al final del archivo.
--
-- Las tres vistas de operación de E12 §5.5, EN ESTE ORDEN: v_ops_o5,
-- v_ops_pending_review, v_ops_health. v_ops_health lee a las otras dos, así
-- que va última -- reordenarlas rompe el CREATE con UNKNOWN_TABLE (H-1).
-- v_ops_panel_quota (T-224) va quinta, después de v_mit_router_events, sin
-- depender de ninguna de las otras cuatro -- ver su propio comentario más
-- abajo sobre por qué existe y por qué acá.
--
-- Por qué el archivo se llama 94c_ y no 96_ (E00e G-3): 95_roles_grants.sql
-- ENUMERA estas tres vistas en sus GRANT SELECT ... TO secisp_ro. El orden
-- de aplicación del instalador es lexicográfico por BYTES (E00b D-13): el
-- guion bajo '_' (0x5F) es MENOR que cualquier letra minúscula, así que
-- "94_ops_feedback.sql" < "94b_profile_panel.sql" < "94c_ops_views.sql" <
-- "95_roles_grants.sql" -- los cuatro caen donde tienen que caer sin
-- renumerar nada. Con la numeración vieja (96_) el GRANT corría ANTES de
-- que las vistas existieran, fallaba con UNKNOWN_TABLE y volteaba
-- 95_roles_grants.sql entero: ningún rol ni usuario queda creado, Grafana
-- da ACCESS_DENIED en todos los paneles, el mitigador no lee det_cases y el
-- collector no inserta. La regla general: todo objeto que
-- 95_roles_grants.sql nombra tiene que crearse en un archivo de número
-- MENOR que 95_.
--
-- Objetos de otras épicas que este archivo lee, con su archivo del
-- instalador (todos de número menor que 94c, por la misma regla H-1):
--   isp.mit_actions          -- 50_mit.sql               [E11]
--   isp.ops_feedback         -- 94_ops_feedback.sql       [E12]
--   isp.det_cases            -- 40_det.sql                [E05]
--   isp.v_ops_data_health    -- 39_v_ops_data_health.sql  [E03]
--   isp.dim_net_prefixes     -- 05_dim_net_prefixes.sql   [E04]
--   isp.v_ops_exporters      -- 93_ops_exporter_stats.sql [E12]
--   isp.ops_schema_version   -- 00_database.sql           [E03]
--   isp.ops_watchdog_checks  -- 92_ops_watchdog.sql       [E12]
--   isp.ops_audit            -- 90_ops_audit.sql          [E12] (v_mit_router_events)
--   isp_ip_str()             -- 00_database.sql           [E03]
CREATE OR REPLACE VIEW isp.v_ops_o5
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
WITH bloqueos AS (
    SELECT count() AS n
    FROM isp.mit_actions FINAL
    WHERE created_at >= now() - INTERVAL 30 DAY
      AND action IN ('block_pair','block_service','block_src','rate_limit')
      AND status IN ('ok','partial')
),
fp AS (
    SELECT count() AS n
    FROM isp.ops_feedback FINAL
    WHERE at >= now() - INTERVAL 30 DAY
      AND verdict = 'false_positive'
      AND was_mitigated = 1
)
SELECT
    (SELECT n FROM bloqueos)                                        AS blocking_actions_30d,
    (SELECT n FROM fp)                                              AS false_positive_actions_30d,
    (SELECT n FROM fp) / greatest((SELECT n FROM bloqueos), 1)       AS o5_ratio,
    (SELECT n FROM fp) / greatest((SELECT n FROM bloqueos), 1) < 0.01 AS o5_met,
    -- Denominador suficiente para que o5_met signifique algo (§4.13, puerta T+30).
    -- Con menos de 100 acciones, o5_ratio = 0 es indistinguible de "no pasó nada":
    -- o5_met sale 1 igual, y ese 1 es el que abriría la puerta a `production` sin
    -- haber medido nada. La columna separa "cumple" de "todavía no se sabe".
    --
    -- ATENCIÓN, el 100 NO sale de P9. P9 fija el umbral (1 %) y nada más; el
    -- denominador mínimo lo agrega esta épica, porque P8 (acción automática, sin
    -- ventana de gracia) hace que la puerta a `production` sea la única defensa
    -- que queda. El número es el mínimo con el que un 1 % es representable:
    -- con 100 acciones, un solo falso positivo ya da 1 %. Es aditivo -- no
    -- endurece o5_met ni rompe ninguna lectura -- pero es una decisión de esta
    -- ronda y hay que confirmarla con el usuario, no heredarla como si viniera
    -- de la respuesta.
    (SELECT n FROM bloqueos) >= 100                                 AS o5_measurable;

-- Casos accionados en las últimas 24 h que todavía no tienen veredicto humano.
-- El objetivo operativo durante la calibración es que esta vista quede vacía cada día.
CREATE OR REPLACE VIEW isp.v_ops_pending_review
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
SELECT c.case_id, isp_ip_str(c.src_ip) AS src, c.customer_id, c.attack_class,
       c.peak_score, c.detectors, c.opened_at, c.last_action
FROM isp.det_cases AS c FINAL
WHERE c.state IN ('mitigating','mitigated')
  AND c.updated_at >= now() - INTERVAL 24 HOUR
  AND c.case_id NOT IN (SELECT case_id FROM isp.ops_feedback FINAL WHERE case_id != toUUID('00000000-0000-0000-0000-000000000000'))
ORDER BY c.peak_score DESC;

-- Un renglón con la salud del sistema entero. Es el primer SELECT de todo runbook.
CREATE OR REPLACE VIEW isp.v_ops_health
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
    (SELECT ingest_lag_seconds FROM isp.v_ops_data_health)              AS ingest_lag_seconds,
    (SELECT transit_flows_5m   FROM isp.v_ops_data_health)              AS transit_flows_5m,
    (SELECT unknown_scope_5m   FROM isp.v_ops_data_health)              AS unknown_scope_5m,
    -- Los nombres son los de E04 §4.1.1: la columna es `scope` (Enum8, 'customer'=1),
    -- no `kind`, y el borrado lógico es `is_enabled`, no `enabled`. Y va con FINAL
    -- porque dim_net_prefixes es ReplacingMergeTree(updated_at): sin FINAL, una fila
    -- deshabilitada y su versión vieja habilitada cuentan las dos.
    (SELECT count() FROM isp.dim_net_prefixes FINAL
       WHERE scope = 'customer' AND is_enabled = 1)                      AS customer_prefixes,
    (SELECT countIf(silent_seconds > 600) FROM isp.v_ops_exporters
       WHERE minute >= now() - INTERVAL 5 MINUTE)                       AS exporters_mute,
    (SELECT max(version) FROM isp.ops_schema_version)                   AS schema_version,
    (SELECT countIf(ok = 0) FROM isp.ops_watchdog_checks
       WHERE ts >= now() - INTERVAL 10 MINUTE)                          AS checks_down,
    (SELECT o5_ratio FROM isp.v_ops_o5)                                 AS o5_ratio,
    (SELECT count() FROM isp.v_ops_pending_review)                      AS pending_review;

-- Salud del actuador, para E10 y E12. Sale de ops_audit, no de una tabla nueva.
--
-- NO va en 50_mit.sql (donde E11 §5.4 la ubica textualmente): su SELECT lee
-- isp.ops_audit, que se declara en 90_ops_audit.sql -- un número MAYOR que
-- 50. Por H-1, declararla ahí abortaría 50_mit.sql entero y con él 6x/7x/9x
-- y 95_roles_grants.sql. Va acá, después de v_ops_health -- sin depender de
-- ninguna de las otras dos de este archivo, así que el orden entre ella y
-- las tres de arriba no importa, pero SÍ importa que corra después de
-- 90_ops_audit.sql (lo hace: 90 < 94c).
CREATE OR REPLACE VIEW isp.v_mit_router_events
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
SELECT ts, actor, object_key AS router, op, reason, after
FROM isp.ops_audit
WHERE object_type IN ('mit_router', 'mit_rules', 'mit_breaker');

-- v_ops_panel_quota (T-224): la vista que le permite a secisp_grafana (y a
-- secisp_ro en general) verificar que la cuota del panel RIGE, sin un
-- GRANT directo sobre system.quotas_usage.
--
-- Hallazgo real de T-224: la aserción que E12 §8.3 pide correr COMO
-- secisp_grafana -- `SELECT count() FROM system.quotas_usage WHERE
-- quota_name = 'secisp_panel_quota'` -- da ACCESS_DENIED contra un
-- ClickHouse 25.11 real (`grant SELECT(quota_name) ON
-- system.quotas_usage`) porque 95_roles_grants.sql (T-092) nunca le dio a
-- secisp_grafana/secisp_ro ningún GRANT sobre system.*, a propósito
-- (E12 §5.7.2): el mecanismo para que un rol de solo lectura vea datos de
-- system.* es una vista con SQL SECURITY DEFINER, nunca un GRANT directo
-- -- test/schema/grants_test.go (TestNoDirectSystemGrantsToReadOnlyUsers)
-- lo hace cumplir. G-6a describe exactamente este modo de falla para la
-- ASIGNACIÓN de la cuota ("puede estar declarada y nadie se entera si no
-- rige"); T-224 encontró la misma clase de falla silenciosa un nivel más
-- abajo, en la VERIFICACIÓN de la cuota: sin esta vista, la cuota puede
-- regir de verdad y aun así nadie con el rol de solo lectura podría
-- comprobarlo.
--
-- Va en ESTE archivo (no uno nuevo, E00b D-13/docs/tasks/ola-03: el
-- layout instalado quedó fijo en 50 archivos desde el cierre de esa ola, y
-- ninguna task de las olas 4-6 lo tocó) y AL FINAL (sin depender de las
-- otras tres) -- corre DESPUÉS de 94b_profile_panel.sql, que declara la
-- QUOTA secisp_panel_quota (94b < 94c por orden de bytes, E00b D-13),
-- aunque CREATE VIEW no valida en tiempo de creación que esa cuota exista
-- todavía: system.quotas_usage es una tabla virtual, no isp.*.
--
-- Se filtra a quota_name = 'secisp_panel_quota' (la única cuota que este
-- despliegue declara) en vez de exponer system.quotas_usage entero: esta
-- vista es específicamente "cómo le va a la cuota del panel", no un espejo
-- genérico de la tabla de sistema. system.quotas_usage tiene una fila por
-- (quota_key, duration) -- la cuota de E10 §4.9.3 declara dos intervalos
-- (1 MINUTE con queries/errors/execution_time, 1 HOUR con read_rows) --
-- así que un consumidor al que solo le interesan los tres topes de §8.3
-- filtra por duration = 60.
CREATE OR REPLACE VIEW isp.v_ops_panel_quota
-- SQL SECURITY DEFINER (T-092, E12 §5.7.2, generalizado más allá de
-- system.*): sin esta cláusula, una vista normal de ClickHouse ejecuta con
-- los privilegios del INVOCADOR sobre las tablas que su SELECT nombra -- el
-- GRANT SELECT sobre la vista misma no alcanza. Verificado contra un
-- ClickHouse 25.11 real: sin esta línea, secisp_grafana recibe el mismo
-- ACCESS_DENIED de más arriba, ahora sobre la vista en vez de sobre la
-- tabla de sistema -- exactamente el resultado que esta vista existe para
-- evitar. Sin DEFINER = ... explícito por la misma razón que
-- isp.v_ops_panel_cost (70_v_panel.sql): secisp_ops todavía no existe a
-- esta altura del layout (lo crea 95_roles_grants.sql).
SQL SECURITY DEFINER
AS
SELECT
    quota_key, duration, is_current,
    queries, max_queries,
    errors, max_errors,
    execution_time, max_execution_time
FROM system.quotas_usage
WHERE quota_name = 'secisp_panel_quota';
