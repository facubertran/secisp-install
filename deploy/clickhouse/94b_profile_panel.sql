-- 94b_profile_panel.sql [E10]
--
-- T-084 (E10-T06) -- E10 §4.9.3 · E10 D7, D8, D9 · E00b D-40a, D-40b ·
-- E00c C-18 · E00d F-2 · E00e G-3, G-6a · E10 §9.1 Q21 · E10 §9.2 Q17.
--
-- SETTINGS PROFILE del usuario de Grafana (secisp_grafana, D-39) y su QUOTA.
-- Va ANTES de 95_roles_grants.sql -- no DESPUÉS -- porque ahí es donde E12
-- crea ese usuario con `SETTINGS PROFILE secisp_panel` (E12 §5.7.3): si este
-- archivo corriera después, el usuario se crearía SIN LÍMITE NINGUNO, la
-- creación no fallaría, y nadie se entera (Q21). `94b` en el bloque `9x` de
-- E12 y no `69c` en el de E10: tiene que correr lo más cerca posible de
-- `95_` y antes (E03 §4.9.1).
--
-- TRAMPA 1: la QUOTA se crea SIN `TO secisp_ro`. El rol `secisp_ro` todavía
-- no existe a esta altura -- lo crea `95_roles_grants.sql`, que corre
-- después -- y un `TO` sobre un rol inexistente voltea el archivo ENTERO,
-- incluido el `CREATE SETTINGS PROFILE` de arriba, que es justo lo que F-2
-- vino a garantizar. La asignación la agrega E12 en su bloque de roles con
-- `ALTER QUOTA secisp_panel_quota TO secisp_ro;` (E00e G-6a); sin esa línea
-- el perfil aplica y la cuota queda huérfana -- el límite de 900
-- queries/minuto no rige -- y no falla nada.
--
-- TRAMPA 2 (E00c C-18): este perfil es la ÚNICA declaración de
-- `max_execution_time`, `max_result_rows` y `max_memory_usage` del camino de
-- lectura de Grafana. Si `95_roles_grants.sql` los redeclara por usuario,
-- el `CREATE USER` falla con SETTING_CONSTRAINT_VIOLATION (un `CONST` no se
-- puede subir) y no queda usuario de Grafana. E12 solo asigna el perfil.
--
-- TRAMPA 3 (Q17): `query_cache_nondeterministic_function_handling` (24.7+) y
-- `query_cache_system_table_handling` (24.8+) exigen ClickHouse >= 24.8: en
-- una versión anterior el `CREATE SETTINGS PROFILE` entero falla con
-- UNKNOWN_SETTING -- no se degrada, no se crea nada -- y el paso 0 del
-- instalador (`SELECT version()`) tiene que abortar antes de llegar acá.
-- Están marcados CHANGEABLE_IN_READONLY (D-40a) para no perder la
-- habilitación de query cache si un panel puntual necesita otro TTL.

CREATE SETTINGS PROFILE IF NOT EXISTS secisp_panel SETTINGS
    -- Techos duros: la query cara falla rápido en vez de comerse el host.
    --
    -- max_execution_time es MAX, no CONST (a diferencia de las otras nueve
    -- de este bloque): el driver de grafana-clickhouse-datasource
    -- (ClickHouse/clickhouse-go, context.go: queryOptions()) inyecta
    -- max_execution_time = segundos_restantes_del_contexto + 5 en CADA
    -- query, automáticamente, en cuanto el contexto que le llega tiene
    -- deadline (el timeout por request de Grafana, dataproxy.timeout,
    -- default 30 s) -- ni el plugin ni este proyecto lo piden. Con CONST,
    -- ese intento (~30-35) choca SIEMPRE contra ClickHouse con "code: 452,
    -- Setting max_execution_time should not be changed": TODO panel de
    -- TODO dashboard de ClickHouse roto, encontrado en la primera
    -- instalación real con el plugin real. MAX 60 deja pasar lo que el
    -- driver manda sin poder, sin que el usuario lo pida, superar el
    -- minuto -- 10 sigue siendo el default real para cualquier query que
    -- NO llegue con ese contexto (ninguna hoy, pero no depender de eso).
    max_execution_time              = 10 MAX 60,
    max_rows_to_read                = 2000000000  CONST,
    max_bytes_to_read               = 20000000000 CONST,
    max_memory_usage                = 2000000000  CONST,   -- 2 GiB por query
    -- (E00b D-40b) Techo agregado del usuario `secisp_grafana`: sin esto, 12 queries × 2 GiB
    -- reservaban 24 GiB contra un max_server_memory_usage de ~28,8 GiB que además
    -- tiene que alojar al motor de detección y a los merges.
    max_memory_usage_for_user       = 6442450944  CONST,   -- 6 GiB para TODO el usuario
    max_result_rows                 = 20000       CONST,
    max_result_bytes                = 100000000   CONST,
    result_overflow_mode            = 'throw'     CONST,
    max_threads                     = 4           CONST,
    max_concurrent_queries_for_user = 6           CONST,   -- era 12 (E00b D-40b)
    -- El panel SÍ puede tocar estas: son las de D8/D9.
    use_query_cache                 = 1           CHANGEABLE_IN_READONLY,
    query_cache_ttl                 = 30          CHANGEABLE_IN_READONLY,
    query_cache_min_query_duration  = 100         CHANGEABLE_IN_READONLY,
    query_cache_min_query_runs      = 0           CHANGEABLE_IN_READONLY,
    -- (E00b D-40a) Sin estas dos, TODA query de panel devuelve excepción: las vistas
    -- usan now(), dictGet y system.query_log, y los defaults son 'throw'.
    query_cache_nondeterministic_function_handling = 'save' CHANGEABLE_IN_READONLY,
    query_cache_system_table_handling              = 'save' CHANGEABLE_IN_READONLY,
    log_comment                     = ''          CHANGEABLE_IN_READONLY,
    -- readonly=2 permite SETTINGS por query; los CONST de arriba impiden subirlos.
    readonly                        = 2;

-- La cuota se DEFINE acá, sin destinatario: `94b_profile_panel.sql` corre ANTES de
-- `95_roles_grants.sql` (E03 §4.9.1 · E00d F-2 · E00e G-3), que es donde E12 crea
-- el rol `secisp_ro`.
-- Un `TO secisp_ro` en esta línea fallaría con el rol inexistente y voltearía el
-- archivo entero — incluido el SETTINGS PROFILE, que es lo que F-2 vino a garantizar.
CREATE QUOTA IF NOT EXISTS secisp_panel_quota
    KEYED BY user_name
    FOR INTERVAL 1 MINUTE MAX queries = 900, errors = 120, execution_time = 240,
    FOR INTERVAL 1 HOUR   MAX read_rows = 200000000000;

-- La asignación va en `95_roles_grants.sql`, junto al CREATE ROLE (E12 §5.7):
--     ALTER QUOTA secisp_panel_quota TO secisp_ro;
-- y el nombre canónico del usuario es `secisp_grafana` por E00b D-39 (era `grafana`),
-- que E12 §5.7.3 crea ya con `SETTINGS PROFILE secisp_panel`, así que un
-- `ALTER USER secisp_grafana SETTINGS PROFILE secisp_panel` acá sería redundante
-- y además fallaría por usuario inexistente.
