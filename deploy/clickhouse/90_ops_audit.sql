-- 90_ops_audit.sql [E12]
--
-- T-087 (E12a-T27) -- E12 §5.0, §5.4 · E00b D-36 · E00 ADR-015 · E03 §4.9.1.
--
-- DDL canónico de auditoría (D-36): E00 fijó el nombre, E03 asignó el
-- archivo a E12, y E04 §4.10 y E05 §5.3 habían declarado dos formas
-- distintas. Esta es la que vale -- la unión de ambas, con los nombres de
-- E04 donde había choque (before/after en JSON, más generales que
-- old_value/new_value) y las columnas de E05 que E04 no tenía (role,
-- action). E04 §4.10 y E05 §5.3 quedan como referencia de una línea a esta
-- sección; E11 §5.3 apunta también acá.
--
-- TTL: 365 DÍAS, no 730. E00 ADR-015 fija en un año la retención de
-- ops_audit; la versión de E12 §5.4 previa a esta corrección tenía 730, y
-- una tabla de auditoría que sobrevive al ADR que la gobierna es la misma
-- clase de drift documental que E00 §1.2b describe. No re-discutir este
-- número sin volver a ADR-015 primero.
--
-- ENGINE = MergeTree, NUNCA ReplacingMergeTree: es append-only por
-- definición. Dos cambios idénticos sobre el mismo objeto (mismo
-- object_type/object_key, mismo op) son DOS HECHOS distintos que ocurrieron
-- en instantes distintos, no una fila que se deduplica a la última versión
-- -- lo que un ReplacingMergeTree haría, en silencio, contra el sentido
-- mismo de tener una auditoría.
--
-- Nadie hace ALTER UPDATE sobre esta tabla ni sobre isp.det_cases: un caso
-- se actualiza insertando una versión nueva sobre su ReplacingMergeTree
-- (E05 §4.10), y una mutación con inserts concurrentes reescribe partes
-- bajo los pies del motor. El `GRANT ALTER UPDATE ON isp.det_cases` que
-- E12 tenía en su §5.7 se quitó por D-36 -- no se transcribe acá ni en
-- 95_roles_grants.sql. test/schema/ops_tables_test.go lo verifica con un
-- grep sobre TODO el layout embebido, no solo sobre este archivo.
--
-- Quién la escribe: los cuatro roles (`engine` para cambios de modo y
-- params_drift, `mitigator` para unblock y acciones manuales, `watchdog`
-- para las demociones automáticas de D14, `cli` para todo lo que pasa por
-- `secisp`) más el escritor compartido de internal/ops/audit.go. Es la
-- ÚNICA excepción a "una tabla, un escritor" (§7 de secuencia-de-desarrollo,
-- E00 §2.3): el origen de cada fila queda siempre deducible por `role`.
CREATE TABLE IF NOT EXISTS isp.ops_audit
(
    audit_id     UUID DEFAULT generateUUIDv4(),
    ts           DateTime64(3, 'UTC') DEFAULT now64(3),

    -- Quién. Resolución, en orden: --actor > SEC_ACTOR > SUDO_USER > USER > 'unknown'.
    actor        LowCardinality(String),
    actor_source Enum8('cli' = 1, 'file' = 2, 'api' = 3, 'seed' = 4, 'system' = 5) DEFAULT 'cli',
    role         LowCardinality(String),   -- collector|engine|mitigator|watchdog|cli
    host         LowCardinality(String) DEFAULT '',

    -- Qué.
    object_type  LowCardinality(String),   -- 'dim_net_prefixes','detector_mode','case','config',…
    object_key   String,                   -- '8.8.8.8/32','scan.horizontal',<uuid>,…
    op           Enum8('create' = 1, 'update' = 2, 'disable' = 3, 'enable' = 4, 'delete' = 5,
                        'reload' = 6, 'label' = 7, 'promote' = 8, 'demote' = 9, 'unblock' = 10),
    action       LowCardinality(String),   -- etiqueta libre del subsistema: 'detector_mode_change',…

    before       String CODEC(ZSTD(3)),    -- JSON del estado previo; '' si create
    after        String CODEC(ZSTD(3)),    -- JSON del estado nuevo;  '' si delete

    config_version UInt64 DEFAULT 0,
    reason       String DEFAULT '',        -- obligatorio para disable/delete/demote/unblock
    -- DEFAULT antes de CODEC: ClickHouse exige ese orden en la declaración de
    -- columna (name type [DEFAULT expr] [CODEC(...)]); al revés es un error
    -- de sintaxis, no de semántica.
    details      String DEFAULT '' CODEC(ZSTD(3))
)
ENGINE = MergeTree                          -- append-only: la auditoría no se deduplica
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, object_type, object_key)
-- toDateTime(ts): TTL exige DateTime/Date, no DateTime64 -- mismo patrón que
-- 10_flows_raw.sql (TTL toDateTime(ts_received) + ...).
TTL toDateTime(ts) + INTERVAL 365 DAY DELETE;  -- E00 ADR-015 (E00b D-36); NO 730
