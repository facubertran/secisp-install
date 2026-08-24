-- 64_bl_service_seen.sql [E09]
--
-- T-076 (E09-T04) -- E09 §5.1, §5.2 · E00b D-13 · E00e G-1.
--
-- Servicios de la watchlist vistos por entidad (J7, horario a :12, E09
-- §4.8.5): first_seen/last_seen/hours_seen/packets/max_uniq_dsts por
-- (entity_kind, entity_key, proto, dst_port). Es AggregatingMergeTree con
-- SimpleAggregateFunction -- las columnas se leen tal cual, sin *Merge ni
-- finalizeAggregation (E00b D-9 reserva el sufijo _state para
-- AggregateFunction; estas no lo llevan a propósito). No hay vista de
-- lectura para esta tabla en E09 §5.3 (las 5 vistas del contrato son
-- v_bl_profiles, v_bl_entities, v_bl_coverage, v_bl_residuals y
-- v_bl_thresholds); el diccionario sí, porque `anomaly.new_service` lo
-- consulta por entidad+servicio.

CREATE TABLE IF NOT EXISTS isp.bl_service_seen
(
    entity_kind   Enum8('global'=0,'cohort'=1,'customer'=2,'src_ip'=3,'src_prefix'=4,'service'=5),
    entity_key    String,
    proto         UInt8,
    dst_port      UInt16,
    first_seen    SimpleAggregateFunction(min, DateTime('UTC')),
    last_seen     SimpleAggregateFunction(max, DateTime('UTC')),
    -- UInt64, no UInt32: sum() SIEMPRE ensancha un entero sin signo de menos
    -- de 64 bits a UInt64 (mismo motivo documentado en 35_agg_smtp_sessions.sql
    -- para "chunks") -- con UInt32 el CREATE TABLE falla con BAD_ARGUMENTS
    -- ("Incompatible data types between aggregate function 'sum' ...") en
    -- TODOS los casos, sin necesidad de insertar una fila.
    hours_seen    SimpleAggregateFunction(sum, UInt64),
    packets       SimpleAggregateFunction(sum, UInt64),
    max_uniq_dsts SimpleAggregateFunction(max, UInt64)
)
ENGINE = AggregatingMergeTree
ORDER BY (entity_kind, entity_key, proto, dst_port)
TTL last_seen + INTERVAL 45 DAY DELETE
SETTINGS index_granularity = 8192;

-- Fuente del diccionario: FINAL, como el resto de los cinco (T-076 criterio
-- de aceptación). SimpleAggregateFunction se resuelve solo al fusionar
-- partes (sum/min/max según la columna); FINAL fuerza esa fusión al leer,
-- así que hours_seen/first_seen salen ya correctos sin re-agregar a mano.
-- El DEFAULT de un atributo de DICTIONARY tiene que ser un literal: una
-- expresión de función (toDateTime(0)) da "Syntax error ... Expected one of:
-- literal, ..." al CREATE, a diferencia de una columna de tabla común, donde
-- sí se admite (ver first_seen/last_seen del CREATE TABLE de arriba).
CREATE DICTIONARY IF NOT EXISTS isp.dict_bl_service_seen
( entity_kind UInt8, entity_key String, proto UInt8, dst_port UInt16,
  hours_seen UInt32 DEFAULT 0, first_seen DateTime DEFAULT '1970-01-01 00:00:00' )
PRIMARY KEY entity_kind, entity_key, proto, dst_port
SOURCE(CLICKHOUSE(QUERY '
    SELECT toUInt8(entity_kind), entity_key, proto, dst_port, hours_seen, first_seen
    FROM isp.bl_service_seen FINAL'))
LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(MIN 600 MAX 900);
